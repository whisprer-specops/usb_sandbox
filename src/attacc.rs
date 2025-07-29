// ATmega Nixie Clock Firmware Extraction & Analysis
// Adapted for AVR architecture instead of ARM Cortex-M

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct AtmegaTarget {
    pub device_id: String,
    pub chip_variant: AtmegaVariant,
    pub flash_size: u32,
    pub eeprom_size: u32,
    pub fuse_protection: FuseProtection,
    pub programming_interface: ProgrammingInterface,
    pub usb_config: UsbConfiguration,
}

#[derive(Debug, Clone)]
pub enum AtmegaVariant {
    ATmega328P,  // 32KB Flash, 1KB EEPROM
    ATmega32U4,  // 32KB Flash, 1KB EEPROM, USB
    ATmega2560,  // 256KB Flash, 4KB EEPROM
    ATmega16U2,  // 16KB Flash, 512B EEPROM, USB
    ATmega8U2,   // 8KB Flash, 512B EEPROM, USB
    Unknown(String), // For ATmega367/387 if that's what it really is
}

impl AtmegaVariant {
    pub fn from_marking(marking: &str) -> Self {
        match marking.to_lowercase().as_str() {
            s if s.contains("328") => Self::ATmega328P,
            s if s.contains("32u4") => Self::ATmega32U4,
            s if s.contains("2560") => Self::ATmega2560,
            s if s.contains("16u2") => Self::ATmega16U2,
            s if s.contains("8u2") => Self::ATmega8U2,
            s if s.contains("367") => Self::Unknown("ATmega367".to_string()),
            s if s.contains("387") => Self::Unknown("ATmega387".to_string()),
            _ => Self::Unknown(marking.to_string()),
        }
    }

    pub fn specs(&self) -> (u32, u32) { // (flash_size, eeprom_size)
        match self {
            Self::ATmega328P => (32768, 1024),
            Self::ATmega32U4 => (32768, 1024),
            Self::ATmega2560 => (262144, 4096),
            Self::ATmega16U2 => (16384, 512),
            Self::ATmega8U2 => (8192, 512),
            Self::Unknown(_) => (32768, 1024), // Reasonable guess
        }
    }
}

#[derive(Debug, Clone)]
pub enum FuseProtection {
    Unlocked,        // No protection, full access
    BootloaderLocked, // Application section locked
    FullyLocked,     // All sections locked
    Unknown,
}

#[derive(Debug, Clone)]
pub enum ProgrammingInterface {
    ISP,     // In-System Programming (SPI-based)
    HVPP,    // High Voltage Parallel Programming
    HVSP,    // High Voltage Serial Programming
    USB,     // USB bootloader
    None,    // No accessible interface
}

#[derive(Debug, Clone)]
pub struct UsbConfiguration {
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_class: UsbDeviceClass,
    pub has_dfu: bool,
    pub has_cdc: bool,
    pub has_hid: bool,
}

#[derive(Debug, Clone)]
pub enum UsbDeviceClass {
    HID,           // Human Interface Device
    CDC,           // Communication Device Class
    DFU,           // Device Firmware Update
    CustomVendor,  // Vendor-specific
    Composite,     // Multiple classes
}

pub struct AtmegaExtractor {
    target: AtmegaTarget,
    tools: AvrTools,
    sandbox_manager: crate::usb_sandbox::UsbSandboxManager,
}

#[derive(Debug)]
pub struct AvrTools {
    pub avrdude_path: PathBuf,
    pub programmer_type: String,
    pub usb_tools: UsbTools,
    pub logic_analyzer: Option<PathBuf>,
}

#[derive(Debug)]
pub struct UsbTools {
    pub dfu_util: PathBuf,
    pub lsusb: PathBuf,
    pub usb_capture: PathBuf,
}

impl AtmegaExtractor {
    pub fn new(chip_marking: &str, sandbox_manager: crate::usb_sandbox::UsbSandboxManager) -> Self {
        let variant = AtmegaVariant::from_marking(chip_marking);
        let (flash_size, eeprom_size) = variant.specs();

        let target = AtmegaTarget {
            device_id: format!("nixie_clock_{}", uuid::Uuid::new_v4()),
            chip_variant: variant,
            flash_size,
            eeprom_size,
            fuse_protection: FuseProtection::Unknown,
            programming_interface: ProgrammingInterface::USB, // Start with USB since that's what we have
            usb_config: UsbConfiguration {
                vendor_id: 0x0000, // Will detect from lsusb
                product_id: 0x0000,
                device_class: UsbDeviceClass::CustomVendor,
                has_dfu: false,
                has_cdc: false,
                has_hid: false,
            },
        };

        let tools = AvrTools {
            avrdude_path: PathBuf::from("/usr/bin/avrdude"),
            programmer_type: "usbasp".to_string(), // Will adjust based on what we find
            usb_tools: UsbTools {
                dfu_util: PathBuf::from("/usr/bin/dfu-util"),
                lsusb: PathBuf::from("/usr/bin/lsusb"),
                usb_capture: PathBuf::from("/usr/bin/tshark"),
            },
            logic_analyzer: None, // Optional for advanced analysis
        };

        Self {
            target,
            tools,
            sandbox_manager,
        }
    }

    // PHASE 1: USB Reconnaissance & Device Enumeration
    pub async fn usb_reconnaissance(&mut self) -> Result<()> {
        println!("🔍 Phase 1: USB Reconnaissance on nixie tube clock...");

        // Step 1: Detect USB device
        let usb_devices = self.scan_usb_devices().await?;
        println!("📱 Found {} USB devices", usb_devices.len());

        for device in &usb_devices {
            println!("   - {:04x}:{:04x} {} {}", 
                device.vendor_id, device.product_id, 
                device.manufacturer.as_deref().unwrap_or("Unknown"), 
                device.product.as_deref().unwrap_or("Unknown"));
        }

        // Step 2: Identify our target device
        let target_device = self.identify_nixie_clock_device(&usb_devices)?;
        self.target.usb_config.vendor_id = target_device.vendor_id;
        self.target.usb_config.product_id = target_device.product_id;

        println!("🎯 Target identified: {:04x}:{:04x}", 
            target_device.vendor_id, target_device.product_id);

        // Step 3: Analyze USB descriptors
        self.analyze_usb_descriptors(&target_device).await?;

        // Step 4: Check for known bootloader signatures
        self.check_bootloader_signatures(&target_device).await?;

        Ok(())
    }

    // PHASE 2: Multi-Vector Firmware Extraction
    pub async fn extract_firmware(&mut self) -> Result<AtmegaFirmware> {
        println!("⚡ Phase 2: Multi-vector firmware extraction...");

        // Vector 1: USB Bootloader Exploitation
        println!("🔧 Vector 1: USB Bootloader Exploitation");
        if let Ok(firmware) = self.usb_bootloader_extraction().await {
            println!("✅ USB bootloader extraction successful!");
            return Ok(firmware);
        }

        // Vector 2: DFU Mode Exploitation
        println!("📥 Vector 2: DFU Mode Exploitation");
        if let Ok(firmware) = self.dfu_extraction().await {
            println!("✅ DFU extraction successful!");
            return Ok(firmware);
        }

        // Vector 3: Custom USB Protocol Reverse Engineering
        println!("🕵️ Vector 3: Custom USB Protocol Analysis");
        if let Ok(firmware) = self.custom_protocol_extraction().await {
            println!("✅ Custom protocol extraction successful!");
            return Ok(firmware);
        }

        // Vector 4: ISP Interface Discovery (if accessible)
        println!("🔌 Vector 4: ISP Interface Discovery");
        if let Ok(firmware) = self.isp_extraction().await {
            println!("✅ ISP extraction successful!");
            return Ok(firmware);
        }

        // Vector 5: Bootloader Memory Dump
        println!("💾 Vector 5: Bootloader Memory Analysis");
        if let Ok(firmware) = self.bootloader_memory_dump().await {
            println!("✅ Bootloader memory dump successful!");
            return Ok(firmware);
        }

        Err(anyhow!("All extraction vectors failed - device may be locked or using unknown protocol"))
    }

    async fn scan_usb_devices(&self) -> Result<Vec<UsbDeviceInfo>> {
        let output = Command::new(&self.tools.usb_tools.lsusb)
            .args(&["-v"])
            .output()
            .await?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let devices = self.parse_lsusb_output(&output_str);

        Ok(devices)
    }

    fn parse_lsusb_output(&self, output: &str) -> Vec<UsbDeviceInfo> {
        let mut devices = Vec::new();
        let mut current_device = None;

        for line in output.lines() {
            // Parse device line: "Bus 001 Device 002: ID 1234:5678 Vendor Product"
            if line.starts_with("Bus ") && line.contains("ID ") {
                if let Some(device) = current_device.take() {
                    devices.push(device);
                }

                if let Some(id_part) = line.split("ID ").nth(1) {
                    let parts: Vec<&str> = id_part.split_whitespace().collect();
                    if let Some(vid_pid) = parts.first() {
                        let vid_pid_parts: Vec<&str> = vid_pid.split(':').collect();
                        if vid_pid_parts.len() == 2 {
                            if let (Ok(vid), Ok(pid)) = (
                                u16::from_str_radix(vid_pid_parts[0], 16),
                                u16::from_str_radix(vid_pid_parts[1], 16)
                            ) {
                                current_device = Some(UsbDeviceInfo {
                                    vendor_id: vid,
                                    product_id: pid,
                                    manufacturer: None,
                                    product: None,
                                    serial: None,
                                    device_class: 0,
                                    device_subclass: 0,
                                    device_protocol: 0,
                                });
                            }
                        }
                    }
                }
            }
            // Parse additional device info
            else if line.trim().starts_with("iManufacturer") {
                if let Some(ref mut device) = current_device {
                    device.manufacturer = line.split_whitespace().last().map(|s| s.to_string());
                }
            }
            else if line.trim().starts_with("iProduct") {
                if let Some(ref mut device) = current_device {
                    device.product = line.split_whitespace().last().map(|s| s.to_string());
                }
            }
        }

        if let Some(device) = current_device {
            devices.push(device);
        }

        devices
    }

    fn identify_nixie_clock_device(&self, devices: &[UsbDeviceInfo]) -> Result<&UsbDeviceInfo> {
        // Look for common AVR bootloader VID/PIDs or custom device
        let avr_bootloader_ids = [
            (0x03eb, 0x2104), // Atmel DFU bootloader
            (0x16c0, 0x05df), // VUSB identifier
            (0x1781, 0x0c9f), // AVR910 compatible
            (0x16c0, 0x05dc), // HID bootloader
        ];

        // First, try to find known AVR bootloaders
        for device in devices {
            for &(vid, pid) in &avr_bootloader_ids {
                if device.vendor_id == vid && device.product_id == pid {
                    println!("🎯 Found known AVR bootloader: {:04x}:{:04x}", vid, pid);
                    return Ok(device);
                }
            }
        }

        // If no known bootloaders, look for custom devices
        for device in devices {
            // Skip well-known system devices
            if self.is_system_device(device) {
                continue;
            }

            println!("🤔 Potential target device: {:04x}:{:04x} {} {}", 
                device.vendor_id, device.product_id,
                device.manufacturer.as_deref().unwrap_or("Unknown"),
                device.product.as_deref().unwrap_or("Unknown"));
                
            return Ok(device);
        }

        Err(anyhow!("Could not identify nixie clock device. Try connecting/disconnecting to see which device appears/disappears."))
    }

    fn is_system_device(&self, device: &UsbDeviceInfo) -> bool {
        let system_vendors = [
            0x1d6b, // Linux Foundation
            0x8087, // Intel Corp
            0x0a5c, // Broadcom Corp
            0x046d, // Logitech
            0x05ac, // Apple
            0x045e, // Microsoft
        ];

        system_vendors.contains(&device.vendor_id)
    }

    async fn analyze_usb_descriptors(&mut self, device: &UsbDeviceInfo) -> Result<()> {
        println!("🔍 Analyzing USB descriptors for {:04x}:{:04x}...", 
            device.vendor_id, device.product_id);

        // Get detailed device information
        let output = Command::new(&self.tools.usb_tools.lsusb)
            .args(&["-d", &format!("{:04x}:{:04x}", device.vendor_id, device.product_id), "-v"])
            .output()
            .await?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Look for DFU capability
        if output_str.contains("bInterfaceClass") && output_str.contains("254") {
            println!("🔄 Device supports DFU (Device Firmware Update)");
            self.target.usb_config.has_dfu = true;
        }

        // Look for CDC (Serial) capability
        if output_str.contains("bInterfaceClass") && output_str.contains("2") {
            println!("📡 Device supports CDC (Virtual Serial Port)");
            self.target.usb_config.has_cdc = true;
        }

        // Look for HID capability
        if output_str.contains("bInterfaceClass") && output_str.contains("3") {
            println!("🖱️ Device supports HID (Human Interface Device)");
            self.target.usb_config.has_hid = true;
        }

        // Extract vendor/product strings for pattern matching
        self.analyze_device_strings(&output_str);

        Ok(())
    }

    fn analyze_device_strings(&self, descriptor_output: &str) {
        for line in descriptor_output.lines() {
            let line = line.trim();
            if line.contains("iProduct") || line.contains("iManufacturer") {
                println!("📝 Device string: {}", line);
                
                // Look for common bootloader indicators
                let lower_line = line.to_lowercase();
                if lower_line.contains("bootloader") || 
                   lower_line.contains("dfu") || 
                   lower_line.contains("arduino") ||
                   lower_line.contains("avr") ||
                   lower_line.contains("usbasp") {
                    println!("🎯 Bootloader indicator found: {}", line);
                }
            }
        }
    }

    async fn check_bootloader_signatures(&mut self, device: &UsbDeviceInfo) -> Result<()> {
        println!("🔍 Checking for known bootloader signatures...");

        // Check for Arduino bootloader
        if let Ok(_) = self.test_arduino_bootloader(device).await {
            println!("🎯 Arduino-compatible bootloader detected!");
            self.tools.programmer_type = "arduino".to_string();
            return Ok(());
        }

        // Check for USBasp
        if let Ok(_) = self.test_usbasp_protocol(device).await {
            println!("🎯 USBasp programmer protocol detected!");
            self.tools.programmer_type = "usbasp".to_string();
            return Ok(());
        }

        // Check for AVRISP mkII protocol
        if let Ok(_) = self.test_avrisp_protocol(device).await {
            println!("🎯 AVRISP mkII protocol detected!");
            self.tools.programmer_type = "avrispmkII".to_string();
            return Ok(());
        }

        println!("⚠️ Unknown bootloader - will try generic approaches");
        Ok(())
    }

    async fn test_arduino_bootloader(&self, device: &UsbDeviceInfo) -> Result<()> {
        // Arduino bootloaders typically appear as CDC devices
        if !self.target.usb_config.has_cdc {
            return Err(anyhow!("Not a CDC device"));
        }

        // Try to communicate via serial
        // This would require actual serial communication
        Ok(())
    }

    async fn test_usbasp_protocol(&self, device: &UsbDeviceInfo) -> Result<()> {
        // USBasp has specific VID/PID
        if device.vendor_id == 0x16c0 && device.product_id == 0x05dc {
            return Ok(());
        }
        Err(anyhow!("Not USBasp"))
    }

    async fn test_avrisp_protocol(&self, device: &UsbDeviceInfo) -> Result<()> {
        // AVRISP mkII has specific VID/PID
        if device.vendor_id == 0x03eb && device.product_id == 0x2104 {
            return Ok(());
        }
        Err(anyhow!("Not AVRISP mkII"))
    }

    // FIRMWARE EXTRACTION METHODS

    async fn usb_bootloader_extraction(&self) -> Result<AtmegaFirmware> {
        println!("🔧 Attempting USB bootloader extraction...");

        match self.tools.programmer_type.as_str() {
            "arduino" => self.arduino_bootloader_extraction().await,
            "usbasp" => self.usbasp_extraction().await,
            "avrispmkII" => self.avrisp_extraction().await,
            _ => self.generic_bootloader_extraction().await,
        }
    }

    async fn arduino_bootloader_extraction(&self) -> Result<AtmegaFirmware> {
        println!("🔧 Extracting via Arduino bootloader...");

        // Use avrdude with Arduino programmer
        let output = Command::new(&self.tools.avrdude_path)
            .args(&[
                "-c", "arduino",
                "-p", &self.get_avrdude_part_name(),
                "-P", &format!("/dev/ttyACM0"), // Adjust based on system
                "-U", &format!("flash:r:firmware_arduino.hex:i"),
                "-U", &format!("eeprom:r:eeprom_arduino.hex:i"),
            ])
            .output()
            .await?;

        if output.status.success() {
            return self.load_extracted_firmware("firmware_arduino.hex", "eeprom_arduino.hex", "Arduino bootloader").await;
        }

        Err(anyhow!("Arduino bootloader extraction failed: {}", String::from_utf8_lossy(&output.stderr)))
    }

    async fn usbasp_extraction(&self) -> Result<AtmegaFirmware> {
        println!("🔧 Extracting via USBasp...");

        let output = Command::new(&self.tools.avrdude_path)
            .args(&[
                "-c", "usbasp",
                "-p", &self.get_avrdude_part_name(),
                "-U", "flash:r:firmware_usbasp.hex:i",
                "-U", "eeprom:r:eeprom_usbasp.hex:i",
                "-U", "lfuse:r:lfuse.hex:h",
                "-U", "hfuse:r:hfuse.hex:h",
                "-U", "efuse:r:efuse.hex:h",
            ])
            .output()
            .await?;

        if output.status.success() {
            let firmware = self.load_extracted_firmware("firmware_usbasp.hex", "eeprom_usbasp.hex", "USBasp").await?;
            
            // Also read fuse bytes for analysis
            self.analyze_fuse_bytes().await?;
            
            return Ok(firmware);
        }

        Err(anyhow!("USBasp extraction failed: {}", String::from_utf8_lossy(&output.stderr)))
    }

    async fn avrisp_extraction(&self) -> Result<AtmegaFirmware> {
        println!("🔧 Extracting via AVRISP mkII...");

        let output = Command::new(&self.tools.avrdude_path)
            .args(&[
                "-c", "avrispmkII",
                "-p", &self.get_avrdude_part_name(),
                "-P", "usb",
                "-U", "flash:r:firmware_avrisp.hex:i",
                "-U", "eeprom:r:eeprom_avrisp.hex:i",
            ])
            .output()
            .await?;

        if output.status.success() {
            return self.load_extracted_firmware("firmware_avrisp.hex", "eeprom_avrisp.hex", "AVRISP mkII").await;
        }

        Err(anyhow!("AVRISP extraction failed: {}", String::from_utf8_lossy(&output.stderr)))
    }

    async fn generic_bootloader_extraction(&self) -> Result<AtmegaFirmware> {
        println!("🔧 Attempting generic bootloader extraction...");

        // Try common programmer types
        let programmer_types = ["usbtiny", "dragon_isp", "stk500v2"];

        for prog_type in &programmer_types {
            println!("🔄 Trying programmer type: {}", prog_type);
            
            let output = Command::new(&self.tools.avrdude_path)
                .args(&[
                    "-c", prog_type,
                    "-p", &self.get_avrdude_part_name(),
                    "-P", "usb",
                    "-U", &format!("flash:r:firmware_{}.hex:i", prog_type),
                ])
                .output()
                .await;

            if let Ok(output) = output {
                if output.status.success() {
                    println!("✅ Success with programmer type: {}", prog_type);
                    return self.load_extracted_firmware(&format!("firmware_{}.hex", prog_type), "", prog_type).await;
                }
            }
        }

        Err(anyhow!("All generic bootloader methods failed"))
    }

    async fn dfu_extraction(&self) -> Result<AtmegaFirmware> {
        if !self.target.usb_config.has_dfu {
            return Err(anyhow!("Device does not support DFU"));
        }

        println!("📥 Attempting DFU extraction...");

        let output = Command::new(&self.tools.usb_tools.dfu_util)
            .args(&[
                "-d", &format!("{:04x}:{:04x}", self.target.usb_config.vendor_id, self.target.usb_config.product_id),
                "-a", "0",
                "-U", "firmware_dfu.bin",
            ])
            .output()
            .await?;

        if output.status.success() {
            return self.load_extracted_firmware("firmware_dfu.bin", "", "DFU").await;
        }

        Err(anyhow!("DFU extraction failed: {}", String::from_utf8_lossy(&output.stderr)))
    }

    async fn custom_protocol_extraction(&self) -> Result<AtmegaFirmware> {
        println!("🕵️ Analyzing custom USB protocol...");

        // Capture USB traffic to understand the protocol
        let capture_file = "usb_capture.pcap";
        let capture_process = Command::new(&self.tools.usb_tools.usb_capture)
            .args(&[
                "-i", "usbmon1",
                "-f", &format!("usb.device_address == {}", self.target.usb_config.vendor_id), // Simplified
                "-w", capture_file,
            ])
            .spawn();

        if capture_process.is_err() {
            return Err(anyhow!("Could not start USB capture"));
        }

        // Interact with device to generate traffic
        tokio::time::sleep(Duration::from_secs(10)).await;

        // Stop capture and analyze
        // This would require packet analysis implementation
        println!("📊 USB traffic captured, analyzing...");

        // For now, try to reverse engineer common patterns
        self.try_common_vendor_commands().await
    }

    async fn try_common_vendor_commands(&self) -> Result<AtmegaFirmware> {
        println!("🔍 Trying common vendor commands...");

        // Common vendor command patterns for firmware reading
        let vendor_commands = [
            (0x40, 0x01, 0x0000, 0x0000), // Read version
            (0x40, 0x02, 0x0000, 0x0000), // Read flash page
            (0x40, 0x03, 0x0000, 0x0000), // Read EEPROM
            (0x40, 0x10, 0x0000, 0x0000), // Enter bootloader
            (0x40, 0xFF, 0x0000, 0x0000), // Debug command
        ];

        for (req_type, request, value, index) in &vendor_commands {
            // This would require libusb implementation to send actual USB control transfers
            println!("🔄 Trying vendor command: {:02x} {:02x} {:04x} {:04x}", req_type, request, value, index);
        }

        Err(anyhow!("Custom protocol analysis incomplete - requires USB control transfer implementation"))
    }

    async fn isp_extraction(&self) -> Result<AtmegaFirmware> {
        println!("🔌 Attempting ISP interface discovery...");
        
        // This would require finding ISP pins on the PCB
        println!("⚠️ ISP extraction requires hardware connection to MISO/MOSI/SCK/RESET pins");
        println!("💡 Look for 6-pin ISP header or test points labeled with these signals");

        Err(anyhow!("ISP interface not accessible via USB"))
    }

    async fn bootloader_memory_dump(&self) -> Result<AtmegaFirmware> {
        println!("💾 Attempting bootloader memory analysis...");

        // Try to read bootloader section (usually at high memory addresses)
        let bootloader_start = self.target.flash_size - 4096; // Common 4KB bootloader

        let output = Command::new(&self.tools.avrdude_path)
            .args(&[
                "-c", &self.tools.programmer_type,
                "-p", &self.get_avrdude_part_name(),
                "-U", &format!("flash:r:bootloader.hex:i:0x{:x}:0x1000", bootloader_start),
            ])
            .output()
            .await?;

        if output.status.success() {
            println!("📖 Bootloader section read successfully");
            // Analyze bootloader for vulnerabilities or information leakage
            self.analyze_bootloader_code("bootloader.hex").await?;
        }

        Err(anyhow!("Could not extract firmware via bootloader analysis"))
    }

    // UTILITY METHODS

    fn get_avrdude_part_name(&self) -> String {
        match self.target.chip_variant {
            AtmegaVariant::ATmega328P => "m328p".to_string(),
            AtmegaVariant::ATmega32U4 => "m32u4".to_string(),
            AtmegaVariant::ATmega2560 => "m2560".to_string(),
            AtmegaVariant::ATmega16U2 => "m16u2".to_string(),
            AtmegaVariant::ATmega8U2 => "m8u2".to_string(),
            AtmegaVariant::Unknown(ref name) => {
                // Try to guess based on name
                if name.contains("328") { "m328p".to_string() }
                else if name.contains("32") { "m32u4".to_string() }
                else { "m328p".to_string() } // Default guess
            }
        }
    }

    async fn load_extracted_firmware(&self, flash_file: &str, eeprom_file: &str, method: &str) -> Result<AtmegaFirmware> {
        let flash_data = if std::path::Path::new(flash_file).exists() {
            self.hex_to_binary(flash_file).await?
        } else {
            Vec::new()
        };

        let eeprom_data = if !eeprom_file.is_empty() && std::path::Path::new(eeprom_file).exists() {
            self.hex_to_binary(eeprom_file).await?
        } else {
            Vec::new()






















