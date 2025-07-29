// STM32F208 Firmware Extraction and Analysis Toolkit
// Integrates with our USB Sandbox for complete analysis pipeline

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct Stm32Target {
    pub device_id: String,
    pub chip_variant: Stm32Variant,
    pub flash_size: u32,
    pub ram_size: u32,
    pub protection_level: ReadProtectionLevel,
    pub debug_interface: DebugInterface,
    pub usb_config: UsbConfiguration,
}

#[derive(Debug, Clone)]
pub enum Stm32Variant {
    STM32F208VE, // 512KB Flash, 128KB RAM
    STM32F208VG, // 1MB Flash, 128KB RAM  
    STM32F208ZE, // 512KB Flash, 128KB RAM
    STM32F208ZG, // 1MB Flash, 128KB RAM
}

#[derive(Debug, Clone)]
pub enum ReadProtectionLevel {
    RDP0, // No protection - full debug access
    RDP1, // Debug disabled, flash readable via bootloader
    RDP2, // Permanent protection - flash unreadable
    Unknown,
}

#[derive(Debug, Clone)]
pub enum DebugInterface {
    SWD,     // Serial Wire Debug (2-pin: SWDIO, SWCLK)
    JTAG,    // Joint Test Action Group (4-pin: TDI, TDO, TMS, TCK)
    None,    // Debug pins not accessible
}

#[derive(Debug, Clone)]
pub struct UsbConfiguration {
    pub connector_type: UsbConnectorType,
    pub usb_speed: UsbSpeed,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_class: UsbDeviceClass,
}

#[derive(Debug, Clone)]
pub enum UsbConnectorType {
    UsbA,
    UsbC,
    MicroUsb,
    MiniUsb,
}

#[derive(Debug, Clone)]
pub enum UsbSpeed {
    LowSpeed,   // 1.5 Mbps
    FullSpeed,  // 12 Mbps  
    HighSpeed,  // 480 Mbps
}

#[derive(Debug, Clone)]
pub enum UsbDeviceClass {
    HID,           // Human Interface Device
    CDC,           // Communication Device Class
    MSC,           // Mass Storage Class
    CustomVendor,  // Vendor-specific
}

// Main firmware extraction orchestrator
pub struct FirmwareExtractor {
    target: Stm32Target,
    tools: ExtractionTools,
    sandbox_manager: crate::usb_sandbox::UsbSandboxManager,
}

#[derive(Debug)]
pub struct ExtractionTools {
    pub openocd_config: OpenOcdConfig,
    pub stlink_path: PathBuf,
    pub dfu_util_path: PathBuf,
    pub usb_analyzer: UsbAnalyzer,
}

#[derive(Debug)]
pub struct OpenOcdConfig {
    pub interface_config: String,
    pub target_config: String,
    pub custom_scripts: Vec<String>,
}

impl FirmwareExtractor {
    pub fn new(target: Stm32Target, sandbox_manager: crate::usb_sandbox::UsbSandboxManager) -> Self {
        let tools = ExtractionTools {
            openocd_config: OpenOcdConfig {
                interface_config: "interface/stlink.cfg".to_string(),
                target_config: "target/stm32f2x.cfg".to_string(),
                custom_scripts: Vec::new(),
            },
            stlink_path: PathBuf::from("/usr/bin/st-flash"),
            dfu_util_path: PathBuf::from("/usr/bin/dfu-util"),
            usb_analyzer: UsbAnalyzer::new(),
        };

        Self {
            target,
            tools,
            sandbox_manager,
        }
    }

    // Multi-vector firmware extraction attack
    pub async fn extract_firmware(&self) -> Result<FirmwareImage> {
        println!("🎯 Starting multi-vector firmware extraction on STM32F208...");

        // Phase 1: USB-based extraction attempts
        if let Ok(firmware) = self.usb_extraction_attack().await {
            println!("✅ USB extraction successful!");
            return Ok(firmware);
        }

        // Phase 2: Debug interface attacks
        if let Ok(firmware) = self.debug_interface_attack().await {
            println!("✅ Debug interface extraction successful!");
            return Ok(firmware);
        }

        // Phase 3: Side-channel and fault injection
        if let Ok(firmware) = self.advanced_extraction_techniques().await {
            println!("✅ Advanced extraction techniques successful!");
            return Ok(firmware);
        }

        Err(anyhow!("All extraction methods failed - target may be RDP2 protected"))
    }

    // Attack Vector 1: USB-based extraction
    async fn usb_extraction_attack(&self) -> Result<FirmwareImage> {
        println!("🔍 Attempting USB-based firmware extraction...");

        // Method 1: DFU (Device Firmware Update) mode
        if let Ok(firmware) = self.dfu_extraction().await {
            return Ok(firmware);
        }

        // Method 2: Custom USB protocol exploitation
        if let Ok(firmware) = self.usb_protocol_exploit().await {
            return Ok(firmware);
        }

        // Method 3: USB bootloader hijacking
        if let Ok(firmware) = self.bootloader_hijack().await {
            return Ok(firmware);
        }

        Err(anyhow!("USB extraction methods failed"))
    }

    async fn dfu_extraction(&self) -> Result<FirmwareImage> {
        println!("🔧 Attempting DFU mode extraction...");

        // Check if device supports DFU
        let dfu_devices = self.scan_dfu_devices().await?;
        
        if dfu_devices.is_empty() {
            return Err(anyhow!("No DFU devices found"));
        }

        for device in dfu_devices {
            println!("📱 Found DFU device: {:?}", device);

            // Try to read firmware via DFU
            let output = Command::new(&self.tools.dfu_util_path)
                .args(&[
                    "-d", &format!("{:04x}:{:04x}", device.vendor_id, device.product_id),
                    "-a", "0",  // Alternate setting 0
                    "-U", "firmware_dump.bin",  // Upload from device
                ])
                .output()
                .await?;

            if output.status.success() {
                println!("✅ DFU extraction successful!");
                return self.load_firmware_image("firmware_dump.bin").await;
            } else {
                println!("❌ DFU extraction failed: {}", String::from_utf8_lossy(&output.stderr));
            }
        }

        Err(anyhow!("DFU extraction failed for all devices"))
    }

    async fn usb_protocol_exploit(&self) -> Result<FirmwareImage> {
        println!("🕵️ Analyzing USB protocol for exploitation vectors...");

        // Capture USB traffic to understand protocol
        let usb_capture = self.tools.usb_analyzer.capture_traffic(Duration::from_secs(30)).await?;
        
        // Look for custom vendor commands that might leak firmware
        let vendor_commands = self.analyze_vendor_commands(&usb_capture);
        
        for cmd in vendor_commands {
            if let Ok(firmware) = self.exploit_vendor_command(&cmd).await {
                return Ok(firmware);
            }
        }

        // Try to trigger firmware update mode
        if let Ok(firmware) = self.trigger_update_mode().await {
            return Ok(firmware);
        }

        Err(anyhow!("USB protocol exploitation failed"))
    }

    async fn bootloader_hijack(&self) -> Result<FirmwareImage> {
        println!("🎭 Attempting bootloader hijacking...");

        // STM32F208 system bootloader entry methods:
        // 1. BOOT0 pin high + reset
        // 2. Software trigger via specific RAM pattern + reset
        // 3. USB DFU trigger sequence

        // Method 1: Try USB DFU trigger sequence
        let dfu_trigger_sequence = vec![
            UsbControlTransfer {
                request_type: 0x21, // Host to device, class, interface
                request: 0x00,      // DETACH
                value: 1000,        // Timeout in ms
                index: 0,
                data: Vec::new(),
            }
        ];

        for transfer in dfu_trigger_sequence {
            if self.send_usb_control_transfer(&transfer).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(100)).await;
                
                // Check if device re-enumerated in DFU mode
                if self.scan_dfu_devices().await?.len() > 0 {
                    return self.dfu_extraction().await;
                }
            }
        }

        Err(anyhow!("Bootloader hijacking failed"))
    }

    // Attack Vector 2: Debug interface exploitation
    async fn debug_interface_attack(&self) -> Result<FirmwareImage> {
        println!("🔌 Attempting debug interface attacks...");

        match self.target.debug_interface {
            DebugInterface::SWD => self.swd_extraction().await,
            DebugInterface::JTAG => self.jtag_extraction().await,
            DebugInterface::None => Err(anyhow!("No debug interface available")),
        }
    }

    async fn swd_extraction(&self) -> Result<FirmwareImage> {
        println!("🔗 Attempting SWD (Serial Wire Debug) extraction...");

        // Create OpenOCD script for SWD connection
        let openocd_script = format!(r#"
            source [find {interface}]
            source [find {target}]
            
            init
            reset halt
            
            # Check protection level
            set protection [stm32f2x options_read 0]
            echo "Protection level: $protection"
            
            # Try to read flash
            dump_image firmware_swd.bin 0x08000000 0x{flash_size:x}
            
            shutdown
        "#, 
            interface = self.tools.openocd_config.interface_config,
            target = self.tools.openocd_config.target_config,
            flash_size = self.target.flash_size
        );

        // Execute OpenOCD
        let output = Command::new("openocd")
            .args(&["-c", &openocd_script])
            .output()
            .await?;

        if output.status.success() && std::path::Path::new("firmware_swd.bin").exists() {
            println!("✅ SWD extraction successful!");
            return self.load_firmware_image("firmware_swd.bin").await;
        }

        // If direct read failed, try advanced techniques
        self.swd_advanced_techniques().await
    }

    async fn swd_advanced_techniques(&self) -> Result<FirmwareImage> {
        println!("🧠 Trying advanced SWD techniques...");

        // Technique 1: Option byte manipulation
        if let Ok(firmware) = self.option_byte_attack().await {
            return Ok(firmware);
        }

        // Technique 2: Flash readout via debug registers
        if let Ok(firmware) = self.debug_register_readout().await {
            return Ok(firmware);
        }

        // Technique 3: Memory mapping exploitation
        if let Ok(firmware) = self.memory_mapping_exploit().await {
            return Ok(firmware);
        }

        Err(anyhow!("Advanced SWD techniques failed"))
    }

    async fn option_byte_attack(&self) -> Result<FirmwareImage> {
        println!("⚙️ Attempting option byte manipulation...");

        let openocd_script = r#"
            init
            reset halt
            
            # Read current option bytes
            set current_options [stm32f2x options_read 0]
            echo "Current options: $current_options"
            
            # Try to unlock option bytes
            stm32f2x unlock 0
            stm32f2x options_unlock 0
            
            # Attempt to set RDP to Level 0 (may cause mass erase on RDP1)
            # Only try this if we're prepared for mass erase!
            # stm32f2x options_write 0 0xAA 0xFF
            
            # Alternative: try to read via system memory bootloader
            dump_image bootloader.bin 0x1FFF0000 0x8000
            
            shutdown
        "#;

        let output = Command::new("openocd")
            .args(&["-c", openocd_script])
            .output()
            .await?;

        if std::path::Path::new("bootloader.bin").exists() {
            // Analyze bootloader for vulnerabilities
            return self.analyze_bootloader("bootloader.bin").await;
        }

        Err(anyhow!("Option byte attack failed"))
    }

    async fn debug_register_readout(&self) -> Result<FirmwareImage> {
        println!("📊 Attempting debug register readout...");

        let openocd_script = r#"
            init
            reset halt
            
            # Try to read flash via debug registers
            # This sometimes works even with RDP1
            
            set flash_base 0x08000000
            set flash_size 0x80000
            set chunk_size 0x1000
            
            set addr $flash_base
            set remaining $flash_size
            
            while {$remaining > 0} {
                set current_chunk [expr {$remaining < $chunk_size ? $remaining : $chunk_size}]
                
                # Use debug interface to read memory
                set data [read_memory $addr 32 [expr {$current_chunk / 4}]]
                
                # Save to file (this would need proper file handling)
                append_file "debug_readout.bin" $data
                
                set addr [expr {$addr + $current_chunk}]
                set remaining [expr {$remaining - $current_chunk}]
            }
            
            shutdown
        "#;

        let output = Command::new("openocd")
            .args(&["-c", openocd_script])
            .output()
            .await?;

        if std::path::Path::new("debug_readout.bin").exists() {
            return self.load_firmware_image("debug_readout.bin").await;
        }

        Err(anyhow!("Debug register readout failed"))
    }

    async fn memory_mapping_exploit(&self) -> Result<FirmwareImage> {
        println!("🗺️ Attempting memory mapping exploitation...");
        
        // STM32F2 has aliased memory regions that might bypass protection
        let memory_aliases = vec![
            (0x08000000, "Main flash"),
            (0x00000000, "Flash alias (boot from flash)"),
            (0x1FFF0000, "System memory (bootloader)"),
            (0x20000000, "SRAM"),
        ];

        for (addr, desc) in memory_aliases {
            println!("🔍 Trying to read from {}: 0x{:08x}", desc, addr);
            
            if let Ok(data) = self.read_memory_region(addr, 0x1000).await {
                if self.is_valid_firmware_data(&data) {
                    // Found valid firmware data, try to read full image
                    if let Ok(firmware) = self.read_memory_region(addr, self.target.flash_size).await {
                        return Ok(FirmwareImage {
                            data: firmware,
                            base_address: addr,
                            size: self.target.flash_size,
                            extraction_method: "Memory mapping exploit".to_string(),
                        });
                    }
                }
            }
        }

        Err(anyhow!("Memory mapping exploitation failed"))
    }

    // Attack Vector 3: Advanced techniques (side-channel, fault injection)
    async fn advanced_extraction_techniques(&self) -> Result<FirmwareImage> {
        println!("⚡ Attempting advanced extraction techniques...");

        // These would require specialized hardware
        println!("⚠️ Advanced techniques require specialized hardware:");
        println!("   - Voltage glitching equipment");
        println!("   - EM fault injection setup");
        println!("   - Decapping and optical readout tools");
        println!("   - Side-channel analysis equipment");

        Err(anyhow!("Advanced techniques not implemented (hardware required)"))
    }

    // Utility methods
    async fn scan_dfu_devices(&self) -> Result<Vec<DfuDevice>> {
        let output = Command::new(&self.tools.dfu_util_path)
            .args(&["-l"])
            .output()
            .await?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut devices = Vec::new();

        for line in output_str.lines() {
            if line.contains("Found DFU") {
                // Parse DFU device info
                // Format: "Found DFU: [1234:5678] ver=0100, devnum=1, cfg=1, intf=0, path="1-1", alt=0, name="@Internal Flash  /0x08000000/04*016Kg,01*064Kg,07*128Kg", serial="FFFFFFFEFFFF"
                
                if let Some(device) = self.parse_dfu_device_line(line) {
                    devices.push(device);
                }
            }
        }

        Ok(devices)
    }

    fn parse_dfu_device_line(&self, line: &str) -> Option<DfuDevice> {
        // Extract vendor:product ID
        let vid_pid_regex = regex::Regex::new(r"\[([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\]").ok()?;
        let captures = vid_pid_regex.captures(line)?;
        
        let vendor_id = u16::from_str_radix(&captures[1], 16).ok()?;
        let product_id = u16::from_str_radix(&captures[2], 16).ok()?;

        Some(DfuDevice {
            vendor_id,
            product_id,
            device_version: 0x0100, // Default
            configuration: 1,
            interface: 0,
            alternate_setting: 0,
        })
    }

    async fn send_usb_control_transfer(&self, transfer: &UsbControlTransfer) -> Result<Vec<u8>> {
        // This would use libusb or similar to send USB control transfers
        // For now, return placeholder
        Ok(Vec::new())
    }

    async fn read_memory_region(&self, address: u32, size: u32) -> Result<Vec<u8>> {
        let openocd_script = format!(r#"
            init
            reset halt
            dump_image memory_region.bin 0x{:08x} 0x{:x}
            shutdown
        "#, address, size);

        let output = Command::new("openocd")
            .args(&["-c", &openocd_script])
            .output()
            .await?;

        if output.status.success() && std::path::Path::new("memory_region.bin").exists() {
            let data = tokio::fs::read("memory_region.bin").await?;
            tokio::fs::remove_file("memory_region.bin").await?;
            return Ok(data);
        }

        Err(anyhow!("Failed to read memory region"))
    }

    fn is_valid_firmware_data(&self, data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }

        // Check for valid ARM Cortex-M vector table
        // First word should be initial stack pointer (in RAM)
        let initial_sp = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        
        // Second word should be reset vector (in flash, odd for Thumb mode)
        let reset_vector = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        // Initial SP should be in RAM range (0x20000000 - 0x20020000 for STM32F208)
        let sp_valid = initial_sp >= 0x20000000 && initial_sp <= 0x20020000;
        
        // Reset vector should be in flash range and have Thumb bit set
        let rv_valid = reset_vector >= 0x08000000 && 
                      reset_vector <= 0x08100000 && 
                      (reset_vector & 1) == 1;

        sp_valid && rv_valid
    }

    async fn load_firmware_image(&self, filename: &str) -> Result<FirmwareImage> {
        let data = tokio::fs::read(filename).await?;
        
        Ok(FirmwareImage {
            data,
            base_address: 0x08000000, // Default STM32 flash base
            size: self.target.flash_size,
            extraction_method: "Direct extraction".to_string(),
        })
    }

    async fn analyze_bootloader(&self, filename: &str) -> Result<FirmwareImage> {
        let bootloader_data = tokio::fs::read(filename).await?;
        
        // Analyze bootloader for vulnerabilities or information leakage
        println!("🔍 Analyzing bootloader for vulnerabilities...");
        
        // Look for hardcoded keys, backdoors, or info leaks
        let strings = self.extract_strings(&bootloader_data);
        for string in &strings {
            if string.len() > 10 && (string.contains("key") || string.contains("password")) {
                println!("🔑 Potential key found: {}", string);
            }
        }

        Err(anyhow!("Bootloader analysis complete but no firmware extracted"))
    }

    fn extract_strings(&self, data: &[u8]) -> Vec<String> {
        let mut strings = Vec::new();
        let mut current_string = Vec::new();
        
        for &byte in data {
            if byte >= 32 && byte <= 126 {
                current_string.push(byte);
            } else {
                if current_string.len() >= 4 {
                    if let Ok(s) = String::from_utf8(current_string.clone()) {
                        strings.push(s);
                    }
                }
                current_string.clear();
            }
        }
        
        strings
    }

    fn analyze_vendor_commands(&self, capture: &UsbCapture) -> Vec<VendorCommand> {
        // Analyze USB capture for vendor-specific commands
        Vec::new() // Placeholder
    }

    async fn exploit_vendor_command(&self, cmd: &VendorCommand) -> Result<FirmwareImage> {
        Err(anyhow!("Vendor command exploitation not implemented"))
    }

    async fn trigger_update_mode(&self) -> Result<FirmwareImage> {
        Err(anyhow!("Update mode trigger not implemented"))
    }

    async fn jtag_extraction(&self) -> Result<FirmwareImage> {
        println!("🔗 Attempting JTAG extraction...");
        
        let openocd_script = format!(r#"
            source [find interface/jlink.cfg]
            source [find target/stm32f2x.cfg]
            
            init
            reset halt
            
            dump_image firmware_jtag.bin 0x08000000 0x{:x}
            
            shutdown
        "#, self.target.flash_size);

        let output = Command::new("openocd")
            .args(&["-c", &openocd_script])
            .output()
            .await?;

        if output.status.success() && std::path::Path::new("firmware_jtag.bin").exists() {
            return self.load_firmware_image("firmware_jtag.bin").await;
        }

        Err(anyhow!("JTAG extraction failed"))
    }

    // Integration with USB Sandbox for analysis
    pub async fn analyze_extracted_firmware(&self, firmware: &FirmwareImage) -> Result<crate::usb_sandbox::ThreatAnalysis> {
        println!("🧪 Analyzing extracted firmware in sandbox...");

        // Create temporary file for analysis
        let temp_file = format!("/tmp/firmware_{}.bin", uuid::Uuid::new_v4());
        tokio::fs::write(&temp_file, &firmware.data).await?;

        // Create mock USB device for sandbox analysis
        let mock_device = crate::usb_sandbox::UsbDevice {
            id: uuid::Uuid::new_v4(),
            vendor_id: self.target.usb_config.vendor_id,
            product_id: self.target.usb_config.product_id,
            device_path: PathBuf::from(&temp_file),
            mount_point: Some(PathBuf::from(&temp_file)),
            device_type: crate::usb_sandbox::UsbDeviceType::Unknown,
            first_seen: std::time::Instant::now(),
            threat_score: 0.0,
        };

        // Run through sandbox analysis
        let analysis = self.sandbox_manager.analyze_usb_device(mock_device).await?;

        // Clean up
        tokio::fs::remove_file(&temp_file).await?;

        Ok(analysis)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirmwareImage {
    pub data: Vec<u8>,
    pub base_address: u32,
    pub size: u32,
    pub extraction_method: String,
}

#[derive(Debug)]
pub struct DfuDevice {
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_version: u16,
    pub configuration: u8,
    pub interface: u8,
    pub alternate_setting: u8,
}

#[derive(Debug)]
pub struct UsbControlTransfer {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct UsbCapture {
    pub packets: Vec<UsbPacket>,
    pub duration: Duration,
}

#[derive(Debug)]
pub struct UsbPacket {
    pub timestamp: std::time::Instant,
    pub direction: UsbDirection,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum UsbDirection {
    HostToDevice,
    DeviceToHost,
}

#[derive(Debug)]
pub struct VendorCommand {
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub data: Vec<u8>,
}

pub struct UsbAnalyzer;

impl UsbAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub async fn capture_traffic(&self, duration: Duration) -> Result<UsbCapture> {
        // This would use usbmon or Wireshark to capture USB traffic
        Ok(UsbCapture {
            packets: Vec::new(),
            duration,
        })
    }
}

// Example usage and integration
impl FirmwareExtractor {
    pub async fn full_nixie_clock_assault(&self) -> Result<()> {
        println!("🎯 Launching full assault on nixie tube clock STM32F208!");
        
        // Step 1: Extract firmware
        match self.extract_firmware().await {
            Ok(firmware) => {
                println!("✅ Firmware extraction successful! Size: {} bytes", firmware.data.len());
                
                // Step 2: Analyze in sandbox
                match self.analyze_extracted_firmware(&firmware).await {
                    Ok(analysis) => {
                        println!("🧪 Sandbox analysis complete!");
                        println!("Threat level: {:?}", analysis.threat_level);
                        println!("Indicators found: {}", analysis.indicators.len());
                        
                        // Step 3: Save results
                        self.save_analysis_results(&firmware, &analysis).await?;
                    }
                    Err(e) => println!("❌ Sandbox analysis failed: {}", e),
                }
            }
            Err(e) => {
                println!("❌ Firmware extraction failed: {}", e);
                println!("💡 Suggestions:");
                println!("   - Check if debug pins are accessible");
                println!("   - Try different debug interfaces (SWD/JTAG)");
                println!("   - Look for test points on PCB");
                println!("   - Consider advanced hardware attacks");
            }
        }

        Ok(())
    }

    async fn save_analysis_results(&self, firmware: &FirmwareImage, analysis: &crate::usb_sandbox::ThreatAnalysis) -> Result<()> {
        let results = serde_json::json!({
            "firmware": {
                "size": firmware.size,
                "extraction_method": firmware.extraction_method,
                "base_address": format!("0x{:08x}", firmware.base_address),
            },
            "analysis": analysis,
            "timestamp": chrono::Utc::now(),
        });

        let filename = format!("nixie_clock_analysis_{}.json", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
        tokio::fs::write(&filename, serde_json::to_string_pretty(&results)?).await?;
        
        println!("💾 Analysis results saved to: {}", filename);
        Ok(())
    }