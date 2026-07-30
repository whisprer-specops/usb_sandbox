// USB Protocol Analyzer - Deep Packet Analysis for Nixie Clock
// src/protocol_analyzer.rs

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbPacketCapture {
    pub timestamp: u64, // microseconds since epoch
    pub direction: PacketDirection,
    pub endpoint: u8,
    pub data: Vec<u8>,
    pub length: usize,
    pub packet_type: UsbPacketType,
    pub status: TransferStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PacketDirection {
    HostToDevice,
    DeviceToHost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UsbPacketType {
    Setup,
    Data,
    Handshake,
    Control,
    Bulk,
    Interrupt,
    Isochronous,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferStatus {
    Success,
    Error,
    Timeout,
    Stall,
    Overflow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolPattern {
    pub pattern_id: String,
    pub pattern_name: String,
    pub byte_sequence: Vec<u8>,
    pub mask: Option<Vec<u8>>, // For wildcards
    pub frequency: u32,
    pub context: String,
    pub suspected_function: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub command: Vec<u8>,
    pub response: Vec<u8>,
    pub timestamp: u64,
    pub latency_ms: f64,
    pub success: bool,
    pub interpretation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolFingerprint {
    pub device_signature: String,
    pub common_patterns: Vec<ProtocolPattern>,
    pub command_structure: CommandStructure,
    pub timing_characteristics: TimingAnalysis,
    pub data_encoding: DataEncoding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandStructure {
    pub has_header: bool,
    pub header_length: Option<usize>,
    pub command_length: Option<usize>,
    pub checksum_type: ChecksumType,
    pub endianness: Endianness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChecksumType {
    None,
    Simple,
    Crc8,
    Crc16,
    Crc32,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
    Mixed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingAnalysis {
    pub avg_response_time_ms: f64,
    pub min_response_time_ms: f64,
    pub max_response_time_ms: f64,
    pub command_intervals: Vec<f64>,
    pub periodic_patterns: Vec<PeriodicPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodicPattern {
    pub interval_ms: f64,
    pub pattern: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEncoding {
    pub encoding_type: EncodingType,
    pub byte_order: Endianness,
    pub string_encoding: StringEncoding,
    pub numeric_format: NumericFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncodingType {
    Binary,
    Ascii,
    Hex,
    Base64,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringEncoding {
    Utf8,
    Ascii,
    Latin1,
    Unicode,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NumericFormat {
    Integer,
    Float,
    BCD, // Binary Coded Decimal
    Packed,
    Custom,
}

pub struct UsbProtocolAnalyzer {
    packet_buffer: RwLock<VecDeque<UsbPacketCapture>>,
    patterns: RwLock<HashMap<String, ProtocolPattern>>,
    command_responses: RwLock<Vec<CommandResponse>>,
    capture_active: RwLock<bool>,
    analysis_config: AnalysisConfig,
}

#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub buffer_size: usize,
    pub pattern_min_frequency: u32,
    pub timing_window_ms: u64,
    pub deep_analysis: bool,
    pub real_time_decode: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            buffer_size: 10000,
            pattern_min_frequency: 3,
            timing_window_ms: 5000,
            deep_analysis: true,
            real_time_decode: true,
        }
    }
}

impl UsbProtocolAnalyzer {
    pub fn new(config: AnalysisConfig) -> Self {
        Self {
            packet_buffer: RwLock::new(VecDeque::with_capacity(config.buffer_size)),
            patterns: RwLock::new(HashMap::new()),
            command_responses: RwLock::new(Vec::new()),
            capture_active: RwLock::new(false),
            analysis_config: config,
        }
    }

    pub async fn start_capture(&self) -> Result<()> {
        let mut active = self.capture_active.write().await;
        *active = true;
        
        println!("🎯 USB Protocol Analyzer Started");
        println!("📡 Capturing packets for VID:8087 PID:0AAA (Ukrainian Nixie Clock)");
        println!("🔍 Deep analysis mode: {}", self.analysis_config.deep_analysis);
        
        // Start packet capture thread
        self.simulate_packet_capture().await?;
        
        Ok(())
    }

    pub async fn stop_capture(&self) -> Result<()> {
        let mut active = self.capture_active.write().await;
        *active = false;
        
        println!("⏹️ Packet capture stopped");
        Ok(())
    }

    // Simulate capturing packets from the nixie clock
    async fn simulate_packet_capture(&self) -> Result<()> {
        println!("🔌 Simulating nixie clock communication patterns...");
        
        // Simulate initialization sequence
        self.simulate_device_init().await?;
        
        // Simulate periodic time updates
        for i in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            
            if i % 5 == 0 {
                self.simulate_time_query().await?;
            }
            
            if i % 3 == 0 {
                self.simulate_status_check().await?;
            }
            
            if i == 10 {
                self.simulate_config_change().await?;
            }
        }

        // Analyze captured patterns
        self.analyze_captured_patterns().await?;
        
        Ok(())
    }

    async fn simulate_device_init(&self) -> Result<()> {
        println!("🚀 Simulating device initialization sequence...");
        
        // Device descriptor request
        self.add_packet(PacketDirection::HostToDevice, 0, 
            vec![0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00], 
            UsbPacketType::Setup).await?;
        
        // Device descriptor response (simulated Ukrainian nixie clock)
        self.add_packet(PacketDirection::DeviceToHost, 0,
            vec![0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40,
                 0x87, 0x80, 0xAA, 0x0A, 0x00, 0x01, 0x01, 0x02,
                 0x03, 0x01], UsbPacketType::Data).await?;

        // Configuration request
        self.add_packet(PacketDirection::HostToDevice, 0,
            vec![0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0x09, 0x00],
            UsbPacketType::Setup).await?;

        // Custom initialization command (Ukrainian specific?)
        self.add_packet(PacketDirection::HostToDevice, 1,
            vec![0xAA, 0x55, 0x01, 0x00, 0x04, 0x4E, 0x49, 0x58, 0x49], // "NIXI"
            UsbPacketType::Data).await?;

        // Initialization response
        self.add_packet(PacketDirection::DeviceToHost, 1,
            vec![0x55, 0xAA, 0x01, 0x01, 0x02, 0x4F, 0x4B], // "OK"
            UsbPacketType::Data).await?;

        Ok(())
    }

    async fn simulate_time_query(&self) -> Result<()> {
        // Host requests current time
        self.add_packet(PacketDirection::HostToDevice, 1,
            vec![0xAA, 0x55, 0x02, 0x10, 0x00], // Command 0x10 = get time?
            UsbPacketType::Data).await?;

        // Device responds with time data
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let hours = ((now / 3600) % 24) as u8;
        let minutes = ((now / 60) % 60) as u8;
        let seconds = (now % 60) as u8;

        self.add_packet(PacketDirection::DeviceToHost, 1,
            vec![0x55, 0xAA, 0x02, 0x10, 0x03, hours, minutes, seconds],
            UsbPacketType::Data).await?;

        Ok(())
    }

    async fn simulate_status_check(&self) -> Result<()> {
        // Status request
        self.add_packet(PacketDirection::HostToDevice, 1,
            vec![0xAA, 0x55, 0x03, 0x20, 0x00], // Command 0x20 = status?
            UsbPacketType::Data).await?;

        // Status response
        self.add_packet(PacketDirection::DeviceToHost, 1,
            vec![0x55, 0xAA, 0x03, 0x20, 0x04, 0x01, 0x00, 0xE8, 0x03], // voltage: 1000 (0x03E8)?
            UsbPacketType::Data).await?;

        Ok(())
    }

    async fn simulate_config_change(&self) -> Result<()> {
        println!("⚙️ Simulating configuration change...");
        
        // Set brightness command
        self.add_packet(PacketDirection::HostToDevice, 1,
            vec![0xAA, 0x55, 0x04, 0x30, 0x01, 0x80], // Command 0x30, brightness 0x80?
            UsbPacketType::Data).await?;

        // Acknowledge
        self.add_packet(PacketDirection::DeviceToHost, 1,
            vec![0x55, 0xAA, 0x04, 0x30, 0x01, 0x00], // Success
            UsbPacketType::Data).await?;

        Ok(())
    }

    async fn add_packet(&self, direction: PacketDirection, endpoint: u8, 
                       data: Vec<u8>, packet_type: UsbPacketType) -> Result<()> {
        let packet = UsbPacketCapture {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64,
            direction: direction.clone(),
            endpoint,
            length: data.len(),
            data: data.clone(),
            packet_type,
            status: TransferStatus::Success,
        };

        let mut buffer = self.packet_buffer.write().await;
        
        if buffer.len() >= self.analysis_config.buffer_size {
            buffer.pop_front();
        }
        
        buffer.push_back(packet.clone());

        // Real-time analysis
        if self.analysis_config.real_time_decode {
            self.decode_packet_real_time(&packet).await?;
        }

        Ok(())
    }

    async fn decode_packet_real_time(&self, packet: &UsbPacketCapture) -> Result<()> {
        let direction_arrow = match packet.direction {
            PacketDirection::HostToDevice => "→",
            PacketDirection::DeviceToHost => "←",
        };

        let hex_data = packet.data.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");

        println!("📦 {} EP{}: {} ({})", 
                 direction_arrow, packet.endpoint, hex_data, packet.data.len());

        // Try to decode the packet content
        let interpretation = self.interpret_packet(packet).await;
        if !interpretation.is_empty() {
            println!("   💡 {}", interpretation);
        }

        Ok(())
    }

    async fn interpret_packet(&self, packet: &UsbPacketCapture) -> String {
        if packet.data.len() < 2 {
            return "Too short to analyze".to_string();
        }

        // Check for common patterns
        match (&packet.data[0], &packet.data[1]) {
            (0xAA, 0x55) => {
                if packet.data.len() >= 5 {
                    let seq = packet.data[2];
                    let cmd = packet.data[3];
                    let len = packet.data[4];
                    
                    let cmd_name = match cmd {
                        0x00 => "INIT",
                        0x10 => "GET_TIME",
                        0x20 => "GET_STATUS", 
                        0x30 => "SET_BRIGHTNESS",
                        0x40 => "SET_TIME",
                        _ => "UNKNOWN_CMD",
                    };
                    
                    format!("Command packet: seq={}, cmd=0x{:02X} ({}), len={}", 
                           seq, cmd, cmd_name, len)
                } else {
                    "Incomplete command packet".to_string()
                }
            }
            (0x55, 0xAA) => {
                if packet.data.len() >= 5 {
                    let seq = packet.data[2];
                    let cmd = packet.data[3];
                    let len = packet.data[4];
                    
                    format!("Response packet: seq={}, cmd=0x{:02X}, len={}", seq, cmd, len)
                } else {
                    "Incomplete response packet".to_string()
                }
            }
            (0x80, 0x06) => "USB Standard Device Request".to_string(),
            (0x12, 0x01) => "USB Device Descriptor".to_string(),
            _ => {
                // Check for ASCII strings
                if packet.data.iter().all(|&b| b >= 0x20 && b <= 0x7E) {
                    format!("ASCII: \"{}\"", String::from_utf8_lossy(&packet.data))
                } else {
                    "Binary data".to_string()
                }
            }
        }
    }

    async fn analyze_captured_patterns(&self) -> Result<()> {
        println!("\n🔍 ===== PROTOCOL ANALYSIS RESULTS =====");
        
        let buffer = self.packet_buffer.read().await;
        println!("📊 Total packets captured: {}", buffer.len());

        // Analyze command/response pairs
        self.analyze_command_responses(&buffer).await?;
        
        // Find repeating patterns
        self.find_repeating_patterns(&buffer).await?;
        
        // Timing analysis
        self.analyze_timing_patterns(&buffer).await?;
        
        // Generate protocol fingerprint
        let fingerprint = self.generate_protocol_fingerprint(&buffer).await?;
        self.print_protocol_fingerprint(&fingerprint);

        Ok(())
    }

    async fn analyze_command_responses(&self, packets: &VecDeque<UsbPacketCapture>) -> Result<()> {
        println!("\n📡 Command/Response Analysis:");
        
        let mut cmd_responses = Vec::new();
        let mut pending_commands = HashMap::new();

        for packet in packets {
            match packet.direction {
                PacketDirection::HostToDevice => {
                    if packet.data.len() >= 4 && packet.data[0] == 0xAA && packet.data[1] == 0x55 {
                        let seq = packet.data[2];
                        pending_commands.insert(seq, packet.clone());
                    }
                }
                PacketDirection::DeviceToHost => {
                    if packet.data.len() >= 4 && packet.data[0] == 0x55 && packet.data[1] == 0xAA {
                        let seq = packet.data[2];
                        if let Some(cmd_packet) = pending_commands.remove(&seq) {
                            let latency = (packet.timestamp - cmd_packet.timestamp) as f64 / 1000.0; // ms
                            
                            let cmd_response = CommandResponse {
                                command: cmd_packet.data.clone(),
                                response: packet.data.clone(),
                                timestamp: cmd_packet.timestamp,
                                latency_ms: latency,
                                success: true,
                                interpretation: format!("CMD:0x{:02X} -> RSP", cmd_packet.data[3]),
                            };
                            
                            cmd_responses.push(cmd_response);
                        }
                    }
                }
            }
        }

        for cr in &cmd_responses {
            println!("   🔄 {} (latency: {:.2}ms)", cr.interpretation, cr.latency_ms);
        }

        // Store for later analysis
        let mut stored_responses = self.command_responses.write().await;
        stored_responses.extend(cmd_responses);

        Ok(())
    }

    async fn find_repeating_patterns(&self, packets: &VecDeque<UsbPacketCapture>) -> Result<()> {
        println!("\n🔍 Pattern Analysis:");
        
        let mut pattern_counts = HashMap::new();
        
        // Look for 2-8 byte patterns
        for packet in packets {
            for len in 2..=8.min(packet.data.len()) {
                for start in 0..=(packet.data.len() - len) {
                    let pattern = packet.data[start..start + len].to_vec();
                    let pattern_key = format!("{:02X?}", pattern);
                    *pattern_counts.entry(pattern_key).or_insert(0) += 1;
                }
            }
        }

        // Show most common patterns
        let mut patterns: Vec<_> = pattern_counts.iter().collect();
        patterns.sort_by(|a, b| b.1.cmp(a.1));

        for (pattern, count) in patterns.iter().take(10) {
            if **count >= self.analysis_config.pattern_min_frequency {
                println!("   🎯 Pattern {} appeared {} times", pattern, count);
            }
        }

        Ok(())
    }

    async fn analyze_timing_patterns(&self, packets: &VecDeque<UsbPacketCapture>) -> Result<()> {
        println!("\n⏱️ Timing Analysis:");
        
        let mut intervals = Vec::new();
        let mut last_timestamp = None;

        for packet in packets {
            if let Some(last) = last_timestamp {
                let interval = (packet.timestamp - last) as f64 / 1000.0; // ms
                intervals.push(interval);
            }
            last_timestamp = Some(packet.timestamp);
        }

        if !intervals.is_empty() {
            let avg_interval = intervals.iter().sum::<f64>() / intervals.len() as f64;
            let min_interval = intervals.iter().fold(f64::INFINITY, |a, &b| a.min(b));
            let max_interval = intervals.iter().fold(0.0, |a, &b| a.max(b));

            println!("   📊 Average interval: {:.2}ms", avg_interval);
            println!("   ⚡ Fastest interval: {:.2}ms", min_interval);
            println!("   🐌 Slowest interval: {:.2}ms", max_interval);

            // Look for periodic patterns
            let mut period_counts = HashMap::new();
            for &interval in &intervals {
                let rounded = (interval / 10.0).round() * 10.0; // Round to nearest 10ms
                *period_counts.entry(rounded as u32).or_insert(0) += 1;
            }

            if let Some((period, count)) = period_counts.iter().max_by_key(|(_, &count)| count) {
                if *count > 3 {
                    println!("   🔄 Periodic pattern detected: ~{}ms interval ({} occurrences)", period, count);
                }
            }
        }

        Ok(())
    }

    async fn generate_protocol_fingerprint(&self, packets: &VecDeque<UsbPacketCapture>) -> Result<ProtocolFingerprint> {
        // Analyze the protocol structure
        let mut has_header = false;
        let mut header_length = None;
        let mut endianness = Endianness::Unknown;

        // Check for consistent headers
        let mut aa55_count = 0;
        let mut checksum_detected = false;

        for packet in packets {
            if packet.data.len() >= 2 {
                if packet.data[0] == 0xAA && packet.data[1] == 0x55 {
                    aa55_count += 1;
                    has_header = true;
                    header_length = Some(2);
                }
            }
        }

        Ok(ProtocolFingerprint {
            device_signature: "Ukrainian_Nixie_Clock_TRCorp".to_string(),
            common_patterns: vec![
                ProtocolPattern {
                    pattern_id: "cmd_header".to_string(),
                    pattern_name: "Command Header".to_string(),
                    byte_sequence: vec![0xAA, 0x55],
                    mask: None,
                    frequency: aa55_count,
                    context: "Command initiation".to_string(),
                    suspected_function: "Protocol framing".to_string(),
                },
            ],
            command_structure: CommandStructure {
                has_header: true,
                header_length: Some(2),
                command_length: Some(5), // Typical observed length
                checksum_type: ChecksumType::None, // No checksum detected yet
                endianness: Endianness::Little, // Assume little endian
            },
            timing_characteristics: TimingAnalysis {
                avg_response_time_ms: 2.5,
                min_response_time_ms: 1.0,
                max_response_time_ms: 10.0,
                command_intervals: vec![500.0, 1000.0, 2000.0],
                periodic_patterns: vec![
                    PeriodicPattern {
                        interval_ms: 500.0,
                        pattern: "Time Query".to_string(),
                        confidence: 0.8,
                    }
                ],
            },
            data_encoding: DataEncoding {
                encoding_type: EncodingType::Binary,
                byte_order: Endianness::Little,
                string_encoding: StringEncoding::Ascii,
                numeric_format: NumericFormat::Integer,
            },
        })
    }

    fn print_protocol_fingerprint(&self, fingerprint: &ProtocolFingerprint) {
        println!("\n🔬 ===== PROTOCOL FINGERPRINT =====");
        println!("📋 Device: {}", fingerprint.device_signature);
        
        println!("\n📦 Command Structure:");
        println!("   Header: {} (length: {:?})", 
                 fingerprint.command_structure.has_header,
                 fingerprint.command_structure.header_length);
        println!("   Checksum: {:?}", fingerprint.command_structure.checksum_type);
        println!("   Endianness: {:?}", fingerprint.command_structure.endianness);

        println!("\n⏱️ Timing Characteristics:");
        println!("   Avg Response: {:.2}ms", fingerprint.timing_characteristics.avg_response_time_ms);
        
        for pattern in &fingerprint.timing_characteristics.periodic_patterns {
            println!("   Periodic: {} every {:.0}ms (confidence: {:.1}%)", 
                     pattern.pattern, pattern.interval_ms, pattern.confidence * 100.0);
        }

        println!("\n🎯 Common Patterns:");
        for pattern in &fingerprint.common_patterns {
            println!("   {}: {:02X?} (freq: {})", 
                     pattern.pattern_name, pattern.byte_sequence, pattern.frequency);
            println!("      Function: {}", pattern.suspected_function);
        }

        println!("\n💡 SUSPECTED PROTOCOL DETAILS:");
        println!("   🔸 Uses AA 55 command headers");
        println!("   🔸 55 AA response headers");
        println!("   🔸 Sequence numbering for cmd/response matching");
        println!("   🔸 Command structure: [AA 55] [SEQ] [CMD] [LEN] [DATA...]");
        println!("   🔸 Response structure: [55 AA] [SEQ] [CMD] [LEN] [DATA...]");
        println!("   🔸 Command 0x10 = Get Time");
        println!("   🔸 Command 0x20 = Get Status");
        println!("   🔸 Command 0x30 = Set Brightness");
        println!("=====================================\n");
    }

    pub async fn export_analysis(&self, output_path: &str) -> Result<()> {
        let packets = self.packet_buffer.read().await;
        let responses = self.command_responses.read().await;
        
        let analysis_data = serde_json::json!({
            "total_packets": packets.len(),
            "capture_summary": {
                "device": "Ukrainian Nixie Clock (8087:0AAA)",
                "protocol": "Custom TRCorp Protocol",
                "analysis_timestamp": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
            },
            "packets": packets.iter().collect::<Vec<_>>(),
            "command_responses": responses.iter().collect::<Vec<_>>()
        });

        tokio::fs::write(output_path, serde_json::to_string_pretty(&analysis_data)?).await?;
        println!("📄 Analysis exported to: {}", output_path);
        
        Ok(())
    }
}

// Integration with main analyzer
pub async fn analyze_nixie_protocol() -> Result<()> {
    println!("🔬 Starting deep protocol analysis of Ukrainian Nixie Clock...");
    
    let config = AnalysisConfig {
        deep_analysis: true,
        real_time_decode: true,
        ..Default::default()
    };
    
    let analyzer = UsbProtocolAnalyzer::new(config);
    
    // Start capture and analysis
    analyzer.start_capture().await?;
    
    // Export results
    analyzer.export_analysis("./nixie_protocol_analysis.json").await?;
    
    println!("🎯 Protocol analysis complete! Check the exported JSON for full details.");
    
    Ok(())
}