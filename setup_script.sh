#!/bin/bash

# USB Device Sandbox - Complete Setup Script
# Creates an isolated environment for analyzing untrusted USB devices
# Author: For the paranoid and the wise

set -e

# Configuration
SANDBOX_DIR="/opt/usb-sandbox"
VM_NAME="usb-sandbox-vm"
VM_DISK_SIZE="20G"
ISO_URL="https://releases.ubuntu.com/22.04.3/ubuntu-22.04.3-desktop-amd64.iso"
LOG_DIR="$SANDBOX_DIR/logs"
CAPTURE_DIR="$SANDBOX_DIR/captures"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔒 USB Device Sandbox Setup${NC}"
echo "Creating isolated environment for untrusted USB analysis..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Install required packages
echo -e "${YELLOW}📦 Installing required packages...${NC}"
apt update
apt install -y \
    qemu-kvm \
    libvirt-daemon-system \
    libvirt-clients \
    bridge-utils \
    virt-manager \
    ovmf \
    wireshark \
    tshark \
    usbutils \
    tcpdump \
    socat \
    python3-pip \
    python3-venv \
    git \
    build-essential \
    libusb-1.0-0-dev \
    libpcap-dev

# Create sandbox directory structure
echo -e "${YELLOW}📁 Setting up directory structure...${NC}"
mkdir -p "$SANDBOX_DIR"/{logs,captures,vms,scripts,tools}
mkdir -p "$LOG_DIR"/{usb,network,system,vm}
mkdir -p "$CAPTURE_DIR"/{pcap,usb,files}

# Create virtual environment for Python tools
echo -e "${YELLOW}🐍 Setting up Python environment...${NC}"
python3 -m venv "$SANDBOX_DIR/venv"
source "$SANDBOX_DIR/venv/bin/activate"
pip install pyusb scapy psutil

# Download and compile USBPcap alternative (since we're on Linux)
echo -e "${YELLOW}🔧 Setting up USB monitoring tools...${NC}"
cd "$SANDBOX_DIR/tools"
git clone https://github.com/desowin/usbpcap.git || true
cd usbpcap
make || echo "USBPcap build may have issues, continuing..."

# Create USB monitoring script
cat > "$SANDBOX_DIR/scripts/usb_monitor.py" << 'EOF'
#!/usr/bin/env python3
"""
USB Device Monitor - Captures and logs USB device activity
"""
import os
import sys
import time
import json
import subprocess
import threading
from datetime import datetime
import usb.core
import usb.util

class USBMonitor:
    def __init__(self, log_dir):
        self.log_dir = log_dir
        self.running = False
        self.devices_before = set()
        self.log_file = os.path.join(log_dir, f"usb_activity_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
    def get_usb_devices(self):
        """Get currently connected USB devices"""
        devices = set()
        try:
            for device in usb.core.find(find_all=True):
                device_info = {
                    'vendor_id': hex(device.idVendor),
                    'product_id': hex(device.idProduct),
                    'manufacturer': usb.util.get_string(device, device.iManufacturer) if device.iManufacturer else None,
                    'product': usb.util.get_string(device, device.iProduct) if device.iProduct else None,
                    'serial': usb.util.get_string(device, device.iSerialNumber) if device.iSerialNumber else None,
                    'bus': device.bus,
                    'address': device.address
                }
                devices.add(json.dumps(device_info, sort_keys=True))
        except Exception as e:
            self.log_event('error', f"Error scanning USB devices: {e}")
        return devices
    
    def log_event(self, event_type, data):
        """Log USB events to file"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'data': data
        }
        print(f"[{event['timestamp']}] {event_type.upper()}: {data}")
        
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
    
    def start_monitoring(self):
        """Start USB device monitoring"""
        self.running = True
        self.devices_before = self.get_usb_devices()
        self.log_event('info', 'USB monitoring started')
        
        while self.running:
            try:
                current_devices = self.get_usb_devices()
                
                # Check for new devices
                new_devices = current_devices - self.devices_before
                for device_json in new_devices:
                    device = json.loads(device_json)
                    self.log_event('device_connected', device)
                
                # Check for removed devices
                removed_devices = self.devices_before - current_devices
                for device_json in removed_devices:
                    device = json.loads(device_json)
                    self.log_event('device_disconnected', device)
                
                self.devices_before = current_devices
                time.sleep(1)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.log_event('error', f"Monitoring error: {e}")
                time.sleep(5)
        
        self.log_event('info', 'USB monitoring stopped')
    
    def stop_monitoring(self):
        """Stop USB monitoring"""
        self.running = False

if __name__ == "__main__":
    log_dir = sys.argv[1] if len(sys.argv) > 1 else "/opt/usb-sandbox/logs/usb"
    monitor = USBMonitor(log_dir)
    
    try:
        monitor.start_monitoring()
    except KeyboardInterrupt:
        monitor.stop_monitoring()
EOF

chmod +x "$SANDBOX_DIR/scripts/usb_monitor.py"

# Create network monitoring script
cat > "$SANDBOX_DIR/scripts/network_monitor.sh" << 'EOF'
#!/bin/bash

# Network Monitor for USB Sandbox
CAPTURE_DIR="$1"
INTERFACE="$2"

if [ -z "$CAPTURE_DIR" ] || [ -z "$INTERFACE" ]; then
    echo "Usage: $0 <capture_dir> <interface>"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="$CAPTURE_DIR/network_$TIMESTAMP.pcap"

echo "Starting network capture on $INTERFACE..."
echo "Saving to: $PCAP_FILE"

# Start tcpdump with detailed logging
tcpdump -i "$INTERFACE" \
    -w "$PCAP_FILE" \
    -s 0 \
    -v \
    -n \
    'not (host 127.0.0.1 or net 224.0.0.0/4)' &

TCPDUMP_PID=$!
echo "Network monitoring started (PID: $TCPDUMP_PID)"
echo "Press Ctrl+C to stop..."

# Trap interrupt signal
trap "kill $TCPDUMP_PID; echo 'Network monitoring stopped'" INT

wait $TCPDUMP_PID
EOF

chmod +x "$SANDBOX_DIR/scripts/network_monitor.sh"

# Create VM management script
cat > "$SANDBOX_DIR/scripts/vm_manager.sh" << 'EOF'
#!/bin/bash

# VM Manager for USB Sandbox
VM_NAME="usb-sandbox-vm"
SANDBOX_DIR="/opt/usb-sandbox"

case "$1" in
    "create")
        echo "Creating sandbox VM..."
        
        # Create VM disk
        qemu-img create -f qcow2 "$SANDBOX_DIR/vms/sandbox.qcow2" 20G
        
        # Download Ubuntu ISO if not exists
        if [ ! -f "$SANDBOX_DIR/vms/ubuntu-22.04.3-desktop-amd64.iso" ]; then
            echo "Downloading Ubuntu ISO..."
            wget -O "$SANDBOX_DIR/vms/ubuntu-22.04.3-desktop-amd64.iso" \
                "https://releases.ubuntu.com/22.04.3/ubuntu-22.04.3-desktop-amd64.iso"
        fi
        
        echo "VM created. Use 'start' to boot from ISO for installation."
        ;;
        
    "start")
        echo "Starting sandbox VM..."
        
        # Get USB device to pass through (if specified)
        USB_DEVICE=""
        if [ ! -z "$2" ]; then
            USB_DEVICE="-device usb-host,vendorid=0x$2,productid=0x$3"
        fi
        
        qemu-system-x86_64 \
            -name "$VM_NAME" \
            -machine q35 \
            -cpu host \
            -smp 2 \
            -m 4G \
            -enable-kvm \
            -drive file="$SANDBOX_DIR/vms/sandbox.qcow2",format=qcow2 \
            -cdrom "$SANDBOX_DIR/vms/ubuntu-22.04.3-desktop-amd64.iso" \
            -boot menu=on \
            -usb \
            -device usb-tablet \
            $USB_DEVICE \
            -netdev user,id=net0,hostfwd=tcp::2222-:22 \
            -device virtio-net,netdev=net0 \
            -vnc :1 \
            -monitor telnet:127.0.0.1:1234,server,nowait &
        
        echo "VM started. Connect via VNC on :5901 or monitor on telnet 127.0.0.1:1234"
        ;;
        
    "stop")
        echo "Stopping sandbox VM..."
        pkill -f "qemu-system.*$VM_NAME" || echo "VM not running"
        ;;
        
    "status")
        if pgrep -f "qemu-system.*$VM_NAME" > /dev/null; then
            echo "VM is running"
        else
            echo "VM is stopped"
        fi
        ;;
        
    "usb-passthrough")
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 usb-passthrough <vendor_id> <product_id>"
            echo "Example: $0 usb-passthrough 1234 5678"
            exit 1
        fi
        
        echo "Passing through USB device $2:$3 to VM..."
        echo "device_add usb-host,vendorid=0x$2,productid=0x$3" | nc 127.0.0.1 1234
        ;;
        
    *)
        echo "Usage: $0 {create|start|stop|status|usb-passthrough}"
        echo ""
        echo "Commands:"
        echo "  create                    - Create new VM"
        echo "  start [vendor_id] [product_id] - Start VM (optionally with USB passthrough)"
        echo "  stop                      - Stop VM"
        echo "  status                    - Check VM status"
        echo "  usb-passthrough <vid> <pid> - Pass USB device to running VM"
        ;;
esac
EOF

chmod +x "$SANDBOX_DIR/scripts/vm_manager.sh"

# Create main sandbox control script
cat > "$SANDBOX_DIR/sandbox.sh" << 'EOF'
#!/bin/bash

# USB Device Sandbox Controller
SANDBOX_DIR="/opt/usb-sandbox"
LOG_DIR="$SANDBOX_DIR/logs"
CAPTURE_DIR="$SANDBOX_DIR/captures"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    USB Device Sandbox                       ║"
    echo "║                 Analyze with Confidence                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

list_usb_devices() {
    echo -e "${YELLOW}🔌 Connected USB Devices:${NC}"
    lsusb | while read line; do
        echo "  $line"
    done
    echo ""
}

start_monitoring() {
    echo -e "${GREEN}🚀 Starting comprehensive monitoring...${NC}"
    
    # Start USB monitoring
    source "$SANDBOX_DIR/venv/bin/activate"
    python3 "$SANDBOX_DIR/scripts/usb_monitor.py" "$LOG_DIR/usb" &
    USB_MONITOR_PID=$!
    echo "USB Monitor started (PID: $USB_MONITOR_PID)"
    
    # Start network monitoring on default interface
    DEFAULT_IFACE=$(ip route | grep default | head -1 | awk '{print $5}')
    "$SANDBOX_DIR/scripts/network_monitor.sh" "$CAPTURE_DIR/pcap" "$DEFAULT_IFACE" &
    NETWORK_MONITOR_PID=$!
    echo "Network Monitor started (PID: $NETWORK_MONITOR_PID)"
    
    # Start system call monitoring if available
    if command -v strace >/dev/null 2>&1; then
        echo "System call monitoring available - attach manually with strace"
    fi
    
    echo ""
    echo -e "${GREEN}✅ All monitors active${NC}"
    echo "Log files location: $LOG_DIR"
    echo "Capture files location: $CAPTURE_DIR"
    echo ""
    echo -e "${YELLOW}Press Ctrl+C to stop all monitoring${NC}"
    
    # Wait for interrupt
    trap "echo ''; echo 'Stopping monitors...'; kill $USB_MONITOR_PID $NETWORK_MONITOR_PID 2>/dev/null; exit 0" INT
    wait
}

analyze_logs() {
    echo -e "${BLUE}📊 Log Analysis Summary${NC}"
    echo "=========================="
    
    if [ -d "$LOG_DIR/usb" ]; then
        echo -e "${YELLOW}USB Events:${NC}"
        find "$LOG_DIR/usb" -name "*.json" -exec wc -l {} + | tail -1 | awk '{print "  Total events: " $1}'
        
        # Show recent USB events
        latest_usb_log=$(find "$LOG_DIR/usb" -name "*.json" | sort | tail -1)
        if [ -f "$latest_usb_log" ]; then
            echo "  Recent events:"
            tail -5 "$latest_usb_log" | while read line; do
                echo "    $(echo $line | jq -r '.timestamp + " - " + .type + ": " + (.data | tostring)')"
            done
        fi
        echo ""
    fi
    
    if [ -d "$CAPTURE_DIR/pcap" ]; then
        echo -e "${YELLOW}Network Captures:${NC}"
        find "$CAPTURE_DIR/pcap" -name "*.pcap" -exec ls -lh {} + | awk '{print "  " $9 " (" $5 ")"}'
        echo ""
    fi
}

case "$1" in
    "start")
        show_banner
        list_usb_devices
        start_monitoring
        ;;
        
    "vm")
        shift
        "$SANDBOX_DIR/scripts/vm_manager.sh" "$@"
        ;;
        
    "analyze")
        analyze_logs
        ;;
        
    "list")
        list_usb_devices
        ;;
        
    "clean")
        echo -e "${YELLOW}🧹 Cleaning old logs and captures...${NC}"
        find "$LOG_DIR" -type f -mtime +7 -delete
        find "$CAPTURE_DIR" -type f -mtime +7 -delete
        echo "Cleanup complete"
        ;;
        
    *)
        show_banner
        echo "Usage: $0 {start|vm|analyze|list|clean}"
        echo ""
        echo -e "${YELLOW}Commands:${NC}"
        echo "  start     - Start comprehensive monitoring"
        echo "  vm        - VM management (create|start|stop|status)"
        echo "  analyze   - Analyze captured logs"
        echo "  list      - List connected USB devices"
        echo "  clean     - Clean old logs and captures"
        echo ""
        echo -e "${YELLOW}Quick Start:${NC}"
        echo "  1. $0 vm create                    # Create sandbox VM"
        echo "  2. $0 start                        # Start monitoring"
        echo "  3. Insert suspicious USB device"
        echo "  4. $0 vm usb-passthrough <vid> <pid>  # Pass device to VM"
        echo "  5. $0 analyze                      # Review results"
        ;;
esac
EOF

chmod +x "$SANDBOX_DIR/sandbox.sh"

# Create symlink for easy access
ln -sf "$SANDBOX_DIR/sandbox.sh" /usr/local/bin/usb-sandbox

# Set proper permissions
chown -R root:root "$SANDBOX_DIR"
chmod -R 755 "$SANDBOX_DIR"

# Create systemd service for automatic monitoring
cat > /etc/systemd/system/usb-sandbox-monitor.service << 'EOF'
[Unit]
Description=USB Sandbox Monitor
After=network.target

[Service]
Type=simple
ExecStart=/opt/usb-sandbox/sandbox.sh start
Restart=always
RestartSec=10
User=root
WorkingDirectory=/opt/usb-sandbox

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}✅ USB Sandbox setup complete!${NC}"
echo ""
echo -e "${YELLOW}Quick start guide:${NC}"
echo "1. Create VM: usb-sandbox vm create"
echo "2. Start monitoring: usb-sandbox start"
echo "3. Insert suspicious device"
echo "4. Pass device to VM: usb-sandbox vm usb-passthrough <vendor_id> <product_id>"
echo "5. Analyze results: usb-sandbox analyze"
echo ""
echo -e "${BLUE}Files created:${NC}"
echo "  Main script: /usr/local/bin/usb-sandbox"
echo "  Sandbox dir: $SANDBOX_DIR"
echo "  Logs: $LOG_DIR"
echo "  Captures: $CAPTURE_DIR"
echo ""
echo -e "${RED}⚠️  Remember: This is for analysis only. Never use suspicious devices on production systems!${NC}"