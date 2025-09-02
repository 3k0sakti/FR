#!/usr/bin/env python3
"""
Digital Forensics Network Capture Tool
======================================

A comprehensive tool for capturing network traffic for digital forensic analysis.
Supports multiple capture methods and filtering options.

Usage:
    python3 network_capture.py --interface eth0 --duration 300
    python3 network_capture.py --interface eth0 --filter "port 80" --output evidence/
    python3 network_capture.py --interface eth0 --count 1000 --format pcap

Author: Digital Forensics Lab
License: MIT
"""

import os
import sys
import argparse
import subprocess
import signal
import time
import json
import threading
from datetime import datetime
from pathlib import Path


class NetworkCapture:
    """Class for handling network traffic capture operations."""
    
    def __init__(self):
        self.supported_formats = ['pcap', 'pcapng']
        self.interface = None
        self.output_file = None
        self.capture_filter = None
        self.duration = None
        self.packet_count = None
        self.capture_format = 'pcap'
        self.metadata = {}
        self.capture_process = None
        
    def check_privileges(self):
        """Check if running with sufficient privileges for packet capture."""
        if os.geteuid() != 0:
            print("❌ Error: Root privileges required for packet capture")
            print("   Please run with sudo: sudo python3 network_capture.py ...")
            return False
        return True
    
    def check_dependencies(self):
        """Check if required tools are available."""
        dependencies = {
            'tcpdump': 'tcpdump',
            'tshark': 'tshark',
            'dumpcap': 'dumpcap'
        }
        
        available_tools = []
        
        for tool_name, command in dependencies.items():
            try:
                subprocess.run(['which', command], capture_output=True, check=True)
                available_tools.append(tool_name)
            except subprocess.CalledProcessError:
                continue
        
        if not available_tools:
            print("❌ Error: No capture tools available")
            print("   Please install: tcpdump, wireshark, or tshark")
            return False
        
        print(f"✅ Available tools: {', '.join(available_tools)}")
        return True
    
    def get_network_interfaces(self):
        """Get list of available network interfaces."""
        try:
            # Get interfaces using ip command
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                interfaces = []
                for line in result.stdout.split('\n'):
                    if ':' in line and 'mtu' in line:
                        interface = line.split(':')[1].strip().split('@')[0]
                        if interface != 'lo':  # Skip loopback
                            interfaces.append(interface)
                return interfaces
        except:
            pass
        
        # Fallback to common interface names
        return ['eth0', 'wlan0', 'en0', 'wlp0s20f3']
    
    def verify_interface(self):
        """Verify that the specified interface exists and is up."""
        try:
            # Check if interface exists
            result = subprocess.run(['ip', 'link', 'show', self.interface], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                print(f"❌ Error: Interface {self.interface} does not exist")
                available_interfaces = self.get_network_interfaces()
                if available_interfaces:
                    print(f"   Available interfaces: {', '.join(available_interfaces)}")
                return False
            
            # Check if interface is up
            if 'state UP' not in result.stdout and 'state UNKNOWN' not in result.stdout:
                print(f"⚠️  Warning: Interface {self.interface} may be down")
            
            print(f"✅ Interface verified: {self.interface}")
            return True
            
        except Exception as e:
            print(f"❌ Error verifying interface: {e}")
            return False
    
    def get_interface_info(self):
        """Collect interface information for metadata."""
        try:
            interface_info = {}
            
            # Get IP address
            try:
                result = subprocess.run(['ip', 'addr', 'show', self.interface], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    interface_info['ip_info'] = result.stdout
            except:
                pass
            
            # Get interface statistics
            try:
                result = subprocess.run(['ip', '-s', 'link', 'show', self.interface], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    interface_info['stats'] = result.stdout
            except:
                pass
            
            self.metadata = {
                'timestamp': datetime.now().isoformat(),
                'interface': self.interface,
                'hostname': os.uname().nodename,
                'capture_tool': 'network_capture.py v1.0',
                'format': self.capture_format,
                'filter': self.capture_filter,
                'duration': self.duration,
                'packet_count': self.packet_count,
                'interface_info': interface_info
            }
            
        except Exception as e:
            print(f"⚠️  Warning: Could not collect all interface information: {e}")
    
    def capture_with_tcpdump(self):
        """Capture network traffic using tcpdump."""
        print("🔍 Starting tcpdump network capture...")
        
        tcpdump_command = [
            'tcpdump',
            '-i', self.interface,
            '-w', self.output_file
        ]
        
        # Add filter if specified
        if self.capture_filter:
            tcpdump_command.append(self.capture_filter)
        
        # Add packet count limit if specified
        if self.packet_count:
            tcpdump_command.extend(['-c', str(self.packet_count)])
        
        print(f"📡 Capturing on interface: {self.interface}")
        print(f"   Output file: {self.output_file}")
        if self.capture_filter:
            print(f"   Filter: {self.capture_filter}")
        if self.duration:
            print(f"   Duration: {self.duration} seconds")
        if self.packet_count:
            print(f"   Packet limit: {self.packet_count}")
        
        start_time = time.time()
        
        try:
            # Start capture process
            log_file = f"{self.output_file}.log"
            with open(log_file, 'w') as log:
                self.capture_process = subprocess.Popen(
                    tcpdump_command,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    text=True
                )
            
            # Handle duration-based capture
            if self.duration:
                print(f"⏱️  Capturing for {self.duration} seconds...")
                time.sleep(self.duration)
                self.capture_process.terminate()
                self.capture_process.wait()
            else:
                print("⏱️  Capturing packets... Press Ctrl+C to stop")
                self.capture_process.wait()
            
            end_time = time.time()
            actual_duration = end_time - start_time
            
            if self.capture_process.returncode in [0, -15]:  # 0 = normal, -15 = SIGTERM
                file_size = os.path.getsize(self.output_file) if os.path.exists(self.output_file) else 0
                print(f"✅ Network capture completed in {actual_duration:.2f} seconds")
                print(f"   File size: {file_size / 1024 / 1024:.2f} MB")
                
                self.metadata['capture_time'] = f"{actual_duration:.2f} seconds"
                self.metadata['file_size'] = file_size
                
                # Get packet count from tcpdump output
                try:
                    with open(log_file, 'r') as f:
                        log_content = f.read()
                        for line in log_content.split('\n'):
                            if 'packets captured' in line:
                                print(f"   {line}")
                                break
                except:
                    pass
                
                return True
            else:
                print("❌ Error during network capture")
                return False
                
        except KeyboardInterrupt:
            print("\n⏹️  Capture interrupted by user")
            if self.capture_process:
                self.capture_process.terminate()
                self.capture_process.wait()
            
            end_time = time.time()
            actual_duration = end_time - start_time
            file_size = os.path.getsize(self.output_file) if os.path.exists(self.output_file) else 0
            
            print(f"✅ Network capture stopped after {actual_duration:.2f} seconds")
            print(f"   File size: {file_size / 1024 / 1024:.2f} MB")
            
            self.metadata['capture_time'] = f"{actual_duration:.2f} seconds"
            self.metadata['file_size'] = file_size
            return True
            
        except Exception as e:
            print(f"❌ Error during tcpdump capture: {e}")
            return False
    
    def capture_with_tshark(self):
        """Capture network traffic using tshark."""
        print("🔍 Starting tshark network capture...")
        
        tshark_command = [
            'tshark',
            '-i', self.interface,
            '-w', self.output_file
        ]
        
        # Add filter if specified
        if self.capture_filter:
            tshark_command.extend(['-f', self.capture_filter])
        
        # Add packet count limit if specified
        if self.packet_count:
            tshark_command.extend(['-c', str(self.packet_count)])
        
        # Add duration if specified
        if self.duration:
            tshark_command.extend(['-a', f'duration:{self.duration}'])
        
        print(f"📡 Capturing on interface: {self.interface}")
        print(f"   Output file: {self.output_file}")
        
        start_time = time.time()
        
        try:
            log_file = f"{self.output_file}.log"
            with open(log_file, 'w') as log:
                process = subprocess.run(
                    tshark_command,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    text=True
                )
            
            end_time = time.time()
            actual_duration = end_time - start_time
            
            if process.returncode == 0:
                file_size = os.path.getsize(self.output_file) if os.path.exists(self.output_file) else 0
                print(f"✅ Network capture completed in {actual_duration:.2f} seconds")
                print(f"   File size: {file_size / 1024 / 1024:.2f} MB")
                
                self.metadata['capture_time'] = f"{actual_duration:.2f} seconds"
                self.metadata['file_size'] = file_size
                return True
            else:
                print("❌ Error during tshark capture")
                return False
                
        except Exception as e:
            print(f"❌ Error during tshark capture: {e}")
            return False
    
    def analyze_capture(self):
        """Basic analysis of captured traffic."""
        if not os.path.exists(self.output_file):
            return
        
        print("🔍 Analyzing captured traffic...")
        
        try:
            # Use tcpdump to get basic statistics
            result = subprocess.run([
                'tcpdump', '-r', self.output_file, '-n', '-q'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if lines and lines[0]:
                    print(f"   Total packets: {len(lines)}")
                    
                    # Count different protocols
                    protocols = {}
                    for line in lines[:1000]:  # Analyze first 1000 packets
                        if ' IP ' in line:
                            protocols['IP'] = protocols.get('IP', 0) + 1
                        if ' TCP ' in line:
                            protocols['TCP'] = protocols.get('TCP', 0) + 1
                        if ' UDP ' in line:
                            protocols['UDP'] = protocols.get('UDP', 0) + 1
                        if ' ICMP ' in line:
                            protocols['ICMP'] = protocols.get('ICMP', 0) + 1
                    
                    if protocols:
                        print("   Protocol distribution:")
                        for proto, count in protocols.items():
                            print(f"     {proto}: {count}")
            
        except Exception as e:
            print(f"⚠️  Could not analyze capture: {e}")
    
    def save_metadata(self):
        """Save capture metadata to JSON file."""
        metadata_file = f"{self.output_file}.metadata.json"
        
        try:
            with open(metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
            print(f"📋 Metadata saved to: {metadata_file}")
            
        except Exception as e:
            print(f"⚠️  Warning: Could not save metadata: {e}")
    
    def capture(self, interface, output_file, capture_filter=None, 
               duration=None, packet_count=None, format_type='pcap'):
        """Main capture method."""
        
        self.interface = interface
        self.output_file = output_file
        self.capture_filter = capture_filter
        self.duration = duration
        self.packet_count = packet_count
        self.capture_format = format_type
        
        print("🚀 Digital Forensics Network Capture")
        print("=" * 50)
        
        # Preliminary checks
        if not self.check_privileges():
            return False
        
        if not self.check_dependencies():
            return False
        
        if not self.verify_interface():
            return False
        
        # Collect interface information
        self.get_interface_info()
        
        # Create output directory if needed
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\n⏹️  Stopping capture...")
            if self.capture_process:
                self.capture_process.terminate()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Perform capture based on available tools
        success = False
        
        # Try tshark first (more features), then tcpdump
        if subprocess.run(['which', 'tshark'], capture_output=True).returncode == 0:
            success = self.capture_with_tshark()
        elif subprocess.run(['which', 'tcpdump'], capture_output=True).returncode == 0:
            success = self.capture_with_tcpdump()
        else:
            print("❌ Error: No capture tools available")
            return False
        
        if not success:
            print("❌ Network capture failed")
            return False
        
        # Analyze capture
        self.analyze_capture()
        
        # Save metadata
        self.save_metadata()
        
        print("\n✅ Network capture completed successfully!")
        print(f"   Output: {self.output_file}")
        
        return True


def main():
    """Main function with argument parsing."""
    
    parser = argparse.ArgumentParser(
        description='Digital Forensics Network Capture Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture for 5 minutes
  sudo python3 network_capture.py --interface eth0 --duration 300
  
  # Capture HTTP traffic
  sudo python3 network_capture.py --interface eth0 --filter "port 80"
  
  # Capture 1000 packets to specific directory
  sudo python3 network_capture.py --interface eth0 --count 1000 --output evidence/
        """
    )
    
    parser.add_argument(
        '--interface', '-i',
        required=True,
        help='Network interface to capture on (e.g., eth0, wlan0)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file or directory for capture (default: current directory)'
    )
    
    parser.add_argument(
        '--filter', '-f',
        help='BPF capture filter (e.g., "port 80", "host 192.168.1.1")'
    )
    
    parser.add_argument(
        '--duration', '-d',
        type=int,
        help='Capture duration in seconds'
    )
    
    parser.add_argument(
        '--count', '-c',
        type=int,
        help='Number of packets to capture'
    )
    
    parser.add_argument(
        '--format',
        choices=['pcap', 'pcapng'],
        default='pcap',
        help='Capture file format (default: pcap)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Network Capture Tool v1.0'
    )
    
    args = parser.parse_args()
    
    # Determine output file
    if args.output:
        if os.path.isdir(args.output):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(args.output, f"network_capture_{timestamp}.{args.format}")
        else:
            output_file = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"network_capture_{timestamp}.{args.format}"
    
    # Initialize capture tool
    network_tool = NetworkCapture()
    
    # Perform capture
    success = network_tool.capture(
        interface=args.interface,
        output_file=output_file,
        capture_filter=args.filter,
        duration=args.duration,
        packet_count=args.count,
        format_type=args.format
    )
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
