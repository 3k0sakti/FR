#!/usr/bin/env python3
"""
Digital Forensics Disk Imaging Tool
===================================

A comprehensive tool for creating forensic disk images from storage devices.
Supports multiple imaging formats and verification methods.

Usage:
    python3 disk_image.py --source /dev/sdb --output disk.dd --verify
    python3 disk_image.py --source /dev/sdb --output disk.E01 --format ewf
    python3 disk_image.py --source /dev/sdb --output disk.dd --hash sha256

Author: Digital Forensics Lab
License: MIT
"""

import os
import sys
import argparse
import subprocess
import hashlib
import time
import json
import shutil
from datetime import datetime
from pathlib import Path


class DiskImaging:
    """Class for handling disk imaging operations."""
    
    def __init__(self):
        self.supported_formats = ['dd', 'ewf', 'raw', 'aff']
        self.source_device = None
        self.output_file = None
        self.imaging_format = 'dd'
        self.verify_integrity = False
        self.hash_algorithm = 'md5'
        self.quick_mode = False
        self.block_size = '1M'
        self.metadata = {}
        
    def check_privileges(self):
        """Check if running with sufficient privileges for disk access."""
        if os.geteuid() != 0:
            print("❌ Error: Root privileges required for disk imaging")
            print("   Please run with sudo: sudo python3 disk_image.py ...")
            return False
        return True
    
    def check_dependencies(self):
        """Check if required tools are available."""
        dependencies = {
            'dd': 'dd',
            'dc3dd': 'dc3dd',
            'ddrescue': 'ddrescue',
            'ewfacquire': 'ewfacquire'
        }
        
        available_tools = []
        
        for tool_name, command in dependencies.items():
            try:
                subprocess.run(['which', command], capture_output=True, check=True)
                available_tools.append(tool_name)
            except subprocess.CalledProcessError:
                continue
        
        if not available_tools:
            print("❌ Error: No imaging tools available")
            print("   Please install: dd, dc3dd, ddrescue, or ewf-tools")
            return False
        
        print(f"✅ Available tools: {', '.join(available_tools)}")
        return True
    
    def get_device_info(self):
        """Collect device information for metadata."""
        try:
            # Get device size
            device_size = 0
            if os.path.exists(self.source_device):
                try:
                    result = subprocess.run(['blockdev', '--getsize64', self.source_device], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        device_size = int(result.stdout.strip())
                except:
                    pass
            
            # Get device information
            device_info = {}
            try:
                result = subprocess.run(['fdisk', '-l', self.source_device], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    device_info['fdisk_output'] = result.stdout
            except:
                pass
            
            self.metadata = {
                'timestamp': datetime.now().isoformat(),
                'source_device': self.source_device,
                'device_size': device_size,
                'device_size_gb': round(device_size / (1024**3), 2) if device_size > 0 else 0,
                'imaging_tool': 'disk_image.py v1.0',
                'format': self.imaging_format,
                'block_size': self.block_size,
                'hostname': os.uname().nodename,
                'device_info': device_info
            }
            
        except Exception as e:
            print(f"⚠️  Warning: Could not collect all device information: {e}")
    
    def verify_source_device(self):
        """Verify that source device exists and is accessible."""
        if not os.path.exists(self.source_device):
            print(f"❌ Error: Source device {self.source_device} does not exist")
            return False
        
        if not os.access(self.source_device, os.R_OK):
            print(f"❌ Error: No read access to {self.source_device}")
            return False
        
        # Check if it's a block device
        if not os.path.isblk(self.source_device):
            print(f"⚠️  Warning: {self.source_device} is not a block device")
        
        print(f"✅ Source device verified: {self.source_device}")
        return True
    
    def image_with_dd(self):
        """Create disk image using dd."""
        print("🔍 Starting dd disk imaging...")
        
        dd_command = [
            'dd',
            f'if={self.source_device}',
            f'of={self.output_file}',
            f'bs={self.block_size}'
        ]
        
        if not self.quick_mode:
            dd_command.extend(['conv=noerror,sync'])
        
        print(f"💾 Creating disk image: {self.output_file}")
        print("   This may take a long time depending on disk size...")
        
        start_time = time.time()
        
        try:
            with open(f"{self.output_file}.log", 'w') as log_file:
                process = subprocess.run(
                    dd_command,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True
                )
            
            end_time = time.time()
            
            if process.returncode == 0:
                duration = end_time - start_time
                file_size = os.path.getsize(self.output_file)
                print(f"✅ Disk imaging completed in {duration:.2f} seconds")
                print(f"   File size: {file_size / 1024 / 1024 / 1024:.2f} GB")
                
                self.metadata['imaging_time'] = f"{duration:.2f} seconds"
                self.metadata['file_size'] = file_size
                return True
            else:
                print("❌ Error during disk imaging")
                return False
                
        except Exception as e:
            print(f"❌ Error during dd imaging: {e}")
            return False
    
    def image_with_dc3dd(self):
        """Create disk image using dc3dd (enhanced dd for forensics)."""
        print("🔍 Starting dc3dd disk imaging...")
        
        dc3dd_command = [
            'dc3dd',
            f'if={self.source_device}',
            f'of={self.output_file}',
            f'bs={self.block_size}',
            'hash=md5',
            'log=/tmp/dc3dd.log'
        ]
        
        if not self.quick_mode:
            dc3dd_command.extend(['conv=noerror,sync'])
        
        print(f"💾 Creating disk image: {self.output_file}")
        
        start_time = time.time()
        
        try:
            process = subprocess.run(dc3dd_command, capture_output=True, text=True)
            
            end_time = time.time()
            
            if process.returncode == 0:
                duration = end_time - start_time
                file_size = os.path.getsize(self.output_file)
                print(f"✅ Disk imaging completed in {duration:.2f} seconds")
                print(f"   File size: {file_size / 1024 / 1024 / 1024:.2f} GB")
                
                self.metadata['imaging_time'] = f"{duration:.2f} seconds"
                self.metadata['file_size'] = file_size
                
                # Extract hash from dc3dd output
                if 'md5' in process.stdout:
                    for line in process.stdout.split('\n'):
                        if 'md5' in line.lower():
                            print(f"   MD5: {line}")
                            break
                
                return True
            else:
                print("❌ Error during dc3dd imaging")
                print(process.stderr)
                return False
                
        except Exception as e:
            print(f"❌ Error during dc3dd imaging: {e}")
            return False
    
    def image_with_ddrescue(self):
        """Create disk image using ddrescue (for damaged drives)."""
        print("🔍 Starting ddrescue disk imaging...")
        
        mapfile = f"{self.output_file}.mapfile"
        
        ddrescue_command = [
            'ddrescue',
            self.source_device,
            self.output_file,
            mapfile
        ]
        
        if self.quick_mode:
            ddrescue_command.extend(['-n'])  # No scraping phase
        
        print(f"💾 Creating disk image: {self.output_file}")
        print(f"   Map file: {mapfile}")
        
        start_time = time.time()
        
        try:
            process = subprocess.run(ddrescue_command, capture_output=True, text=True)
            
            end_time = time.time()
            
            if process.returncode in [0, 1]:  # 0 = success, 1 = some errors but recoverable
                duration = end_time - start_time
                file_size = os.path.getsize(self.output_file)
                print(f"✅ Disk imaging completed in {duration:.2f} seconds")
                print(f"   File size: {file_size / 1024 / 1024 / 1024:.2f} GB")
                
                if process.returncode == 1:
                    print("⚠️  Some errors occurred during imaging (check mapfile)")
                
                self.metadata['imaging_time'] = f"{duration:.2f} seconds"
                self.metadata['file_size'] = file_size
                self.metadata['mapfile'] = mapfile
                return True
            else:
                print("❌ Error during ddrescue imaging")
                print(process.stderr)
                return False
                
        except Exception as e:
            print(f"❌ Error during ddrescue imaging: {e}")
            return False
    
    def calculate_hash(self, algorithm='md5'):
        """Calculate hash of the disk image."""
        print(f"🔐 Calculating {algorithm.upper()} hash...")
        
        hash_func = getattr(hashlib, algorithm)()
        
        try:
            with open(self.output_file, 'rb') as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            
            hash_value = hash_func.hexdigest()
            print(f"   {algorithm.upper()}: {hash_value}")
            
            # Save hash to file
            hash_file = f"{self.output_file}.{algorithm}"
            with open(hash_file, 'w') as f:
                f.write(f"{hash_value}  {os.path.basename(self.output_file)}\n")
            
            self.metadata[f'{algorithm}_hash'] = hash_value
            return hash_value
            
        except Exception as e:
            print(f"❌ Error calculating hash: {e}")
            return None
    
    def verify_image(self):
        """Basic verification of disk image."""
        print("🔍 Verifying disk image...")
        
        if not os.path.exists(self.output_file):
            print("❌ Error: Output file does not exist")
            return False
        
        file_size = os.path.getsize(self.output_file)
        if file_size == 0:
            print("❌ Error: Output file is empty")
            return False
        
        print(f"✅ Disk image verified:")
        print(f"   File: {self.output_file}")
        print(f"   Size: {file_size / 1024 / 1024 / 1024:.2f} GB")
        
        return True
    
    def save_metadata(self):
        """Save imaging metadata to JSON file."""
        metadata_file = f"{self.output_file}.metadata.json"
        
        try:
            with open(metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
            print(f"📋 Metadata saved to: {metadata_file}")
            
        except Exception as e:
            print(f"⚠️  Warning: Could not save metadata: {e}")
    
    def create_image(self, source_device, output_file, format_type='dd', 
                    verify=False, hash_algo='md5', quick=False):
        """Main imaging method."""
        
        self.source_device = source_device
        self.output_file = output_file
        self.imaging_format = format_type
        self.verify_integrity = verify
        self.hash_algorithm = hash_algo
        self.quick_mode = quick
        
        print("🚀 Digital Forensics Disk Imaging")
        print("=" * 50)
        
        # Preliminary checks
        if not self.check_privileges():
            return False
        
        if not self.check_dependencies():
            return False
        
        if not self.verify_source_device():
            return False
        
        # Collect device information
        self.get_device_info()
        
        # Create output directory if needed
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Check available space
        try:
            stat = shutil.disk_usage(output_dir if output_dir else '.')
            available_space = stat.free
            device_size = self.metadata.get('device_size', 0)
            
            if device_size > 0 and available_space < device_size * 1.1:  # 10% buffer
                print(f"⚠️  Warning: Available space ({available_space / 1024**3:.2f} GB) "
                      f"may not be sufficient for device ({device_size / 1024**3:.2f} GB)")
                response = input("Continue anyway? (y/N): ")
                if response.lower() != 'y':
                    return False
        except:
            pass
        
        # Perform imaging based on tool preference
        success = False
        
        # Try dc3dd first (forensically enhanced), then ddrescue, then dd
        if shutil.which('dc3dd') and format_type in ['dd', 'raw']:
            success = self.image_with_dc3dd()
        elif shutil.which('ddrescue') and format_type in ['dd', 'raw']:
            success = self.image_with_ddrescue()
        elif format_type in ['dd', 'raw']:
            success = self.image_with_dd()
        else:
            print(f"❌ Error: Unsupported format '{format_type}' or missing tools")
            return False
        
        if not success:
            print("❌ Disk imaging failed")
            return False
        
        # Verify if requested
        if verify and not self.verify_image():
            return False
        
        # Calculate hash if requested
        if hash_algo:
            self.calculate_hash(hash_algo)
        
        # Save metadata
        self.save_metadata()
        
        print("\n✅ Disk imaging completed successfully!")
        print(f"   Output: {self.output_file}")
        
        return True


def main():
    """Main function with argument parsing."""
    
    parser = argparse.ArgumentParser(
        description='Digital Forensics Disk Imaging Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic disk imaging
  sudo python3 disk_image.py --source /dev/sdb --output evidence/disk.dd
  
  # Quick imaging with verification
  sudo python3 disk_image.py --source /dev/sdb --output disk.dd --quick --verify
  
  # Full imaging with SHA256 hash
  sudo python3 disk_image.py --source /dev/sdb --output disk.dd --hash sha256 --verify
        """
    )
    
    parser.add_argument(
        '--source', '-s',
        required=True,
        help='Source device to image (e.g., /dev/sdb)'
    )
    
    parser.add_argument(
        '--output', '-o',
        required=True,
        help='Output file path for disk image'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['dd', 'ewf', 'raw', 'aff'],
        default='dd',
        help='Imaging format (default: dd)'
    )
    
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Verify disk image after creation'
    )
    
    parser.add_argument(
        '--hash',
        choices=['md5', 'sha1', 'sha256'],
        default='md5',
        help='Hash algorithm for integrity verification (default: md5)'
    )
    
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick imaging mode (faster but less thorough)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Disk Imaging Tool v1.0'
    )
    
    args = parser.parse_args()
    
    # Initialize imaging tool
    disk_tool = DiskImaging()
    
    # Perform imaging
    success = disk_tool.create_image(
        source_device=args.source,
        output_file=args.output,
        format_type=args.format,
        verify=args.verify,
        hash_algo=args.hash,
        quick=args.quick
    )
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
