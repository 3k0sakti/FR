#!/usr/bin/env python3
"""
Digital Forensics Memory Acquisition Tool
==========================================

A comprehensive tool for acquiring RAM memory from live systems for digital forensic analysis.
Supports multiple acquisition methods and output formats.

Usage:
    python3 memory_acquire.py --output memory_dump.raw --format lime
    python3 memory_acquire.py --output memory_dump.raw --format dd --quick
    python3 memory_acquire.py --output memory_dump.raw --verify --hash sha256

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
from datetime import datetime
from pathlib import Path


class MemoryAcquisition:
    """Class for handling memory acquisition operations."""
    
    def __init__(self):
        self.supported_formats = ['lime', 'dd', 'raw']
        self.output_file = None
        self.acquisition_format = 'lime'
        self.verify_integrity = False
        self.hash_algorithm = 'md5'
        self.quick_mode = False
        self.metadata = {}
        
    def check_privileges(self):
        """Check if running with sufficient privileges for memory acquisition."""
        if os.geteuid() != 0:
            print("❌ Error: Root privileges required for memory acquisition")
            print("   Please run with sudo: sudo python3 memory_acquire.py ...")
            return False
        return True
    
    def check_dependencies(self):
        """Check if required tools are available."""
        dependencies = {
            'lime': '/proc/iomem',  # LiME kernel module check
            'dd': 'dd',
            'volatility': 'vol.py'
        }
        
        missing = []
        
        # Check for LiME
        if not os.path.exists('/proc/iomem'):
            missing.append('LiME kernel module or /proc/iomem access')
            
        # Check for dd command
        try:
            subprocess.run(['which', 'dd'], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            missing.append('dd command')
            
        if missing:
            print("⚠️  Warning: Missing dependencies:")
            for dep in missing:
                print(f"   - {dep}")
            print("\nInstall missing tools before proceeding.")
            return False
        return True
    
    def get_system_info(self):
        """Collect system information for metadata."""
        try:
            # Get system information
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
            
            with open('/proc/version', 'r') as f:
                kernel_version = f.read().strip()
                
            # Extract total memory
            total_memory = None
            for line in meminfo.split('\n'):
                if line.startswith('MemTotal:'):
                    total_memory = line.split()[1] + ' ' + line.split()[2]
                    break
            
            self.metadata = {
                'timestamp': datetime.now().isoformat(),
                'hostname': os.uname().nodename,
                'kernel_version': kernel_version,
                'total_memory': total_memory,
                'architecture': os.uname().machine,
                'acquisition_tool': 'memory_acquire.py v1.0',
                'format': self.acquisition_format
            }
            
        except Exception as e:
            print(f"⚠️  Warning: Could not collect all system information: {e}")
    
    def acquire_memory_lime(self):
        """Acquire memory using LiME (Linux Memory Extractor)."""
        print("🔍 Starting LiME memory acquisition...")
        
        # Check if LiME module is loaded
        try:
            result = subprocess.run(['lsmod'], capture_output=True, text=True)
            if 'lime' not in result.stdout:
                print("📦 LiME module not loaded. Attempting to load...")
                
                # Try to load LiME module
                lime_paths = [
                    '/lib/modules/$(uname -r)/kernel/drivers/lime.ko',
                    '/usr/src/lime/lime.ko',
                    'tools/LiME/src/lime.ko'
                ]
                
                lime_loaded = False
                for path in lime_paths:
                    try:
                        subprocess.run(['insmod', path], check=True, capture_output=True)
                        print("✅ LiME module loaded successfully")
                        lime_loaded = True
                        break
                    except subprocess.CalledProcessError:
                        continue
                
                if not lime_loaded:
                    print("❌ Error: Could not load LiME module")
                    print("   Please install LiME or use alternative method")
                    return False
            
            # Create memory dump using LiME
            lime_command = [
                'dd',
                'if=/proc/lime',
                f'of={self.output_file}',
                'bs=1M'
            ]
            
            if not self.quick_mode:
                lime_command.extend(['conv=noerror,sync'])
            
            print(f"💾 Acquiring memory to: {self.output_file}")
            print("   This may take several minutes depending on RAM size...")
            
            start_time = time.time()
            
            with open(f"{self.output_file}.log", 'w') as log_file:
                process = subprocess.run(
                    lime_command,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True
                )
            
            end_time = time.time()
            
            if process.returncode == 0:
                duration = end_time - start_time
                file_size = os.path.getsize(self.output_file)
                print(f"✅ Memory acquisition completed in {duration:.2f} seconds")
                print(f"   File size: {file_size / 1024 / 1024:.2f} MB")
                
                self.metadata['acquisition_time'] = f"{duration:.2f} seconds"
                self.metadata['file_size'] = file_size
                return True
            else:
                print("❌ Error during memory acquisition")
                return False
                
        except Exception as e:
            print(f"❌ Error during LiME acquisition: {e}")
            return False
    
    def acquire_memory_dd(self):
        """Acquire memory using dd from /dev/mem or /proc/kcore."""
        print("🔍 Starting dd memory acquisition...")
        
        # Try different memory sources
        memory_sources = ['/proc/kcore', '/dev/mem']
        
        for source in memory_sources:
            if os.path.exists(source):
                print(f"📦 Using memory source: {source}")
                
                dd_command = [
                    'dd',
                    f'if={source}',
                    f'of={self.output_file}',
                    'bs=1M'
                ]
                
                if not self.quick_mode:
                    dd_command.extend(['conv=noerror,sync'])
                
                print(f"💾 Acquiring memory to: {self.output_file}")
                
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
                        print(f"✅ Memory acquisition completed in {duration:.2f} seconds")
                        print(f"   File size: {file_size / 1024 / 1024:.2f} MB")
                        
                        self.metadata['acquisition_time'] = f"{duration:.2f} seconds"
                        self.metadata['file_size'] = file_size
                        self.metadata['source'] = source
                        return True
                        
                except Exception as e:
                    print(f"⚠️  Failed with {source}: {e}")
                    continue
        
        print("❌ Error: Could not acquire memory from any source")
        return False
    
    def calculate_hash(self, algorithm='md5'):
        """Calculate hash of the acquired memory dump."""
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
    
    def save_metadata(self):
        """Save acquisition metadata to JSON file."""
        metadata_file = f"{self.output_file}.metadata.json"
        
        try:
            with open(metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
            print(f"📋 Metadata saved to: {metadata_file}")
            
        except Exception as e:
            print(f"⚠️  Warning: Could not save metadata: {e}")
    
    def verify_dump(self):
        """Basic verification of memory dump."""
        print("🔍 Verifying memory dump...")
        
        if not os.path.exists(self.output_file):
            print("❌ Error: Output file does not exist")
            return False
        
        file_size = os.path.getsize(self.output_file)
        if file_size == 0:
            print("❌ Error: Output file is empty")
            return False
        
        print(f"✅ Memory dump verified:")
        print(f"   File: {self.output_file}")
        print(f"   Size: {file_size / 1024 / 1024:.2f} MB")
        
        # Check if file looks like memory dump (basic heuristics)
        try:
            with open(self.output_file, 'rb') as f:
                header = f.read(1024)
                
            # Look for common memory patterns
            null_bytes = header.count(b'\x00')
            if null_bytes > 900:  # Too many null bytes might indicate problem
                print("⚠️  Warning: High number of null bytes detected")
            
        except Exception as e:
            print(f"⚠️  Warning: Could not analyze dump content: {e}")
        
        return True
    
    def acquire(self, output_file, format_type='lime', verify=False, 
                hash_algo='md5', quick=False):
        """Main acquisition method."""
        
        self.output_file = output_file
        self.acquisition_format = format_type
        self.verify_integrity = verify
        self.hash_algorithm = hash_algo
        self.quick_mode = quick
        
        print("🚀 Digital Forensics Memory Acquisition")
        print("=" * 50)
        
        # Preliminary checks
        if not self.check_privileges():
            return False
        
        if not self.check_dependencies():
            return False
        
        # Collect system information
        self.get_system_info()
        
        # Create output directory if needed
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Perform acquisition based on format
        success = False
        
        if format_type == 'lime':
            success = self.acquire_memory_lime()
        elif format_type in ['dd', 'raw']:
            success = self.acquire_memory_dd()
        else:
            print(f"❌ Error: Unsupported format '{format_type}'")
            return False
        
        if not success:
            print("❌ Memory acquisition failed")
            return False
        
        # Verify if requested
        if verify and not self.verify_dump():
            return False
        
        # Calculate hash if requested
        if hash_algo:
            self.calculate_hash(hash_algo)
        
        # Save metadata
        self.save_metadata()
        
        print("\n✅ Memory acquisition completed successfully!")
        print(f"   Output: {self.output_file}")
        
        return True


def main():
    """Main function with argument parsing."""
    
    parser = argparse.ArgumentParser(
        description='Digital Forensics Memory Acquisition Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic LiME acquisition
  sudo python3 memory_acquire.py --output evidence/memory.raw
  
  # Quick dd acquisition with verification
  sudo python3 memory_acquire.py --output memory.raw --format dd --quick --verify
  
  # Full acquisition with SHA256 hash
  sudo python3 memory_acquire.py --output memory.raw --hash sha256 --verify
        """
    )
    
    parser.add_argument(
        '--output', '-o',
        required=True,
        help='Output file path for memory dump'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['lime', 'dd', 'raw'],
        default='lime',
        help='Acquisition format (default: lime)'
    )
    
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Verify memory dump after acquisition'
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
        help='Quick acquisition mode (faster but less thorough)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Memory Acquisition Tool v1.0'
    )
    
    args = parser.parse_args()
    
    # Initialize acquisition tool
    memory_tool = MemoryAcquisition()
    
    # Perform acquisition
    success = memory_tool.acquire(
        output_file=args.output,
        format_type=args.format,
        verify=args.verify,
        hash_algo=args.hash,
        quick=args.quick
    )
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
