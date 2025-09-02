#!/usr/bin/env python3
"""
Digital Forensics Acquisition Verification Tool
==============================================

A tool for verifying the integrity and authenticity of acquired forensic data.
Supports hash verification, file integrity checks, and metadata validation.

Usage:
    python3 verify_acquisition.py --case evidence/CASE-2024-001/
    python3 verify_acquisition.py --file evidence/disk.dd --hash md5
    python3 verify_acquisition.py --verify-all evidence/

Author: Digital Forensics Lab
License: MIT
"""

import os
import sys
import argparse
import hashlib
import json
import glob
from datetime import datetime
from pathlib import Path


class AcquisitionVerifier:
    """Class for verifying forensic acquisitions."""
    
    def __init__(self):
        self.supported_hash_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        self.verification_results = []
        
    def calculate_file_hash(self, file_path, algorithm='md5'):
        """Calculate hash of a file."""
        try:
            hash_func = getattr(hashlib, algorithm.lower())()
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            
            return hash_func.hexdigest()
            
        except Exception as e:
            print(f"❌ Error calculating {algorithm} hash for {file_path}: {e}")
            return None
    
    def verify_hash_file(self, file_path, hash_algorithm):
        """Verify file against its hash file."""
        hash_file = f"{file_path}.{hash_algorithm}"
        
        if not os.path.exists(hash_file):
            return False, f"Hash file {hash_file} not found"
        
        try:
            # Read expected hash from file
            with open(hash_file, 'r') as f:
                expected_hash = f.read().strip().split()[0]
            
            # Calculate actual hash
            actual_hash = self.calculate_file_hash(file_path, hash_algorithm)
            
            if actual_hash is None:
                return False, "Could not calculate hash"
            
            if actual_hash.lower() == expected_hash.lower():
                return True, "Hash verification passed"
            else:
                return False, f"Hash mismatch: expected {expected_hash}, got {actual_hash}"
                
        except Exception as e:
            return False, f"Error reading hash file: {e}"
    
    def verify_metadata(self, file_path):
        """Verify metadata file for acquisition."""
        metadata_file = f"{file_path}.metadata.json"
        
        if not os.path.exists(metadata_file):
            return False, "Metadata file not found"
        
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Check required fields
            required_fields = ['timestamp', 'file_size', 'acquisition_tool']
            missing_fields = [field for field in required_fields if field not in metadata]
            
            if missing_fields:
                return False, f"Missing metadata fields: {missing_fields}"
            
            # Verify file size
            actual_size = os.path.getsize(file_path)
            expected_size = metadata.get('file_size', 0)
            
            if actual_size != expected_size:
                return False, f"File size mismatch: expected {expected_size}, got {actual_size}"
            
            return True, "Metadata verification passed"
            
        except Exception as e:
            return False, f"Error reading metadata: {e}"
    
    def verify_single_file(self, file_path, hash_algorithm=None):
        """Verify a single acquisition file."""
        print(f"🔍 Verifying: {file_path}")
        
        if not os.path.exists(file_path):
            result = {
                'file': file_path,
                'status': 'FAILED',
                'error': 'File does not exist'
            }
            self.verification_results.append(result)
            print(f"❌ File does not exist")
            return False
        
        result = {
            'file': file_path,
            'status': 'PASSED',
            'checks': {}
        }
        
        overall_status = True
        
        # File existence check
        print(f"✅ File exists: {os.path.getsize(file_path) / 1024 / 1024:.2f} MB")
        
        # Hash verification
        if hash_algorithm:
            hash_valid, hash_message = self.verify_hash_file(file_path, hash_algorithm)
            result['checks']['hash'] = {
                'algorithm': hash_algorithm,
                'status': 'PASSED' if hash_valid else 'FAILED',
                'message': hash_message
            }
            
            if hash_valid:
                print(f"✅ {hash_algorithm.upper()} hash verification: PASSED")
            else:
                print(f"❌ {hash_algorithm.upper()} hash verification: FAILED - {hash_message}")
                overall_status = False
        else:
            # Try to find any hash files
            hash_found = False
            for algo in self.supported_hash_algorithms:
                hash_file = f"{file_path}.{algo}"
                if os.path.exists(hash_file):
                    hash_valid, hash_message = self.verify_hash_file(file_path, algo)
                    result['checks']['hash'] = {
                        'algorithm': algo,
                        'status': 'PASSED' if hash_valid else 'FAILED',
                        'message': hash_message
                    }
                    
                    if hash_valid:
                        print(f"✅ {algo.upper()} hash verification: PASSED")
                    else:
                        print(f"❌ {algo.upper()} hash verification: FAILED - {hash_message}")
                        overall_status = False
                    
                    hash_found = True
                    break
            
            if not hash_found:
                print("⚠️  No hash files found for verification")
                result['checks']['hash'] = {
                    'status': 'SKIPPED',
                    'message': 'No hash files found'
                }
        
        # Metadata verification
        metadata_valid, metadata_message = self.verify_metadata(file_path)
        result['checks']['metadata'] = {
            'status': 'PASSED' if metadata_valid else 'FAILED',
            'message': metadata_message
        }
        
        if metadata_valid:
            print(f"✅ Metadata verification: PASSED")
        else:
            print(f"❌ Metadata verification: FAILED - {metadata_message}")
            if "not found" not in metadata_message.lower():  # Don't fail if metadata file just doesn't exist
                overall_status = False
        
        # Check for log files
        log_file = f"{file_path}.log"
        if os.path.exists(log_file):
            print(f"✅ Acquisition log available: {log_file}")
            result['checks']['log'] = {
                'status': 'FOUND',
                'file': log_file
            }
        else:
            print("⚠️  No acquisition log found")
            result['checks']['log'] = {
                'status': 'NOT_FOUND'
            }
        
        result['status'] = 'PASSED' if overall_status else 'FAILED'
        self.verification_results.append(result)
        
        return overall_status
    
    def verify_case_directory(self, case_path):
        """Verify all acquisition files in a case directory."""
        print(f"🔍 Verifying case directory: {case_path}")
        
        if not os.path.exists(case_path):
            print(f"❌ Case directory does not exist: {case_path}")
            return False
        
        # Find all potential acquisition files
        acquisition_files = []
        
        # Common acquisition file extensions
        patterns = ['*.dd', '*.raw', '*.E01', '*.pcap', '*.pcapng', '*.mem', '*.dmp']
        
        for pattern in patterns:
            files = glob.glob(os.path.join(case_path, pattern))
            acquisition_files.extend(files)
            
            # Also check subdirectories
            subdir_files = glob.glob(os.path.join(case_path, '**', pattern), recursive=True)
            acquisition_files.extend(subdir_files)
        
        if not acquisition_files:
            print("⚠️  No acquisition files found in case directory")
            return True
        
        print(f"📁 Found {len(acquisition_files)} acquisition files to verify")
        
        overall_success = True
        
        for file_path in acquisition_files:
            print(f"\n{'='*60}")
            success = self.verify_single_file(file_path)
            if not success:
                overall_success = False
        
        return overall_success
    
    def generate_verification_report(self, output_file=None):
        """Generate a verification report."""
        if not self.verification_results:
            print("⚠️  No verification results to report")
            return
        
        report = {
            'verification_report': {
                'timestamp': datetime.now().isoformat(),
                'total_files': len(self.verification_results),
                'passed': len([r for r in self.verification_results if r['status'] == 'PASSED']),
                'failed': len([r for r in self.verification_results if r['status'] == 'FAILED']),
                'results': self.verification_results
            }
        }
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"📊 Verification report saved to: {output_file}")
            except Exception as e:
                print(f"❌ Error saving report: {e}")
        
        # Print summary
        print(f"\n📊 Verification Summary:")
        print(f"   Total files: {report['verification_report']['total_files']}")
        print(f"   Passed: {report['verification_report']['passed']}")
        print(f"   Failed: {report['verification_report']['failed']}")
        
        if report['verification_report']['failed'] > 0:
            print(f"\n❌ Failed verifications:")
            for result in self.verification_results:
                if result['status'] == 'FAILED':
                    print(f"   - {result['file']}")
                    if 'error' in result:
                        print(f"     Error: {result['error']}")
                    else:
                        for check_name, check_result in result.get('checks', {}).items():
                            if check_result['status'] == 'FAILED':
                                print(f"     {check_name}: {check_result['message']}")
    
    def verify(self, target_path, hash_algorithm=None, generate_report=False):
        """Main verification method."""
        print("🚀 Digital Forensics Acquisition Verification")
        print("=" * 50)
        
        success = False
        
        if os.path.isfile(target_path):
            # Verify single file
            success = self.verify_single_file(target_path, hash_algorithm)
        elif os.path.isdir(target_path):
            # Verify case directory
            success = self.verify_case_directory(target_path)
        else:
            print(f"❌ Error: {target_path} is not a valid file or directory")
            return False
        
        # Generate report if requested
        if generate_report:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"verification_report_{timestamp}.json"
            self.generate_verification_report(report_file)
        else:
            self.generate_verification_report()
        
        if success:
            print(f"\n✅ All verifications passed!")
        else:
            print(f"\n❌ Some verifications failed!")
        
        return success


def main():
    """Main function with argument parsing."""
    
    parser = argparse.ArgumentParser(
        description='Digital Forensics Acquisition Verification Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify single file with MD5
  python3 verify_acquisition.py --file evidence/disk.dd --hash md5
  
  # Verify entire case directory
  python3 verify_acquisition.py --case evidence/CASE-2024-001/
  
  # Verify with report generation
  python3 verify_acquisition.py --case evidence/ --report
        """
    )
    
    parser.add_argument(
        '--file', '-f',
        help='Single file to verify'
    )
    
    parser.add_argument(
        '--case', '-c',
        help='Case directory to verify'
    )
    
    parser.add_argument(
        '--hash',
        choices=['md5', 'sha1', 'sha256', 'sha512'],
        help='Hash algorithm to use for verification'
    )
    
    parser.add_argument(
        '--report', '-r',
        action='store_true',
        help='Generate detailed verification report'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Acquisition Verification Tool v1.0'
    )
    
    args = parser.parse_args()
    
    # Determine target path
    if args.file:
        target_path = args.file
    elif args.case:
        target_path = args.case
    else:
        parser.error("Either --file or --case must be specified")
    
    # Initialize verification tool
    verifier = AcquisitionVerifier()
    
    # Perform verification
    success = verifier.verify(
        target_path=target_path,
        hash_algorithm=args.hash,
        generate_report=args.report
    )
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
