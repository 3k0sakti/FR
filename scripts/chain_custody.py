#!/usr/bin/env python3
"""
Digital Forensics Chain of Custody Tool
=======================================

A tool for generating and maintaining chain of custody documentation
for digital forensic evidence.

Usage:
    python3 chain_custody.py --case CASE-2024-001 --investigator "John Doe" --evidence evidence/
    python3 chain_custody.py --add-entry --case CASE-2024-001 --action "Analysis started"

Author: Digital Forensics Lab
License: MIT
"""

import os
import sys
import argparse
import json
import hashlib
from datetime import datetime
from pathlib import Path


class ChainOfCustody:
    """Class for managing chain of custody documentation."""
    
    def __init__(self):
        self.custody_data = {
            'case_info': {},
            'evidence_items': [],
            'custody_log': []
        }
    
    def initialize_case(self, case_id, investigator, evidence_path, description=None):
        """Initialize a new chain of custody for a case."""
        self.custody_data['case_info'] = {
            'case_id': case_id,
            'primary_investigator': investigator,
            'created_date': datetime.now().isoformat(),
            'evidence_location': evidence_path,
            'description': description or f"Digital forensic investigation for case {case_id}"
        }
        
        # Add initial custody entry
        self.add_custody_entry(
            action="Case initialized",
            person=investigator,
            details=f"Chain of custody created for case {case_id}"
        )
        
        # Scan evidence directory
        if os.path.exists(evidence_path):
            self.scan_evidence_directory(evidence_path)
    
    def scan_evidence_directory(self, evidence_path):
        """Scan evidence directory and catalog all files."""
        print(f"📁 Scanning evidence directory: {evidence_path}")
        
        evidence_files = []
        
        # Walk through all files in evidence directory
        for root, dirs, files in os.walk(evidence_path):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, evidence_path)
                
                # Skip hidden files and metadata files we create
                if file.startswith('.') or file.endswith('.metadata.json') or file.endswith('.custody.json'):
                    continue
                
                try:
                    file_stat = os.stat(file_path)
                    file_size = file_stat.st_size
                    file_mtime = datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                    
                    # Calculate MD5 hash
                    file_hash = self.calculate_file_hash(file_path)
                    
                    evidence_item = {
                        'item_id': len(evidence_files) + 1,
                        'filename': file,
                        'relative_path': relative_path,
                        'full_path': file_path,
                        'file_size': file_size,
                        'file_size_mb': round(file_size / (1024 * 1024), 2),
                        'last_modified': file_mtime,
                        'md5_hash': file_hash,
                        'acquisition_date': datetime.now().isoformat(),
                        'status': 'acquired'
                    }
                    
                    evidence_files.append(evidence_item)
                    
                except Exception as e:
                    print(f"⚠️  Warning: Could not process {file_path}: {e}")
        
        self.custody_data['evidence_items'] = evidence_files
        print(f"✅ Cataloged {len(evidence_files)} evidence items")
    
    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of a file."""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return "HASH_ERROR"
    
    def add_custody_entry(self, action, person, details=None):
        """Add an entry to the custody log."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'person': person,
            'details': details or "",
            'entry_id': len(self.custody_data['custody_log']) + 1
        }
        
        self.custody_data['custody_log'].append(entry)
        print(f"📝 Custody log entry added: {action} by {person}")
    
    def add_evidence_item(self, filename, file_path, description=None):
        """Add a new evidence item to the chain of custody."""
        if not os.path.exists(file_path):
            print(f"❌ Error: File does not exist: {file_path}")
            return False
        
        try:
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            file_mtime = datetime.fromtimestamp(file_stat.st_mtime).isoformat()
            file_hash = self.calculate_file_hash(file_path)
            
            evidence_item = {
                'item_id': len(self.custody_data['evidence_items']) + 1,
                'filename': filename,
                'full_path': file_path,
                'file_size': file_size,
                'file_size_mb': round(file_size / (1024 * 1024), 2),
                'last_modified': file_mtime,
                'md5_hash': file_hash,
                'acquisition_date': datetime.now().isoformat(),
                'description': description or "",
                'status': 'acquired'
            }
            
            self.custody_data['evidence_items'].append(evidence_item)
            print(f"✅ Evidence item added: {filename}")
            return True
            
        except Exception as e:
            print(f"❌ Error adding evidence item: {e}")
            return False
    
    def verify_evidence_integrity(self):
        """Verify integrity of all evidence items."""
        print("🔍 Verifying evidence integrity...")
        
        integrity_issues = []
        
        for item in self.custody_data['evidence_items']:
            file_path = item['full_path']
            original_hash = item['md5_hash']
            
            if not os.path.exists(file_path):
                issue = f"File missing: {file_path}"
                integrity_issues.append(issue)
                item['status'] = 'missing'
                continue
            
            # Recalculate hash
            current_hash = self.calculate_file_hash(file_path)
            
            if current_hash != original_hash:
                issue = f"Hash mismatch for {file_path}: expected {original_hash}, got {current_hash}"
                integrity_issues.append(issue)
                item['status'] = 'modified'
            else:
                item['status'] = 'verified'
        
        if integrity_issues:
            print(f"❌ Found {len(integrity_issues)} integrity issues:")
            for issue in integrity_issues:
                print(f"   - {issue}")
            return False
        else:
            print(f"✅ All {len(self.custody_data['evidence_items'])} evidence items verified")
            return True
    
    def generate_custody_report(self, output_file=None):
        """Generate a human-readable custody report."""
        case_info = self.custody_data['case_info']
        evidence_items = self.custody_data['evidence_items']
        custody_log = self.custody_data['custody_log']
        
        report_lines = []
        report_lines.append("DIGITAL EVIDENCE CHAIN OF CUSTODY REPORT")
        report_lines.append("=" * 50)
        report_lines.append("")
        
        # Case Information
        report_lines.append("CASE INFORMATION:")
        report_lines.append(f"Case ID: {case_info.get('case_id', 'N/A')}")
        report_lines.append(f"Primary Investigator: {case_info.get('primary_investigator', 'N/A')}")
        report_lines.append(f"Created Date: {case_info.get('created_date', 'N/A')}")
        report_lines.append(f"Evidence Location: {case_info.get('evidence_location', 'N/A')}")
        report_lines.append(f"Description: {case_info.get('description', 'N/A')}")
        report_lines.append("")
        
        # Evidence Items
        report_lines.append("EVIDENCE ITEMS:")
        report_lines.append("-" * 30)
        
        for item in evidence_items:
            report_lines.append(f"Item #{item['item_id']}: {item['filename']}")
            report_lines.append(f"  Path: {item.get('relative_path', item['full_path'])}")
            report_lines.append(f"  Size: {item['file_size_mb']} MB")
            report_lines.append(f"  MD5 Hash: {item['md5_hash']}")
            report_lines.append(f"  Acquired: {item['acquisition_date']}")
            report_lines.append(f"  Status: {item.get('status', 'unknown')}")
            if item.get('description'):
                report_lines.append(f"  Description: {item['description']}")
            report_lines.append("")
        
        # Custody Log
        report_lines.append("CUSTODY LOG:")
        report_lines.append("-" * 20)
        
        for entry in custody_log:
            report_lines.append(f"[{entry['timestamp']}] {entry['action']}")
            report_lines.append(f"  Person: {entry['person']}")
            if entry['details']:
                report_lines.append(f"  Details: {entry['details']}")
            report_lines.append("")
        
        # Summary
        report_lines.append("SUMMARY:")
        report_lines.append("-" * 15)
        report_lines.append(f"Total Evidence Items: {len(evidence_items)}")
        report_lines.append(f"Total Custody Entries: {len(custody_log)}")
        
        verified_items = len([item for item in evidence_items if item.get('status') == 'verified'])
        missing_items = len([item for item in evidence_items if item.get('status') == 'missing'])
        modified_items = len([item for item in evidence_items if item.get('status') == 'modified'])
        
        report_lines.append(f"Verified Items: {verified_items}")
        if missing_items > 0:
            report_lines.append(f"Missing Items: {missing_items}")
        if modified_items > 0:
            report_lines.append(f"Modified Items: {modified_items}")
        
        report_lines.append("")
        report_lines.append(f"Report Generated: {datetime.now().isoformat()}")
        
        report_text = "\n".join(report_lines)
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report_text)
                print(f"📊 Custody report saved to: {output_file}")
            except Exception as e:
                print(f"❌ Error saving report: {e}")
        
        return report_text
    
    def save_custody_file(self, output_file):
        """Save chain of custody data to JSON file."""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.custody_data, f, indent=2)
            print(f"💾 Chain of custody saved to: {output_file}")
            return True
        except Exception as e:
            print(f"❌ Error saving custody file: {e}")
            return False
    
    def load_custody_file(self, input_file):
        """Load chain of custody data from JSON file."""
        try:
            with open(input_file, 'r') as f:
                self.custody_data = json.load(f)
            print(f"📂 Chain of custody loaded from: {input_file}")
            return True
        except Exception as e:
            print(f"❌ Error loading custody file: {e}")
            return False


def main():
    """Main function with argument parsing."""
    
    parser = argparse.ArgumentParser(
        description='Digital Forensics Chain of Custody Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create new chain of custody
  python3 chain_custody.py --case CASE-2024-001 --investigator "John Doe" --evidence evidence/
  
  # Add custody entry to existing case
  python3 chain_custody.py --load-case CASE-2024-001.custody.json --add-entry --action "Analysis started" --person "Jane Smith"
  
  # Verify evidence integrity
  python3 chain_custody.py --load-case CASE-2024-001.custody.json --verify
        """
    )
    
    parser.add_argument(
        '--case',
        help='Case ID for new chain of custody'
    )
    
    parser.add_argument(
        '--investigator',
        help='Primary investigator name'
    )
    
    parser.add_argument(
        '--evidence',
        help='Evidence directory path'
    )
    
    parser.add_argument(
        '--description',
        help='Case description'
    )
    
    parser.add_argument(
        '--load-case',
        help='Load existing custody file'
    )
    
    parser.add_argument(
        '--add-entry',
        action='store_true',
        help='Add new custody log entry'
    )
    
    parser.add_argument(
        '--action',
        help='Action description for custody entry'
    )
    
    parser.add_argument(
        '--person',
        help='Person responsible for action'
    )
    
    parser.add_argument(
        '--details',
        help='Additional details for custody entry'
    )
    
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Verify evidence integrity'
    )
    
    parser.add_argument(
        '--report',
        help='Generate custody report to file'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Chain of Custody Tool v1.0'
    )
    
    args = parser.parse_args()
    
    # Initialize chain of custody tool
    custody = ChainOfCustody()
    
    # Load existing case if specified
    if args.load_case:
        if not custody.load_custody_file(args.load_case):
            sys.exit(1)
    
    # Create new case
    elif args.case and args.investigator and args.evidence:
        print("🚀 Digital Forensics Chain of Custody")
        print("=" * 50)
        
        custody.initialize_case(
            case_id=args.case,
            investigator=args.investigator,
            evidence_path=args.evidence,
            description=args.description
        )
        
        # Save custody file
        custody_filename = f"{args.case}.custody.json"
        custody.save_custody_file(custody_filename)
    
    # Add custody entry
    if args.add_entry:
        if not args.action or not args.person:
            parser.error("--action and --person are required when using --add-entry")
        
        custody.add_custody_entry(
            action=args.action,
            person=args.person,
            details=args.details
        )
        
        # Save updated custody file
        if args.load_case:
            custody.save_custody_file(args.load_case)
    
    # Verify evidence integrity
    if args.verify:
        custody.verify_evidence_integrity()
        
        # Save updated custody file
        if args.load_case:
            custody.save_custody_file(args.load_case)
    
    # Generate report
    if args.report:
        custody.generate_custody_report(args.report)
    elif custody.custody_data['case_info']:
        # Always show summary
        print("\n" + custody.generate_custody_report())


if __name__ == '__main__':
    main()
