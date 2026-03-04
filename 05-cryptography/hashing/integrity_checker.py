#!/usr/bin/env python3

import os
import sys
import hashlib
import hmac
import json
import argparse
from datetime import datetime
from pathlib import Path
import concurrent.futures
from tqdm import tqdm

class IntegrityChecker:
    """
    File integrity verification using multiple hash algorithms
    """
    
    def __init__(self, algorithm='sha256'):
        """
        Initialize integrity checker
        
        Args:
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        """
        self.algorithm = algorithm
        self.hash_func = getattr(hashlib, algorithm)
        self.manifest = {}
        
    def calculate_hash(self, filepath, blocksize=65536):
        """
        Calculate hash of a file
        
        Args:
            filepath: Path to file
            blocksize: Read block size for large files
        
        Returns:
            Hexadecimal hash string
        """
        hash_obj = self.hash_func()
        
        try:
            with open(filepath, 'rb') as f:
                for block in iter(lambda: f.read(blocksize), b''):
                    hash_obj.update(block)
            return hash_obj.hexdigest()
        except (IOError, PermissionError) as e:
            print(f"[!] Error reading {filepath}: {e}")
            return None
    
    def calculate_hashes_bulk(self, filepaths, show_progress=True):
        """
        Calculate hashes for multiple files in parallel
        
        Args:
            filepaths: List of file paths
            show_progress: Show progress bar
        
        Returns:
            Dictionary mapping filepaths to hashes
        """
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_file = {
                executor.submit(self.calculate_hash, fp): fp 
                for fp in filepaths
            }
            
            iterator = concurrent.futures.as_completed(future_to_file)
            if show_progress:
                iterator = tqdm(iterator, total=len(filepaths), 
                               desc="Hashing files", unit="file")
            
            for future in iterator:
                filepath = future_to_file[future]
                try:
                    hash_value = future.result()
                    if hash_value:
                        results[filepath] = hash_value
                except Exception as e:
                    print(f"[!] Error processing {filepath}: {e}")
        
        return results
    
    def create_manifest(self, directory, recursive=True, exclude=None):
        """
        Create integrity manifest for directory
        
        Args:
            directory: Directory to scan
            recursive: Scan subdirectories
            exclude: List of patterns to exclude
        
        Returns:
            Dictionary with manifest data
        """
        directory = Path(directory)
        if not directory.exists():
            print(f"[!] Directory not found: {directory}")
            return None
        
        print(f"[*] Creating manifest for {directory}")
        
        # Collect files
        files = []
        if recursive:
            for root, dirs, filenames in os.walk(directory):
                for f in filenames:
                    filepath = Path(root) / f
                    if exclude and any(pattern in str(filepath) for pattern in exclude):
                        continue
                    files.append(str(filepath))
        else:
            files = [str(directory / f) for f in directory.iterdir() 
                    if f.is_file()]
        
        print(f"[*] Found {len(files)} files")
        
        # Calculate hashes
        hashes = self.calculate_hashes_bulk(files)
        
        # Create manifest
        manifest = {
            'created': datetime.now().isoformat(),
            'algorithm': self.algorithm,
            'files': hashes,
            'total_files': len(hashes),
            'directory': str(directory)
        }
        
        return manifest
    
    def save_manifest(self, manifest, filename):
        """Save manifest to JSON file"""
        with open(filename, 'w') as f:
            json.dump(manifest, f, indent=2)
        print(f"[✓] Manifest saved to {filename}")
    
    def load_manifest(self, filename):
        """Load manifest from JSON file"""
        with open(filename, 'r') as f:
            return json.load(f)
    
    def verify_manifest(self, manifest, check_missing=True, check_modified=True):
        """
        Verify files against manifest
        
        Args:
            manifest: Manifest dictionary
            check_missing: Check for missing files
            check_modified: Check for modified files
        
        Returns:
            Dictionary with verification results
        """
        results = {
            'verified': [],
            'missing': [],
            'modified': [],
            'new': []
        }
        
        print(f"[*] Verifying files against manifest...")
        print(f"    Algorithm: {manifest['algorithm']}")
        print(f"    Total files in manifest: {manifest['total_files']}")
        
        # Check existing files
        for filepath, expected_hash in tqdm(manifest['files'].items(), 
                                           desc="Verifying", unit="file"):
            if not os.path.exists(filepath):
                if check_missing:
                    results['missing'].append(filepath)
                continue
            
            current_hash = self.calculate_hash(filepath)
            if current_hash == expected_hash:
                results['verified'].append(filepath)
            else:
                if check_modified:
                    results['modified'].append(filepath)
        
        # Check for new files
        if check_missing:
            manifest_files = set(manifest['files'].keys())
            all_files = set()
            for root, dirs, files in os.walk(manifest['directory']):
                for f in files:
                    all_files.add(os.path.join(root, f))
            
            results['new'] = list(all_files - manifest_files)
        
        return results
    
    def verify_file(self, filepath, expected_hash):
        """Verify single file against expected hash"""
        print(f"[*] Verifying {filepath}")
        
        if not os.path.exists(filepath):
            print(f"[✗] File not found")
            return False
        
        current_hash = self.calculate_hash(filepath)
        if current_hash == expected_hash:
            print(f"[✓] Hash matches: {current_hash}")
            return True
        else:
            print(f"[✗] Hash mismatch")
            print(f"    Expected: {expected_hash}")
            print(f"    Actual:   {current_hash}")
            return False
    
    def find_duplicates(self, directory, recursive=True):
        """Find duplicate files by hash"""
        directory = Path(directory)
        if not directory.exists():
            print(f"[!] Directory not found: {directory}")
            return {}
        
        print(f"[*] Finding duplicates in {directory}")
        
        # Collect files
        files = []
        if recursive:
            for root, dirs, filenames in os.walk(directory):
                for f in filenames:
                    files.append(str(Path(root) / f))
        else:
            files = [str(directory / f) for f in directory.iterdir() 
                    if f.is_file()]
        
        # Calculate hashes
        hashes = self.calculate_hashes_bulk(files)
        
        # Group by hash
        hash_to_files = {}
        for filepath, hash_value in hashes.items():
            if hash_value not in hash_to_files:
                hash_to_files[hash_value] = []
            hash_to_files[hash_value].append(filepath)
        
        # Filter duplicates
        duplicates = {
            h: paths for h, paths in hash_to_files.items() 
            if len(paths) > 1
        }
        
        print(f"[*] Found {len(duplicates)} groups of duplicate files")
        return duplicates
    
    def generate_report(self, results):
        """Generate verification report"""
        report = []
        report.append("="*60)
        report.append("FILE INTEGRITY VERIFICATION REPORT")
        report.append("="*60)
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("")
        
        report.append(f"Verified files: {len(results['verified'])} ✓")
        report.append(f"Modified files: {len(results['modified'])} ⚠️")
        report.append(f"Missing files: {len(results['missing'])} ❌")
        report.append(f"New files: {len(results['new'])} ➕")
        report.append("")
        
        if results['modified']:
            report.append("MODIFIED FILES:")
            for f in results['modified'][:10]:
                report.append(f"  ⚠️ {f}")
            if len(results['modified']) > 10:
                report.append(f"  ... and {len(results['modified'])-10} more")
        
        if results['missing']:
            report.append("\nMISSING FILES:")
            for f in results['missing'][:10]:
                report.append(f"  ❌ {f}")
        
        if results['new']:
            report.append("\nNEW FILES:")
            for f in results['new'][:10]:
                report.append(f"  ➕ {f}")
        
        report.append("")
        report.append("="*60)
        
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description='File Integrity Checker')
    parser.add_argument('action', choices=['create', 'verify', 'check', 'duplicates'],
                       help='Action to perform')
    parser.add_argument('target', help='Target file or directory')
    parser.add_argument('-m', '--manifest', help='Manifest file')
    parser.add_argument('-a', '--algorithm', default='sha256',
                       choices=['md5', 'sha1', 'sha256', 'sha512'],
                       help='Hash algorithm')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Process recursively')
    
    args = parser.parse_args()
    
    checker = IntegrityChecker(args.algorithm)
    
    if args.action == 'create':
        manifest = checker.create_manifest(args.target, args.recursive)
        if manifest:
            output = args.output or f"manifest_{args.algorithm}.json"
            checker.save_manifest(manifest, output)
    
    elif args.action == 'verify':
        if not args.manifest:
            print("[!] Manifest file required for verification")
            return
        
        manifest = checker.load_manifest(args.manifest)
        
        if args.target:
            # Verify single file
            if args.target in manifest['files']:
                checker.verify_file(args.target, manifest['files'][args.target])
            else:
                print(f"[!] File not found in manifest: {args.target}")
        else:
            # Verify entire manifest
            results = checker.verify_manifest(manifest)
            report = checker.generate_report(results)
            print(report)
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
    
    elif args.action == 'check':
        # Check single file against provided hash
        expected = input("Enter expected hash: ").strip()
        checker.verify_file(args.target, expected)
    
    elif args.action == 'duplicates':
        duplicates = checker.find_duplicates(args.target, args.recursive)
        
        if duplicates:
            print(f"\nFound {len(duplicates)} groups of duplicate files:")
            for hash_val, files in duplicates.items():
                print(f"\nHash: {hash_val}")
                for f in files:
                    print(f"  📄 {f}")
        else:
            print("No duplicate files found")

if __name__ == "__main__":
    main()
