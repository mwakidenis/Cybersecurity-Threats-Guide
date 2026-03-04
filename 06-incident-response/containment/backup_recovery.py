#!/usr/bin/env python3

import os
import sys
import hashlib
import json
import argparse
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import tarfile
import zipfile
import platform

class BackupRecovery:
    """
    Backup and recovery management for incident response
    """
    
    def __init__(self, backup_root='/backups', incident_id=None):
        """
        Initialize backup recovery
        
        Args:
            backup_root: Root directory containing backups
            incident_id: Incident identifier
        """
        self.backup_root = Path(backup_root)
        self.incident_id = incident_id or f"RECOVERY-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.system = platform.system()
        self.log_file = f"recovery_{self.incident_id}.log"
        
        # Create recovery directory
        self.recovery_dir = Path(f"recovery_{self.incident_id}")
        self.recovery_dir.mkdir(exist_ok=True)
        
        print(f"[*] Backup root: {self.backup_root}")
        print(f"[*] Recovery ID: {self.incident_id}")
        print(f"[*] Recovery directory: {self.recovery_dir}")
    
    def list_backups(self, backup_type='all'):
        """
        List available backups
        
        Args:
            backup_type: Type of backup (system, files, database, all)
        """
        print(f"\n{'='*60}")
        print("📋 AVAILABLE BACKUPS")
        print(f"{'='*60}")
        
        if not self.backup_root.exists():
            print(f"[!] Backup directory not found: {self.backup_root}")
            return []
        
        backups = []
        
        # Walk through backup directory
        for backup_dir in self.backup_root.iterdir():
            if backup_dir.is_dir():
                backup_info = self.get_backup_info(backup_dir)
                if backup_info:
                    backups.append(backup_info)
        
        # Sort by date (newest first)
        backups.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Display backups
        if not backups:
            print("  No backups found")
            return []
        
        print(f"\nFound {len(backups)} backup(s):\n")
        
        for i, backup in enumerate(backups, 1):
            print(f"{i}. {backup['name']}")
            print(f"   Type: {backup['type']}")
            print(f"   Date: {backup['timestamp']}")
            print(f"   Size: {self.format_size(backup['size'])}")
            print(f"   Files: {backup.get('file_count', 'N/A')}")
            if backup.get('verified'):
                print(f"   Status: ✓ Verified")
            print()
        
        return backups
    
    def get_backup_info(self, backup_dir):
        """Get information about a backup"""
        info_file = backup_dir / 'backup_info.json'
        
        if info_file.exists():
            with open(info_file, 'r') as f:
                info = json.load(f)
                info['name'] = backup_dir.name
                info['path'] = str(backup_dir)
                return info
        else:
            # Create basic info from directory
            total_size = sum(f.stat().st_size for f in backup_dir.glob('**/*') if f.is_file())
            file_count = sum(1 for _ in backup_dir.glob('**/*') if _.is_file())
            
            return {
                'name': backup_dir.name,
                'path': str(backup_dir),
                'type': 'unknown',
                'timestamp': datetime.fromtimestamp(backup_dir.stat().st_mtime).isoformat(),
                'size': total_size,
                'file_count': file_count,
                'verified': False
            }
    
    def verify_backup(self, backup_path):
        """Verify backup integrity"""
        print(f"\n{'='*60}")
        print(f"🔍 VERIFYING BACKUP: {backup_path}")
        print(f"{'='*60}")
        
        backup_path = Path(backup_path)
        
        if not backup_path.exists():
            print(f"[!] Backup not found: {backup_path}")
            return False
        
        verified = 0
        failed = 0
        missing = 0
        
        # Check if it's a compressed archive
        if backup_path.suffix in ['.tar', '.gz', '.bz2', '.zip']:
            print("[*] Verifying archive integrity...")
            
            if backup_path.suffix == '.zip':
                with zipfile.ZipFile(backup_path, 'r') as zf:
                    bad_file = zf.testzip()
                    if bad_file:
                        print(f"[✗] Archive corrupted: {bad_file}")
                        return False
                    else:
                        print("[✓] Archive integrity OK")
            
            elif backup_path.suffix in ['.tar', '.gz', '.bz2']:
                # Use tar to test
                result = subprocess.run(['tar', '-tf', backup_path], 
                                       capture_output=True)
                if result.returncode == 0:
                    print("[✓] Archive integrity OK")
                else:
                    print("[✗] Archive corrupted")
                    return False
        
        # Check if it's a directory with backup_info.json
        elif backup_path.is_dir():
            info_file = backup_path / 'backup_info.json'
            if info_file.exists():
                with open(info_file, 'r') as f:
                    info = json.load(f)
                
                if 'files' in info:
                    print(f"[*] Verifying {len(info['files'])} files...")
                    
                    for file_info in info['files']:
                        file_path = backup_path / file_info['path']
                        
                        if file_path.exists():
                            # Verify hash
                            current_hash = self.calculate_hash(file_path)
                            if current_hash == file_info['hash']:
                                verified += 1
                            else:
                                failed += 1
                                print(f"  [✗] Hash mismatch: {file_info['path']}")
                        else:
                            missing += 1
                            print(f"  [✗] Missing: {file_info['path']}")
        
        # Summary
        print(f"\nVerification Summary:")
        print(f"  ✓ Verified: {verified}")
        print(f"  ✗ Failed: {failed}")
        print(f"  ❌ Missing: {missing}")
        
        return failed == 0 and missing == 0
    
    def calculate_hash(self, filepath):
        """Calculate SHA-256 hash of file"""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return None
    
    def restore_backup(self, backup_path, restore_path=None, files=None):
        """
        Restore from backup
        
        Args:
            backup_path: Path to backup
            restore_path: Destination for restoration
            files: Specific files to restore (None = all)
        """
        print(f"\n{'='*60}")
        print(f"🔄 RESTORING BACKUP: {backup_path}")
        print(f"{'='*60}")
        
        backup_path = Path(backup_path)
        
        if not restore_path:
            restore_path = Path.cwd() / 'restored' / backup_path.name
        
        restore_path = Path(restore_path)
        restore_path.mkdir(parents=True, exist_ok=True)
        
        print(f"[*] Restoring to: {restore_path}")
        
        # Verify backup first
        if not self.verify_backup(backup_path):
            response = input("\n[?] Verification failed. Continue anyway? (yes/no): ")
            if response.lower() != 'yes':
                print("[!] Restore aborted")
                return False
        
        # Perform restoration based on type
        if backup_path.is_file() and backup_path.suffix == '.zip':
            with zipfile.ZipFile(backup_path, 'r') as zf:
                if files:
                    for file in files:
                        zf.extract(file, restore_path)
                        print(f"  ✓ Restored: {file}")
                else:
                    zf.extractall(restore_path)
                    print(f"  ✓ Extracted {len(zf.namelist())} files")
        
        elif backup_path.is_file() and backup_path.suffix in ['.tar', '.gz', '.bz2']:
            mode = 'r'
            if backup_path.suffix == '.gz':
                mode = 'r:gz'
            elif backup_path.suffix == '.bz2':
                mode = 'r:bz2'
            
            with tarfile.open(backup_path, mode) as tar:
                if files:
                    for file in files:
                        tar.extract(file, restore_path)
                        print(f"  ✓ Restored: {file}")
                else:
                    tar.extractall(restore_path)
                    print(f"  ✓ Extracted {len(tar.getmembers())} files")
        
        elif backup_path.is_dir():
            # Directory backup
            if files:
                for file in files:
                    src = backup_path / file
                    dst = restore_path / file
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    if src.is_file():
                        shutil.copy2(src, dst)
                        print(f"  ✓ Restored: {file}")
            else:
                # Copy entire directory
                shutil.copytree(backup_path, restore_path, dirs_exist_ok=True)
                print(f"  ✓ Restored complete directory")
        
        # Log restoration
        self.log_restore(backup_path, restore_path, files)
        
        print(f"\n[✓] Restore complete to: {restore_path}")
        return True
    
    def create_emergency_backup(self, paths, backup_name=None):
        """
        Create emergency backup of critical files
        
        Args:
            paths: List of paths to backup
            backup_name: Name for backup
        """
        print(f"\n{'='*60}")
        print("🆘 CREATING EMERGENCY BACKUP")
        print(f"{'='*60}")
        
        if not backup_name:
            backup_name = f"emergency_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        backup_dir = self.backup_root / backup_name
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        file_list = []
        
        for path in paths:
            src_path = Path(path)
            if src_path.exists():
                dest_path = backup_dir / src_path.name
                
                print(f"[*] Backing up: {src_path}")
                
                if src_path.is_dir():
                    shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
                    
                    # Calculate hashes for all files
                    for root, dirs, files in os.walk(dest_path):
                        for file in files:
                            file_path = Path(root) / file
                            rel_path = file_path.relative_to(backup_dir)
                            file_hash = self.calculate_hash(file_path)
                            
                            file_list.append({
                                'path': str(rel_path),
                                'size': file_path.stat().st_size,
                                'hash': file_hash
                            })
                else:
                    shutil.copy2(src_path, dest_path)
                    file_hash = self.calculate_hash(dest_path)
                    file_list.append({
                        'path': src_path.name,
                        'size': dest_path.stat().st_size,
                        'hash': file_hash
                    })
        
        # Save backup info
        info = {
            'name': backup_name,
            'type': 'emergency',
            'timestamp': datetime.now().isoformat(),
            'paths': paths,
            'file_count': len(file_list),
            'total_size': sum(f['size'] for f in file_list),
            'files': file_list,
            'system': platform.platform(),
            'incident_id': self.incident_id
        }
        
        with open(backup_dir / 'backup_info.json', 'w') as f:
            json.dump(info, f, indent=2)
        
        print(f"\n[✓] Emergency backup created: {backup_dir}")
        print(f"    Files backed up: {len(file_list)}")
        print(f"    Total size: {self.format_size(info['total_size'])}")
        
        return backup_dir
    
    def compare_with_backup(self, backup_path, current_path=None):
        """
        Compare current system state with backup
        
        Args:
            backup_path: Path to backup
            current_path: Current path to compare (default: original locations)
        """
        print(f"\n{'='*60}")
        print(f"🔍 COMPARING WITH BACKUP: {backup_path}")
        print(f"{'='*60}")
        
        backup_path = Path(backup_path)
        
        if not backup_path.exists():
            print(f"[!] Backup not found: {backup_path}")
            return None
        
        # Load backup info
        info_file = backup_path / 'backup_info.json'
        if info_file.exists():
            with open(info_file, 'r') as f:
                backup_info = json.load(f)
        else:
            print("[!] No backup info file found")
            return None
        
        differences = {
            'missing_in_current': [],
            'modified': [],
            'new': []
        }
        
        # Check files from backup
        for file_info in backup_info.get('files', []):
            backup_file = backup_path / file_info['path']
            
            if current_path:
                current_file = current_path / file_info['path']
            else:
                # Assume original location from backup paths
                current_file = Path(file_info['path'])
            
            if not current_file.exists():
                differences['missing_in_current'].append(str(file_info['path']))
            else:
                current_hash = self.calculate_hash(current_file)
                if current_hash != file_info['hash']:
                    differences['modified'].append(str(file_info['path']))
        
        # Check for new files in current location
        if current_path and current_path.exists():
            for root, dirs, files in os.walk(current_path):
                for file in files:
                    current_file = Path(root) / file
                    rel_path = current_file.relative_to(current_path)
                    
                    # Check if file exists in backup
                    backup_file = backup_path / rel_path
                    if not backup_file.exists():
                        differences['new'].append(str(rel_path))
        
        # Display results
        print(f"\nComparison Results:")
        print(f"  Files in backup: {len(backup_info.get('files', []))}")
        print(f"  Missing in current: {len(differences['missing_in_current'])}")
        print(f"  Modified: {len(differences['modified'])}")
        print(f"  New files: {len(differences['new'])}")
        
        if differences['missing_in_current']:
            print("\n❌ Missing in current:")
            for f in differences['missing_in_current'][:10]:
                print(f"  • {f}")
        
        if differences['modified']:
            print("\n⚠️ Modified:")
            for f in differences['modified'][:10]:
                print(f"  • {f}")
        
        if differences['new']:
            print("\n➕ New files:")
            for f in differences['new'][:10]:
                print(f"  • {f}")
        
        return differences
    
    def log_restore(self, backup_path, restore_path, files):
        """Log restore operation"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'incident_id': self.incident_id,
            'backup': str(backup_path),
            'restore_path': str(restore_path),
            'files_restored': files if files else 'all',
            'system': platform.platform()
        }
        
        log_file = self.recovery_dir / 'restore_log.json'
        
        if log_file.exists():
            with open(log_file, 'r') as f:
                logs = json.load(f)
        else:
            logs = []
        
        logs.append(log_entry)
        
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)
        
        print(f"[✓] Restore logged to {log_file}")
    
    def format_size(self, size):
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def generate_report(self):
        """Generate recovery report"""
        report = []
        report.append("="*80)
        report.append("BACKUP & RECOVERY REPORT")
        report.append("="*80)
        report.append(f"Recovery ID: {self.incident_id}")
        report.append(f"Timestamp: {datetime.now().isoformat()}")
        report.append(f"System: {platform.system()} {platform.release()}")
        report.append(f"Backup Root: {self.backup_root}")
        report.append("="*80)
        
        # List available backups
        report.append("\n📋 AVAILABLE BACKUPS")
        report.append("-"*40)
        backups = self.list_backups()
        for backup in backups[:10]:
            report.append(f"  • {backup['name']} - {backup['timestamp']}")
        
        # Recovery log
        log_file = self.recovery_dir / 'restore_log.json'
        if log_file.exists():
            with open(log_file, 'r') as f:
                restores = json.load(f)
            
            report.append("\n🔄 RECOVERY HISTORY")
            report.append("-"*40)
            for restore in restores:
                report.append(f"  {restore['timestamp']}")
                report.append(f"    Backup: {restore['backup']}")
                report.append(f"    Restored to: {restore['restore_path']}")
        
        report.append("\n" + "="*80)
        report.append("END OF REPORT")
        report.append("="*80)
        
        report_text = "\n".join(report)
        
        # Save report
        with open(self.recovery_dir / 'recovery_report.txt', 'w') as f:
            f.write(report_text)
        
        return report_text

def main():
    parser = argparse.ArgumentParser(description='Backup and Recovery Tool')
    parser.add_argument('--backup-root', default='/backups', help='Backup root directory')
    parser.add_argument('--id', help='Recovery/incident ID')
    parser.add_argument('--list', action='store_true', help='List available backups')
    parser.add_argument('--verify', metavar='BACKUP', help='Verify backup integrity')
    parser.add_argument('--restore', metavar='BACKUP', help='Restore from backup')
    parser.add_argument('--restore-path', help='Destination for restoration')
    parser.add_argument('--files', nargs='+', help='Specific files to restore')
    parser.add_argument('--emergency-backup', nargs='+', help='Create emergency backup of paths')
    parser.add_argument('--compare', metavar='BACKUP', help='Compare with backup')
    parser.add_argument('--current-path', help='Current path for comparison')
    
    args = parser.parse_args()
    
    recovery = BackupRecovery(args.backup_root, args.id)
    
    print(f"""
    ╔═══════════════════════════════════════╗
    ║     Backup & Recovery Tool v1.0       ║
    ║         Incident Response             ║
    ╚═══════════════════════════════════════╝
    """)
    
    if args.list:
        recovery.list_backups()
    
    elif args.verify:
        recovery.verify_backup(args.verify)
    
    elif args.restore:
        recovery.restore_backup(args.restore, args.restore_path, args.files)
    
    elif args.emergency_backup:
        recovery.create_emergency_backup(args.emergency_backup)
    
    elif args.compare:
        recovery.compare_with_backup(args.compare, args.current_path)
    
    else:
        # Show summary
        backups = recovery.list_backups()
        print(f"\nTotal backups available: {len(backups)}")
        recovery.generate_report()

if __name__ == "__main__":
    main()
