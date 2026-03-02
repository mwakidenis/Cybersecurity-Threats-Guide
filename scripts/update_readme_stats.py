#!/usr/bin/env python3

import os
import re
import sys
import json
from pathlib import Path
from datetime import datetime
import argparse
from collections import defaultdict

# Try to import colorama, but don't fail if not available
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Create dummy colorama replacements
    class Fore:
        RED = GREEN = YELLOW = CYAN = ''
    class Style:
        RESET_ALL = ''

class ReadmeStatsUpdater:
    """
    Automatically updates README.md with repository statistics
    """
    
    def __init__(self, repo_path='.'):
        self.repo_path = Path(repo_path)
        self.readme_path = self.repo_path / 'README.md'
        
        # Initialize statistics
        self.stats = {
            'total_sections': 0,
            'total_topics': 0,
            'python_scripts': 0,
            'doc_files': 0,
            'config_files': 0,
            'shell_scripts': 0,
            'total_files': 0,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'contributors': 0,
            'total_commits': 0
        }
        
        # File extensions to count
        self.python_extensions = ['.py']
        self.doc_extensions = ['.md', '.txt', '.rst', '.markdown']
        self.config_extensions = ['.json', '.yml', '.yaml', '.conf', '.cfg', '.ini']
        self.shell_extensions = ['.sh', '.bash', '.zsh']
        
        # Sections to count (your actual structure)
        self.section_dirs = [
            '01-network-security',
            '02-web-application-security', 
            '03-malware-analysis',
            '04-social-engineering',
            '05-cryptography',
            '06-incident-response'
        ]
        
        # Directories to exclude from counting
        self.exclude_dirs = [
            '.git',
            '__pycache__',
            '.github',
            'venv',
            'env',
            '.venv',
            'node_modules'
        ]
        
    def scan_repository(self):
        """Scan repository and collect statistics"""
        print(f"{Fore.CYAN}[*] Scanning repository...{Style.RESET_ALL}")
        
        python_count = 0
        doc_count = 0
        config_count = 0
        shell_count = 0
        total_files = 0
        topics_found = set()
        
        # Walk through all directories
        for root, dirs, files in os.walk(self.repo_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs and not d.startswith('.')]
            
            # Get relative path
            rel_path = os.path.relpath(root, self.repo_path)
            
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file)[1].lower()
                
                total_files += 1
                
                # Count by file type
                if file_ext in self.python_extensions:
                    python_count += 1
                elif file_ext in self.doc_extensions:
                    doc_count += 1
                elif file_ext in self.config_extensions:
                    config_count += 1
                elif file_ext in self.shell_extensions:
                    shell_count += 1
                
                # Check if this is a README in a topic directory
                if file == 'README.md':
                    # Extract topic name from parent directory
                    parent_dir = os.path.basename(os.path.dirname(file_path))
                    if parent_dir not in ['docs', 'resources', 'scripts', 'tools']:
                        if parent_dir and not parent_dir.startswith('.'):
                            topics_found.add(parent_dir)
        
        # Count sections (existing directories)
        sections_present = 0
        sections_found = []
        for section in self.section_dirs:
            if (self.repo_path / section).exists():
                sections_present += 1
                sections_found.append(section)
        
        # Try to get contributor count from git if available
        try:
            import subprocess
            result = subprocess.run(['git', 'shortlog', '-sn'], 
                                   capture_output=True, text=True, cwd=self.repo_path)
            if result.returncode == 0:
                self.stats['contributors'] = len(result.stdout.strip().split('\n'))
            
            result = subprocess.run(['git', 'rev-list', '--count', 'HEAD'],
                                   capture_output=True, text=True, cwd=self.repo_path)
            if result.returncode == 0:
                self.stats['total_commits'] = int(result.stdout.strip())
        except:
            pass
        
        self.stats.update({
            'total_sections': sections_present,
            'total_topics': len(topics_found),
            'python_scripts': python_count,
            'doc_files': doc_count,
            'config_files': config_count,
            'shell_scripts': shell_count,
            'total_files': total_files,
            'sections_found': sections_found,
            'topics_found': sorted(list(topics_found))[:10]  # Limit to 10 for display
        })
        
        return self.stats
    
    def generate_stats_table(self):
        """Generate markdown table with statistics"""
        table = f"""## 📊 Repository Statistics

| Metric | Count |
|--------|-------|
| **Total Sections** | {self.stats['total_sections']}/6 |
| **Total Topics** | {self.stats['total_topics']}+ |
| **Python Scripts** | {self.stats['python_scripts']} |
| **Shell Scripts** | {self.stats['shell_scripts']} |
| **Documentation Files** | {self.stats['doc_files']} |
| **Configuration Files** | {self.stats['config_files']} |
| **Total Files** | {self.stats['total_files']} |
| **Contributors** | {self.stats['contributors']} |
| **Total Commits** | {self.stats['total_commits']} |

*Last updated: {self.stats['last_updated']} (Auto-updated via GitHub Actions)*

![Progress](https://progress-bar.dev/{int(self.stats['total_sections']*16.67)}/?title=Sections%20Complete)
"""
        return table
    
    def generate_badge(self):
        """Generate badge for README"""
        badge = f"""
[![Python](https://img.shields.io/badge/python-{self.stats['python_scripts']}+-blue.svg)](https://python.org)
[![Shell](https://img.shields.io/badge/shell-{self.stats['shell_scripts']}-green.svg)](https://www.gnu.org/software/bash/)
[![Docs](https://img.shields.io/badge/docs-{self.stats['doc_files']}-yellow.svg)](README.md)
[![Sections](https://img.shields.io/badge/sections-{self.stats['total_sections']}/6-orange.svg)](#-categories)
[![Files](https://img.shields.io/badge/total%20files-{self.stats['total_files']}-brightgreen.svg)](#)
[![Last Updated](https://img.shields.io/badge/last%20updated-{self.stats['last_updated'].replace(' ', '%20')}-lightgrey.svg)](#)
"""
        return badge
    
    def update_readme(self, dry_run=False):
        """Update README.md with new statistics"""
        if not self.readme_path.exists():
            print(f"{Fore.RED}[✗] README.md not found at {self.readme_path}{Style.RESET_ALL}")
            return False
        
        # Read current README
        with open(self.readme_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Generate new stats table
        new_stats = self.generate_stats_table()
        new_badge = self.generate_badge()
        
        # Update badges section
        badge_pattern = r'\[!\[Python\].*?\]\(.*?\)(?:\s*\[!\[.*?\]\(.*?\)\s*)*'
        if re.search(badge_pattern, content):
            content = re.sub(badge_pattern, new_badge.strip(), content)
        
        # Update statistics table
        stats_patterns = [
            r'## 📊 Repository Statistics.*?(?=##|\Z)',
            r'## Repository Statistics.*?(?=##|\Z)',
            r'### Statistics.*?(?=##|\Z)'
        ]
        
        new_content = content
        replaced = False
        
        for pattern in stats_patterns:
            if re.search(pattern, content, re.DOTALL):
                new_content = re.sub(pattern, new_stats, content, flags=re.DOTALL)
                replaced = True
                break
        
        # If no existing section, append before the last section
        if not replaced:
            # Find where to insert (before last heading)
            last_heading = content.rfind('\n## ')
            if last_heading != -1:
                new_content = content[:last_heading] + '\n' + new_stats + '\n' + content[last_heading:]
            else:
                new_content = content + '\n\n' + new_stats
        
        if dry_run:
            print(f"\n{Fore.CYAN}📋 Preview of changes:{Style.RESET_ALL}")
            print(new_stats)
            print(f"\n{Fore.YELLOW}Dry run - no changes written{Style.RESET_ALL}")
            return True
        
        # Write updated content
        with open(self.readme_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"{Fore.GREEN}[✓] README.md updated successfully{Style.RESET_ALL}")
        print(new_stats)
        
        return True
    
    def print_summary(self):
        """Print summary of statistics"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 REPOSITORY STATISTICS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"  Total Sections: {self.stats['total_sections']}/6")
        print(f"  Total Topics: {self.stats['total_topics']}+")
        print(f"  Python Scripts: {self.stats['python_scripts']}")
        print(f"  Shell Scripts: {self.stats['shell_scripts']}")
        print(f"  Documentation Files: {self.stats['doc_files']}")
        print(f"  Configuration Files: {self.stats['config_files']}")
        print(f"  Total Files: {self.stats['total_files']}")
        print(f"  Contributors: {self.stats['contributors']}")
        print(f"  Total Commits: {self.stats['total_commits']}")
        print(f"  Last Updated: {self.stats['last_updated']}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        # Show progress bar
        progress = int(self.stats['total_sections'] * 16.67)
        bar = '█' * (progress // 4) + '░' * (25 - (progress // 4))
        print(f"\n{Fore.GREEN}Progress: [{bar}] {progress}%{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='README.md Statistics Auto-Updater')
    parser.add_argument('--path', default='.', help='Repository path')
    parser.add_argument('--dry-run', action='store_true', help='Preview changes without writing')
    parser.add_argument('--github-actions', action='store_true', help='Running in GitHub Actions')
    
    args = parser.parse_args()
    
    # GitHub Actions mode - suppress color output
    if args.github_actions:
        global Fore, Style
        class DummyFore:
            RED = GREEN = YELLOW = CYAN = ''
        class DummyStyle:
            RESET_ALL = ''
        Fore = DummyFore()
        Style = DummyStyle()
    
    print(f"""
╔═══════════════════════════════════════╗
║    README.md Statistics Updater      ║
║       Auto-Update Repository Stats    ║
╚═══════════════════════════════════════╝
    """)
    
    updater = ReadmeStatsUpdater(args.path)
    updater.scan_repository()
    
    if args.github_actions:
        # GitHub Actions mode - just update and commit
        updater.update_readme()
        updater.print_summary()
    else:
        # Interactive mode
        updater.print_summary()
        
        if args.dry_run:
            updater.update_readme(dry_run=True)
        else:
            response = input(f"\n{Fore.YELLOW}[?] Update README.md with these statistics? (yes/no): {Style.RESET_ALL}")
            if response.lower() == 'yes':
                updater.update_readme()
            else:
                print(f"{Fore.YELLOW}[!] README.md not updated{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
