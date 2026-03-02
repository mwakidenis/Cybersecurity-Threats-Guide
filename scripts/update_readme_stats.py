#!/usr/bin/env python3
"""
README.md Statistics Auto-Updater - FIXED VERSION
Location: scripts/update_readme_stats.py
"""

import os
import re
import sys
import json
from pathlib import Path
from datetime import datetime
import argparse
from collections import defaultdict

class ReadmeStatsUpdater:
    def __init__(self, repo_path='.'):
        self.repo_path = Path(repo_path)
        self.readme_path = self.repo_path / 'README.md'
        
        self.stats = {
            'total_sections': 0,
            'total_topics': 0,
            'python_scripts': 0,
            'doc_files': 0,
            'config_files': 0,
            'shell_scripts': 0,
            'total_files': 0,
            'contributors': 1,
            'total_commits': 74,  # From your history
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Your actual sections (all present!)
        self.section_dirs = [
            '01-network-security',
            '02-web-application-security',
            '03-malware-analysis',
            '04-social-engineering',
            '05-cryptography',
            '06-incident-response'
        ]
        
        # File extensions
        self.python_extensions = ['.py']
        self.doc_extensions = ['.md', '.txt', '.rst', '.markdown']
        self.config_extensions = ['.json', '.yml', '.yaml', '.conf', '.cfg', '.ini']
        self.shell_extensions = ['.sh', '.bash', '.zsh']
        
        # Exclude these directories
        self.exclude_dirs = [
            '.git', '__pycache__', '.github', 'venv', 'env', '.venv', 'node_modules'
        ]
    
    def scan_repository(self):
        """Scan repository and collect accurate statistics"""
        print("[*] Scanning repository...")
        
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
                
                # Count topics (subdirectories with READMEs)
                if file == 'README.md':
                    parent = os.path.basename(os.path.dirname(file_path))
                    if parent not in ['docs', 'resources', 'scripts', 'tools']:
                        if parent and not parent.startswith('.'):
                            topics_found.add(parent)
        
        # Count sections - FIXED: Count all 6 sections
        sections_present = 0
        for section in self.section_dirs:
            if (self.repo_path / section).exists():
                sections_present += 1
        
        self.stats.update({
            'total_sections': sections_present,  # Should be 6
            'total_topics': len(topics_found),    # Should be ~18
            'python_scripts': python_count,       # Should be ~45
            'doc_files': doc_count,                # Should be ~18
            'config_files': config_count,          # Should be ~6
            'shell_scripts': shell_count,          # Should be 2
            'total_files': total_files,            # Should be ~74
            'topics_found': sorted(list(topics_found))[:15]
        })
        
        return self.stats
    
    def generate_stats_table(self):
        """Generate markdown table with accurate statistics"""
        progress = int((self.stats['total_sections'] / 6) * 100)
        
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

![Progress](https://progress-bar.dev/{progress}/?title=Sections%20Complete)
"""
        return table
    
    def update_readme(self):
        """Update README.md with correct statistics"""
        if not self.readme_path.exists():
            print(f"[✗] README.md not found")
            return False
        
        with open(self.readme_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        new_stats = self.generate_stats_table()
        
        # Replace the statistics section
        pattern = r'## 📊 Repository Statistics.*?(?=##|\Z)'
        if re.search(pattern, content, re.DOTALL):
            new_content = re.sub(pattern, new_stats, content, flags=re.DOTALL)
        else:
            new_content = content + '\n\n' + new_stats
        
        with open(self.readme_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"[✓] README.md updated successfully")
        print(new_stats)
        return True

def main():
    updater = ReadmeStatsUpdater()
    updater.scan_repository()
    updater.update_readme()
    
    print("\n📊 Final Statistics:")
    print("-" * 40)
    for key, value in updater.stats.items():
        if key not in ['topics_found']:
            print(f"{key.replace('_', ' ').title()}: {value}")

if __name__ == "__main__":
    main()
