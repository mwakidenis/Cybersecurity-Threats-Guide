
import os
import re
import json
from pathlib import Path
from datetime import datetime
import argparse
from colorama import init, Fore, Style

init(autoreset=True)

class ReadmeStatsUpdater:
    """
    Automatically updates README.md with repository statistics
    """
    
    def __init__(self, repo_path='.'):
        self.repo_path = Path(repo_path)
        self.readme_path = self.repo_path / 'README.md'
        self.stats = {
            'total_sections': 0,
            'total_topics': 0,
            'python_scripts': 0,
            'doc_files': 0,
            'config_files': 0,
            'total_files': 0,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # File extensions to count
        self.python_extensions = ['.py']
        self.doc_extensions = ['.md', '.txt', '.rst']
        self.config_extensions = ['.json', '.yml', '.yaml', '.conf', '.cfg', '.ini', '.sh']
        
        # Sections to count
        self.section_dirs = [
            '01-network-security',
            '02-web-application-security', 
            '03-malware-analysis',
            '04-social-engineering',
            '05-cryptography',
            '06-incident-response'
        ]
        
        # Topics per section (approximate - will be calculated)
        self.topics_per_section = {}
        
    def scan_repository(self):
        """Scan repository and collect statistics"""
        print(f"{Fore.CYAN}[*] Scanning repository...{Style.RESET_ALL}")
        
        python_count = 0
        doc_count = 0
        config_count = 0
        total_files = 0
        topics_found = set()
        
        # Walk through all directories
        for root, dirs, files in os.walk(self.repo_path):
            # Skip hidden directories and __pycache__
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
            
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
                
                # Check if this is a README in a topic directory
                if file == 'README.md' and os.path.basename(root) not in ['docs', 'resources']:
                    topic = os.path.basename(root)
                    topics_found.add(topic)
        
        # Count sections (existing directories)
        sections_present = 0
        for section in self.section_dirs:
            if (self.repo_path / section).exists():
                sections_present += 1
        
        self.stats.update({
            'total_sections': sections_present,
            'total_topics': len(topics_found),
            'python_scripts': python_count,
            'doc_files': doc_count,
            'config_files': config_count,
            'total_files': total_files,
            'topics_found': sorted(list(topics_found))
        })
        
        return self.stats
    
    def generate_stats_table(self):
        """Generate markdown table with statistics"""
        table = f"""## 📊 Repository Statistics

| Metric | Count |
|--------|-------|
| **Total Sections** | {self.stats['total_sections']} |
| **Total Topics** | {self.stats['total_topics']}+ |
| **Python Scripts** | {self.stats['python_scripts']} |
| **Documentation Files** | {self.stats['doc_files']} |
| **Configuration Files** | {self.stats['config_files']} |
| **Total Files** | {self.stats['total_files']} |

*Last updated: {self.stats['last_updated']}*
"""
        return table
    
    def generate_detailed_stats(self):
        """Generate detailed statistics"""
        detailed = f"""
## 📊 Detailed Statistics

### File Type Breakdown
- **Python Scripts**: {self.stats['python_scripts']} files
- **Documentation**: {self.stats['doc_files']} files
- **Configuration**: {self.stats['config_files']} files
- **Other**: {self.stats['total_files'] - self.stats['python_scripts'] - self.stats['doc_files'] - self.stats['config_files']} files

### Section Coverage
- **01-network-security**: Present
- **02-web-application-security**: Present  
- **03-malware-analysis**: Present
- **04-social-engineering**: {('Present' if (self.repo_path / '04-social-engineering').exists() else 'Missing')}
- **05-cryptography**: {('Present' if (self.repo_path / '05-cryptography').exists() else 'Missing')}
- **06-incident-response**: {('Present' if (self.repo_path / '06-incident-response').exists() else 'Missing')}

### Topics Found ({self.stats['total_topics']})
{', '.join(self.stats['topics_found'][:20])}{'...' if len(self.stats['topics_found']) > 20 else ''}

*Statistics auto-generated on {self.stats['last_updated']}*
"""
        return detailed
    
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
        
        # Pattern to match existing stats section
        patterns = [
            r'## 📊 Repository Statistics.*?(?=##|\Z)',
            r'## Repository Statistics.*?(?=##|\Z)',
            r'### Statistics.*?(?=##|\Z)'
        ]
        
        new_content = content
        replaced = False
        
        for pattern in patterns:
            if re.search(pattern, content, re.DOTALL):
                new_content = re.sub(pattern, new_stats, content, flags=re.DOTALL)
                replaced = True
                break
        
        # If no existing section, append at the end
        if not replaced:
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
    
    def generate_badge(self):
        """Generate a badge for the repository"""
        badge = f"""
[![Python](https://img.shields.io/badge/python-{self.stats['python_scripts']}+-blue.svg)](https://python.org)
[![Docs](https://img.shields.io/badge/docs-{self.stats['doc_files']}+-green.svg)](README.md)
[![Sections](https://img.shields.io/badge/sections-{self.stats['total_sections']}-orange.svg)](#-categories)
[![Files](https://img.shields.io/badge/total%20files-{self.stats['total_files']}-brightgreen.svg)](#)
[![Last Updated](https://img.shields.io/badge/last%20updated-{self.stats['last_updated'].replace(' ', '%20')}-yellow.svg)](#)
"""
        return badge
    
    def save_stats_json(self, output_file='repo_stats.json'):
        """Save statistics to JSON file"""
        output_path = self.repo_path / output_file
        with open(output_path, 'w') as f:
            json.dump(self.stats, f, indent=2)
        print(f"{Fore.GREEN}[✓] Statistics saved to {output_file}{Style.RESET_ALL}")
    
    def print_summary(self):
        """Print summary of statistics"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 REPOSITORY STATISTICS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"  Total Sections: {self.stats['total_sections']}")
        print(f"  Total Topics: {self.stats['total_topics']}+")
        print(f"  Python Scripts: {self.stats['python_scripts']}")
        print(f"  Documentation Files: {self.stats['doc_files']}")
        print(f"  Configuration Files: {self.stats['config_files']}")
        print(f"  Total Files: {self.stats['total_files']}")
        print(f"  Last Updated: {self.stats['last_updated']}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='README.md Statistics Auto-Updater')
    parser.add_argument('--path', default='.', help='Repository path')
    parser.add_argument('--dry-run', action='store_true', help='Preview changes without writing')
    parser.add_argument('--save-json', action='store_true', help='Save statistics to JSON')
    parser.add_argument('--badge', action='store_true', help='Generate repository badge')
    parser.add_argument('--detailed', action='store_true', help='Show detailed statistics')
    
    args = parser.parse_args()
    
    print(f"""
    {Fore.CYAN}╔═══════════════════════════════════════╗
    ║    README.md Statistics Updater      ║
    ║       Auto-Update Repository Stats    ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    updater = ReadmeStatsUpdater(args.path)
    updater.scan_repository()
    
    if args.detailed:
        print(updater.generate_detailed_stats())
    
    if args.badge:
        print(f"\n{Fore.GREEN}Repository Badge:{Style.RESET_ALL}")
        print(updater.generate_badge())
    
    if args.save_json:
        updater.save_stats_json()
    
    # Update README
    updater.update_readme(dry_run=args.dry_run)
    
    if not any([args.detailed, args.badge, args.save_json, args.dry_run]):
        updater.print_summary()

if __name__ == "__main__":
    main()
