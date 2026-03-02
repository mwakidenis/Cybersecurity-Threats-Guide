
### phishing/detection/phishing_detector.py

```python
#!/usr/bin/env python3
"""
Phishing Detector
Location: 04-social-engineering/phishing/detection/phishing_detector.py

This script analyzes emails and URLs for phishing indicators including:
- Email header analysis
- Link reputation checking
- Content analysis
- Domain spoofing detection
"""

import os
import re
import json
import hashlib
import argparse
import requests
import dns.resolver
import whois
from datetime import datetime, timedelta
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse, unquote
import tldextract
from colorama import init, Fore, Style

init(autoreset=True)

class PhishingDetector:
    """
    Comprehensive Phishing Detection System
    """
    
    def __init__(self, use_virustotal=False, vt_api_key=None):
        """
        Initialize Phishing Detector
        
        Args:
            use_virustotal: Enable VirusTotal API
            vt_api_key: VirusTotal API key
        """
        self.use_virustotal = use_virustotal
        self.vt_api_key = vt_api_key
        
        # Known phishing indicators
        self.phishing_keywords = [
            'urgent', 'verify', 'account', 'suspended', 'limited',
            'unusual activity', 'sign in', 'update your', 'confirm',
            'security', 'alert', 'warning', 'restricted', 'locked',
            'password expired', 'click here', 'login', 'credential',
            'ssn', 'social security', 'credit card', 'paypal',
            'amazon', 'netflix', 'bank', 'apple id', 'microsoft'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
            '.xyz', '.top', '.win', '.bid', '.trade',  # Cheap TLDs
            '.review', '.date', '.download', '.loan'  # Spammy TLDs
        ]
        
        # Trusted domains (whitelist)
        self.trusted_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'facebook.com', 'twitter.com', 'linkedin.com',
            'github.com', 'dropbox.com', 'box.com', 'salesforce.com'
        ]
        
        # Statistics
        self.stats = {
            'emails_analyzed': 0,
            'urls_analyzed': 0,
            'phishing_detected': 0,
            'suspicious_findings': 0
        }
        
    def analyze_email_file(self, email_file):
        """Analyze email from .eml file"""
        print(f"\n{Fore.CYAN}[*] Analyzing email file: {email_file}{Style.RESET_ALL}")
        
        try:
            with open(email_file, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            results = {
                'filename': email_file,
                'headers': self.analyze_headers(msg),
                'links': self.extract_links(msg),
                'attachments': self.extract_attachments(msg),
                'content': self.analyze_content(msg),
                'spf_dkim_dmarc': self.check_email_auth(msg),
                'risk_score': 0,
                'risk_level': 'LOW',
                'findings': []
            }
            
            # Analyze headers
            header_results = self.analyze_headers(msg)
            results['headers'] = header_results
            if header_results.get('suspicious'):
                results['findings'].extend(header_results['suspicious'])
            
            # Extract and analyze links
            links = self.extract_links(msg)
            results['links'] = links
            for link in links:
                link_analysis = self.analyze_url(link['url'])
                if link_analysis['risk_level'] != 'LOW':
                    results['findings'].append({
                        'type': 'suspicious_link',
                        'url': link['url'],
                        'analysis': link_analysis
                    })
            
            # Analyze attachments
            attachments = self.extract_attachments(msg)
            results['attachments'] = attachments
            for attachment in attachments:
                if attachment['extension'] in ['.exe', '.scr', '.zip', '.js', '.vbs']:
                    results['findings'].append({
                        'type': 'dangerous_attachment',
                        'filename': attachment['filename'],
                        'extension': attachment['extension']
                    })
            
            # Analyze content
            content_results = self.analyze_content(msg)
            results['content'] = content_results
            if content_results['suspicious_keywords']:
                results['findings'].append({
                    'type': 'suspicious_keywords',
                    'keywords': content_results['suspicious_keywords']
                })
            
            # Check email authentication
            auth_results = self.check_email_auth(msg)
            results['spf_dkim_dmarc'] = auth_results
            if not auth_results.get('spf_pass', True):
                results['findings'].append({
                    'type': 'spf_fail',
                    'details': auth_results.get('spf_details', 'SPF check failed')
                })
            
            # Calculate risk score
            results['risk_score'] = self.calculate_risk_score(results)
            results['risk_level'] = self.get_risk_level(results['risk_score'])
            
            self.stats['emails_analyzed'] += 1
            if results['risk_level'] in ['HIGH', 'CRITICAL']:
                self.stats['phishing_detected'] += 1
            elif results['risk_level'] == 'MEDIUM':
                self.stats['suspicious_findings'] += 1
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error analyzing email: {e}{Style.RESET_ALL}")
            return None
    
    def analyze_headers(self, msg):
        """Analyze email headers for spoofing indicators"""
        results = {
            'from': msg.get('From', ''),
            'reply-to': msg.get('Reply-To', ''),
            'return-path': msg.get('Return-Path', ''),
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'message-id': msg.get('Message-ID', ''),
            'received': [],
            'suspicious': []
        }
        
        # Extract From domain
        from_header = msg.get('From', '')
        from_domain = self.extract_domain(from_header)
        
        # Check Reply-To mismatch
        reply_to = msg.get('Reply-To', '')
        if reply_to and from_domain:
            reply_domain = self.extract_domain(reply_to)
            if reply_domain and reply_domain != from_domain:
                results['suspicious'].append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})")
        
        # Check Return-Path
        return_path = msg.get('Return-Path', '')
        if return_path and from_domain:
            return_domain = self.extract_domain(return_path)
            if return_domain and return_domain != from_domain:
                results['suspicious'].append(f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})")
        
        # Parse Received headers
        received_headers = msg.get_all('Received', [])
        for received in received_headers:
            results['received'].append(received[:100] + '...' if len(received) > 100 else received)
            
            # Check for suspicious relays
            if 'unknown' in received.lower() or 'untrusted' in received.lower():
                results['suspicious'].append(f"Suspicious relay in Received header")
        
        # Check Message-ID
        message_id = msg.get('Message-ID', '')
        if message_id and from_domain:
            if from_domain not in message_id:
                results['suspicious'].append(f"Message-ID domain mismatch")
        
        return results
    
    def extract_links(self, msg):
        """Extract all links from email"""
        links = []
        
        # Get email body
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/html':
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    self.extract_links_from_html(body, links)
                elif part.get_content_type() == 'text/plain':
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    self.extract_links_from_text(body, links)
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            if msg.get_content_type() == 'text/html':
                self.extract_links_from_html(body, links)
            else:
                self.extract_links_from_text(body, links)
        
        return links
    
    def extract_links_from_html(self, html, links):
        """Extract links from HTML content"""
        # Simple regex for href links
        href_pattern = r'href=["\'](https?://[^"\']+)["\']'
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            url = match.group(1)
            
            # Try to find display text
            link_text = ''
            text_pattern = r'>([^<]+)</a>'
            text_match = re.search(text_pattern, html[match.end():match.end()+200])
            if text_match:
                link_text = text_match.group(1)
            
            links.append({
                'url': url,
                'text': link_text,
                'type': 'html'
            })
        
        # Extract from text content
        self.extract_links_from_text(html, links)
    
    def extract_links_from_text(self, text, links):
        """Extract links from plain text"""
        url_pattern = r'https?://[^\s<>"\'(){}|\\^`\[\]]+'
        for match in re.finditer(url_pattern, text):
            url = match.group(0)
            if not any(l['url'] == url for l in links):
                links.append({
                    'url': url,
                    'text': '',
                    'type': 'text'
                })
    
    def extract_attachments(self, msg):
        """Extract attachment information"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'filename': filename,
                            'extension': os.path.splitext(filename)[1].lower(),
                            'size': len(part.get_payload(decode=True) or b''),
                            'content_type': part.get_content_type()
                        })
        
        return attachments
    
    def analyze_content(self, msg):
        """Analyze email content for phishing keywords"""
        results = {
            'suspicious_keywords': [],
            'urgency_indicators': [],
            'grammar_issues': []
        }
        
        # Get email body
        body = ''
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ['text/plain', 'text/html']:
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        
        body_lower = body.lower()
        
        # Check for suspicious keywords
        for keyword in self.phishing_keywords:
            if keyword in body_lower:
                results['suspicious_keywords'].append(keyword)
        
        # Check for urgency indicators
        urgency_words = ['immediate', 'urgent', 'asap', 'warning', 'alert', 'suspended', 'locked']
        for word in urgency_words:
            if word in body_lower:
                results['urgency_indicators'].append(word)
        
        # Check for poor grammar (simplified)
        grammar_patterns = [
            r'your\s+account\s+will\s+be',
            r'click\s+the\s+below',
            r'kindly\s+update',
            r'we\s+have\s+noticed'
        ]
        
        for pattern in grammar_patterns:
            if re.search(pattern, body_lower):
                results['grammar_issues'].append(f"Pattern: {pattern}")
        
        return results
    
    def analyze_url(self, url):
        """Analyze URL for phishing indicators"""
        results = {
            'url': url,
            'parsed': None,
            'domain_age': None,
            'ssl_valid': None,
            'suspicious_tld': False,
            'ip_address': False,
            'shortened': False,
            'contains_spoof': False,
            'risk_score': 0,
            'risk_level': 'LOW',
            'findings': []
        }
        
        try:
            parsed = urlparse(url)
            results['parsed'] = {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path,
                'params': parsed.params,
                'query': parsed.query,
                'fragment': parsed.fragment
            }
            
            # Extract domain
            domain = parsed.netloc.lower()
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Check for IP address
            ip_pattern = r'^\d+\.\d+\.\d+\.\d+$'
            if re.match(ip_pattern, domain):
                results['ip_address'] = True
                results['findings'].append('URL uses IP address instead of domain name')
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
            if any(s in domain for s in shorteners):
                results['shortened'] = True
                results['findings'].append('URL uses link shortener')
            
            # Check TLD
            ext = tldextract.extract(url)
            tld = f".{ext.suffix}"
            if tld in self.suspicious_tlds:
                results['suspicious_tld'] = True
                results['findings'].append(f'Suspicious TLD: {tld}')
            
            # Check for domain spoofing
            for trusted in self.trusted_domains:
                if trusted in domain and domain != trusted:
                    # Check if it's a subdomain or different domain containing trusted name
                    if domain.endswith(f".{trusted}") or domain == trusted:
                        continue
                    results['contains_spoof'] = True
                    results['findings'].append(f'Possible spoof of {trusted}')
            
            # Get domain age (if possible)
            try:
                w = whois.whois(domain)
                if w.creation_date:
                    if isinstance(w.creation_date, list):
                        creation_date = w.creation_date[0]
                    else:
                        creation_date = w.creation_date
                    
                    age = datetime.now() - creation_date
                    results['domain_age'] = age.days
                    
                    if age.days < 30:
                        results['findings'].append(f'Domain is very new ({age.days} days old)')
                    elif age.days < 90:
                        results['findings'].append(f'Domain is relatively new ({age.days} days old)')
            except:
                results['domain_age'] = 'Unknown'
            
            # Check SSL certificate
            if parsed.scheme == 'https':
                try:
                    import ssl
                    import socket
                    
                    context = ssl.create_default_context()
                    with socket.create_connection((domain, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Check expiration
                            from datetime import datetime
                            not_after = cert.get('notAfter')
                            if not_after:
                                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                if expiry < datetime.now():
                                    results['findings'].append('SSL certificate expired')
                                elif (expiry - datetime.now()).days < 30:
                                    results['findings'].append('SSL certificate expiring soon')
                            
                            results['ssl_valid'] = True
                except:
                    results['ssl_valid'] = False
                    results['findings'].append('SSL certificate validation failed')
            else:
                results['findings'].append('URL uses HTTP (not HTTPS)')
            
            # Calculate risk score
            results['risk_score'] = len(results['findings'])
            if results['risk_score'] >= 5:
                results['risk_level'] = 'HIGH'
            elif results['risk_score'] >= 3:
                results['risk_level'] = 'MEDIUM'
            
            self.stats['urls_analyzed'] += 1
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def check_email_auth(self, msg):
        """Check SPF, DKIM, DMARC authentication"""
        results = {
            'spf_pass': None,
            'spf_details': None,
            'dkim_pass': None,
            'dkim_details': None,
            'dmarc_pass': None,
            'dmarc_details': None
        }
        
        # Check Authentication-Results header
        auth_results = msg.get('Authentication-Results', '')
        
        if auth_results:
            # Parse SPF
            spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
            if spf_match:
                results['spf_pass'] = spf_match.group(1).lower() == 'pass'
                results['spf_details'] = spf_match.group(0)
            
            # Parse DKIM
            dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
            if dkim_match:
                results['dkim_pass'] = dkim_match.group(1).lower() == 'pass'
                results['dkim_details'] = dkim_match.group(0)
            
            # Parse DMARC
            dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
            if dmarc_match:
                results['dmarc_pass'] = dmarc_match.group(1).lower() == 'pass'
                results['dmarc_details'] = dmarc_match.group(0)
        
        return results
    
    def extract_domain(self, email):
        """Extract domain from email address"""
        match = re.search(r'@([^>\s]+)', email)
        if match:
            return match.group(1).lower()
        return None
    
    def calculate_risk_score(self, results):
        """Calculate overall risk score"""
        score = 0
        
        # Header issues
        if results.get('headers', {}).get('suspicious'):
            score += len(results['headers']['suspicious']) * 10
        
        # Suspicious links
        suspicious_links = [f for f in results.get('findings', []) if f.get('type') == 'suspicious_link']
        score += len(suspicious_links) * 15
        
        # Dangerous attachments
        dangerous_attachments = [f for f in results.get('findings', []) if f.get('type') == 'dangerous_attachment']
        score += len(dangerous_attachments) * 20
        
        # Suspicious keywords
        keyword_findings = [f for f in results.get('findings', []) if f.get('type') == 'suspicious_keywords']
        if keyword_findings:
            score += len(keyword_findings[0].get('keywords', [])) * 5
        
        # Authentication failures
        auth = results.get('spf_dkim_dmarc', {})
        if auth.get('spf_pass') == False:
            score += 15
        if auth.get('dkim_pass') == False:
            score += 15
        if auth.get('dmarc_pass') == False:
            score += 15
        
        return min(score, 100)  # Cap at 100
    
    def get_risk_level(self, score):
        """Get risk level from score"""
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def print_results(self, results):
        """Print analysis results"""
        if not results:
            return
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 PHISHING ANALYSIS RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Risk level
        risk_color = {
            'LOW': Fore.GREEN,
            'MEDIUM': Fore.YELLOW,
            'HIGH': Fore.RED,
            'CRITICAL': Fore.RED + Style.BRIGHT
        }.get(results['risk_level'], Fore.WHITE)
        
        print(f"\n{risk_color}Risk Level: {results['risk_level']} (Score: {results['risk_score']}){Style.RESET_ALL}")
        
        # Headers
        print(f"\n{Fore.CYAN}Email Headers:{Style.RESET_ALL}")
        print(f"  From: {results['headers'].get('from', 'N/A')}")
        print(f"  Reply-To: {results['headers'].get('reply-to', 'N/A')}")
        print(f"  Subject: {results['headers'].get('subject', 'N/A')}")
        
        # Authentication
        auth = results.get('spf_dkim_dmarc', {})
        print(f"\n{Fore.CYAN}Email Authentication:{Style.RESET_ALL}")
        spf_color = Fore.GREEN if auth.get('spf_pass') else Fore.RED
        print(f"  {spf_color}SPF: {auth.get('spf_pass', 'Unknown')}{Style.RESET_ALL}")
        
        dkim_color = Fore.GREEN if auth.get('dkim_pass') else Fore.RED
        print(f"  {dkim_color}DKIM: {auth.get('dkim_pass', 'Unknown')}{Style.RESET_ALL}")
        
        dmarc_color = Fore.GREEN if auth.get('dmarc_pass') else Fore.RED
        print(f"  {dmarc_color}DMARC: {auth.get('dmarc_pass', 'Unknown')}{Style.RESET_ALL}")
        
        # Links
        if results.get('links'):
            print(f"\n{Fore.CYAN}Links Found ({len(results['links'])}):{Style.RESET_ALL}")
            for link in results['links'][:5]:  # Show first 5
                print(f"  • {link['url'][:60]}...")
        
        # Attachments
        if results.get('attachments'):
            print(f"\n{Fore.CYAN}Attachments ({len(results['attachments'])}):{Style.RESET_ALL}")
            for att in results['attachments']:
                color = Fore.RED if att['extension'] in ['.exe', '.scr'] else Fore.YELLOW
                print(f"  {color}• {att['filename']} ({att['extension']}){Style.RESET_ALL}")
        
        # Findings
        if results.get('findings'):
            print(f"\n{Fore.RED}Findings ({len(results['findings'])}):{Style.RESET_ALL}")
            for finding in results['findings']:
                if finding['type'] == 'suspicious_link':
                    print(f"  {Fore.RED}• Suspicious link: {finding['url'][:50]}...{Style.RESET_ALL}")
                elif finding['type'] == 'dangerous_attachment':
                    print(f"  {Fore.RED}• Dangerous attachment: {finding['filename']}{Style.RESET_ALL}")
                elif finding['type'] == 'suspicious_keywords':
                    print(f"  {Fore.YELLOW}• Suspicious keywords: {', '.join(finding['keywords'][:5])}{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.YELLOW}• {finding.get('details', finding.get('type', 'Unknown'))}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    def generate_report(self, results, output_file):
        """Generate JSON report"""
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.GREEN}[✓] Report saved to {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[✗] Error saving report: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Phishing Detector')
    parser.add_argument('-f', '--file', help='Email file (.eml) to analyze')
    parser.add_argument('-u', '--url', help='URL to analyze')
    parser.add_argument('-o', '--output', help='Output report file')
    parser.add_argument('--virustotal', action='store_true', help='Enable VirusTotal API')
    parser.add_argument('--api-key', help='VirusTotal API key')
    
    args = parser.parse_args()
    
    print(f"""
    {Fore.CYAN}╔═══════════════════════════════════════╗
    ║        Phishing Detector v1.0         ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    detector = PhishingDetector(
        use_virustotal=args.virustotal,
        vt_api_key=args.api_key
    )
    
    if args.file:
        results = detector.analyze_email_file(args.file)
        if results:
            detector.print_results(results)
            if args.output:
                detector.generate_report(results, args.output)
    
    elif args.url:
        results = detector.analyze_url(args.url)
        print(f"\n{Fore.CYAN}URL Analysis Results:{Style.RESET_ALL}")
        print(json.dumps(results, indent=2))
    
    else:
        print("Use -f to analyze an email file or -u to analyze a URL")

if __name__ == "__main__":
    main()
