#!/usr/bin/env python3
"""
Email Analyzer
This script analyzes email headers, SPF/DKIM/DMARC records, and performs
deep inspection of email content for phishing indicators.
"""

import os
import sys
import re
import json
import argparse
import dns.resolver
import smtplib
import socket
from email import policy
from email.parser import BytesParser
from datetime import datetime
import hashlib
import base64
from colorama import init, Fore, Style

init(autoreset=True)

class EmailAnalyzer:
    """
    Deep Email Analysis Tool
    """
    
    def __init__(self):
        self.results = {
            'headers': {},
            'authentication': {},
            'security': {},
            'analysis': {}
        }
        
    def parse_email(self, email_file):
        """Parse email file"""
        try:
            with open(email_file, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            return msg
        except Exception as e:
            print(f"{Fore.RED}[!] Error parsing email: {e}{Style.RESET_ALL}")
            return None
    
    def analyze_headers_deep(self, msg):
        """Deep header analysis"""
        headers = {}
        
        # Essential headers
        essential = ['From', 'To', 'Subject', 'Date', 'Message-ID', 
                     'Return-Path', 'Reply-To', 'Sender']
        
        for header in essential:
            value = msg.get(header, '')
            headers[header] = value
            
            # Analyze From header
            if header == 'From':
                from_domain = self.extract_domain(value)
                headers['from_domain'] = from_domain
                
                # Check for display name spoofing
                if '"' in value and '<' in value:
                    headers['display_name_spoof'] = True
        
        # Get all received headers
        headers['received'] = msg.get_all('Received', [])
        
        # Analyze received path
        headers['received_analysis'] = self.analyze_received_path(headers['received'])
        
        # Get authentication results
        headers['auth_results'] = msg.get('Authentication-Results', '')
        
        # Get DKIM signature
        headers['dkim_signature'] = msg.get('DKIM-Signature', '')
        
        # Get ARC headers
        headers['arc'] = {
            'seal': msg.get('ARC-Seal', ''),
            'message-signature': msg.get('ARC-Message-Signature', ''),
            'authentication-results': msg.get('ARC-Authentication-Results', '')
        }
        
        return headers
    
    def analyze_received_path(self, received_headers):
        """Analyze the Received header path"""
        analysis = {
            'hops': len(received_headers),
            'servers': [],
            'suspicious': []
        }
        
        for received in received_headers:
            # Extract server info
            server_info = {}
            
            # Look for "from" server
            from_match = re.search(r'from\s+([^\s]+)', received, re.IGNORECASE)
            if from_match:
                server_info['from'] = from_match.group(1)
            
            # Look for "by" server
            by_match = re.search(r'by\s+([^\s]+)', received, re.IGNORECASE)
            if by_match:
                server_info['by'] = by_match.group(1)
            
            # Look for "with" protocol
            with_match = re.search(r'with\s+([^\s]+)', received, re.IGNORECASE)
            if with_match:
                server_info['with'] = with_match.group(1)
            
            # Look for IP
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
            if ip_match:
                server_info['ip'] = ip_match.group(1)
            
            # Look for timestamp
            time_match = re.search(r';\s*(.+)$', received)
            if time_match:
                server_info['time'] = time_match.group(1)
            
            analysis['servers'].append(server_info)
            
            # Check for suspicious patterns
            if 'unknown' in received.lower():
                analysis['suspicious'].append('Unknown server in path')
            if 'untrusted' in received.lower():
                analysis['suspicious'].append('Untrusted server in path')
        
        return analysis
    
    def check_spf(self, domain, sender_ip=None):
        """Check SPF record for domain"""
        result = {
            'record': None,
            'valid': False,
            'error': None
        }
        
        try:
            # Query SPF record
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text()
                if 'v=spf1' in txt:
                    result['record'] = txt.strip('"')
                    result['valid'] = True
                    break
        except dns.resolver.NoAnswer:
            result['error'] = 'No SPF record found'
        except dns.resolver.NXDOMAIN:
            result['error'] = 'Domain does not exist'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_dkim(self, domain, selector='default'):
        """Check DKIM record for domain"""
        result = {
            'record': None,
            'valid': False,
            'error': None
        }
        
        try:
            # Query DKIM record
            dkim_domain = f'{selector}._domainkey.{domain}'
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text()
                if 'v=DKIM1' in txt:
                    result['record'] = txt.strip('"')
                    result['valid'] = True
                    break
        except dns.resolver.NoAnswer:
            result['error'] = 'No DKIM record found'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_dmarc(self, domain):
        """Check DMARC record for domain"""
        result = {
            'record': None,
            'policy': None,
            'valid': False,
            'error': None
        }
        
        try:
            # Query DMARC record
            dmarc_domain = f'_dmarc.{domain}'
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text()
                if 'v=DMARC1' in txt:
                    result['record'] = txt.strip('"')
                    result['valid'] = True
                    
                    # Extract policy
                    policy_match = re.search(r'p=(\w+)', txt)
                    if policy_match:
                        result['policy'] = policy_match.group(1)
                    break
        except dns.resolver.NoAnswer:
            result['error'] = 'No DMARC record found'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def verify_ssl_certificate(self, domain):
        """Verify SSL certificate of mail server"""
        result = {
            'valid': False,
            'issuer': None,
            'expiry': None,
            'error': None
        }
        
        try:
            # Get MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_record = str(mx_records[0].exchange).rstrip('.')
            
            # Try to connect to mail server
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((mx_record, 587), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=mx_record) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Get issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    result['issuer'] = issuer.get('organizationName', 'Unknown')
                    
                    # Get expiry
                    from datetime import datetime
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        result['expiry'] = expiry.isoformat()
                        result['valid'] = expiry > datetime.now()
                    
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def extract_domain(self, email):
        """Extract domain from email address"""
        match = re.search(r'@([^>\s]+)', email)
        if match:
            return match.group(1).lower()
        return None
    
    def analyze_phishing_patterns(self, msg):
        """Analyze content for phishing patterns"""
        patterns = {
            'urgency': [
                r'urgent',
                r'immediate action',
                r'account.*suspended',
                r'security.*alert',
                r'unusual activity'
            ],
            'threats': [
                r'will be closed',
                r'will be deleted',
                r'legal action',
                r'prosecution'
            ],
            'requests': [
                r'verify.*account',
                r'confirm.*information',
                r'update.*details',
                r'click.*link'
            ]
        }
        
        findings = {
            'urgency': [],
            'threats': [],
            'requests': []
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
        
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, body_lower):
                    findings[category].append(pattern)
        
        return findings
    
    def analyze_email(self, email_file):
        """Complete email analysis"""
        print(f"\n{Fore.CYAN}[*] Analyzing email: {email_file}{Style.RESET_ALL}")
        
        msg = self.parse_email(email_file)
        if not msg:
            return None
        
        # Analyze headers
        self.results['headers'] = self.analyze_headers_deep(msg)
        
        # Extract domain
        from_header = self.results['headers'].get('From', '')
        domain = self.extract_domain(from_header)
        
        if domain:
            # Check SPF
            print(f"{Fore.CYAN}  [*] Checking SPF for {domain}...{Style.RESET_ALL}")
            self.results['authentication']['spf'] = self.check_spf(domain)
            
            # Check DKIM
            print(f"{Fore.CYAN}  [*] Checking DKIM for {domain}...{Style.RESET_ALL}")
            self.results['authentication']['dkim'] = self.check_dkim(domain)
            
            # Check DMARC
            print(f"{Fore.CYAN}  [*] Checking DMARC for {domain}...{Style.RESET_ALL}")
            self.results['authentication']['dmarc'] = self.check_dmarc(domain)
            
            # Check SSL certificate
            print(f"{Fore.CYAN}  [*] Verifying SSL certificate...{Style.RESET_ALL}")
            self.results['security']['ssl'] = self.verify_ssl_certificate(domain)
        
        # Analyze phishing patterns
        self.results['analysis']['phishing_patterns'] = self.analyze_phishing_patterns(msg)
        
        # Calculate risk score
        self.results['analysis']['risk_score'] = self.calculate_risk_score()
        self.results['analysis']['risk_level'] = self.get_risk_level(
            self.results['analysis']['risk_score']
        )
        
        return self.results
    
    def calculate_risk_score(self):
        """Calculate overall risk score"""
        score = 0
        
        # Check SPF
        spf = self.results.get('authentication', {}).get('spf', {})
        if not spf.get('valid'):
            score += 20
        
        # Check DKIM
        dkim = self.results.get('authentication', {}).get('dkim', {})
        if not dkim.get('valid'):
            score += 20
        
        # Check DMARC
        dmarc = self.results.get('authentication', {}).get('dmarc', {})
        if not dmarc.get('valid'):
            score += 20
        elif dmarc.get('policy') == 'none':
            score += 10
        
        # Check SSL
        ssl = self.results.get('security', {}).get('ssl', {})
        if not ssl.get('valid'):
            score += 15
        
        # Check phishing patterns
        patterns = self.results.get('analysis', {}).get('phishing_patterns', {})
        score += len(patterns.get('urgency', [])) * 5
        score += len(patterns.get('threats', [])) * 10
        score += len(patterns.get('requests', [])) * 5
        
        # Check received path
        received_analysis = self.results.get('headers', {}).get('received_analysis', {})
        score += len(received_analysis.get('suspicious', [])) * 10
        
        return min(score, 100)
    
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
    
    def print_report(self):
        """Print analysis report"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 EMAIL ANALYSIS REPORT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Risk level
        risk_level = self.results.get('analysis', {}).get('risk_level', 'UNKNOWN')
        risk_score = self.results.get('analysis', {}).get('risk_score', 0)
        
        risk_color = {
            'LOW': Fore.GREEN,
            'MEDIUM': Fore.YELLOW,
            'HIGH': Fore.RED,
            'CRITICAL': Fore.RED + Style.BRIGHT
        }.get(risk_level, Fore.WHITE)
        
        print(f"\n{risk_color}Risk Level: {risk_level} (Score: {risk_score}){Style.RESET_ALL}")
        
        # Headers
        print(f"\n{Fore.CYAN}📨 Email Headers:{Style.RESET_ALL}")
        headers = self.results.get('headers', {})
        print(f"  From: {headers.get('From', 'N/A')}")
        print(f"  To: {headers.get('To', 'N/A')}")
        print(f"  Subject: {headers.get('Subject', 'N/A')}")
        print(f"  Date: {headers.get('Date', 'N/A')}")
        print(f"  Hops: {headers.get('received_analysis', {}).get('hops', 0)}")
        
        # Authentication
        print(f"\n{Fore.CYAN}🔐 Authentication:{Style.RESET_ALL}")
        
        spf = self.results.get('authentication', {}).get('spf', {})
        spf_color = Fore.GREEN if spf.get('valid') else Fore.RED
        print(f"  {spf_color}SPF: {'✓ Valid' if spf.get('valid') else '✗ Invalid'}{Style.RESET_ALL}")
        if spf.get('record'):
            print(f"    Record: {spf['record']}")
        
        dkim = self.results.get('authentication', {}).get('dkim', {})
        dkim_color = Fore.GREEN if dkim.get('valid') else Fore.RED
        print(f"  {dkim_color}DKIM: {'✓ Valid' if dkim.get('valid') else '✗ Invalid'}{Style.RESET_ALL}")
        
        dmarc = self.results.get('authentication', {}).get('dmarc', {})
        dmarc_color = Fore.GREEN if dmarc.get('valid') else Fore.RED
        print(f"  {dmarc_color}DMARC: {'✓ Valid' if dmarc.get('valid') else '✗ Invalid'}{Style.RESET_ALL}")
        if dmarc.get('policy'):
            print(f"    Policy: {dmarc['policy']}")
        
        # Security
        print(f"\n{Fore.CYAN}🛡️ Security:{Style.RESET_ALL}")
        ssl = self.results.get('security', {}).get('ssl', {})
        ssl_color = Fore.GREEN if ssl.get('valid') else Fore.RED
        print(f"  {ssl_color}SSL Certificate: {'✓ Valid' if ssl.get('valid') else '✗ Invalid'}{Style.RESET_ALL}")
        if ssl.get('issuer'):
            print(f"    Issuer: {ssl['issuer']}")
        
        # Phishing patterns
        patterns = self.results.get('analysis', {}).get('phishing_patterns', {})
        if any(patterns.values()):
            print(f"\n{Fore.RED}⚠️ Phishing Indicators:{Style.RESET_ALL}")
            
            if patterns.get('urgency'):
                print(f"  Urgency patterns: {', '.join(patterns['urgency'])}")
            if patterns.get('threats'):
                print(f"  Threats: {', '.join(patterns['threats'])}")
            if patterns.get('requests'):
                print(f"  Suspicious requests: {', '.join(patterns['requests'])}")
        
        # Received path issues
        suspicious = headers.get('received_analysis', {}).get('suspicious', [])
        if suspicious:
            print(f"\n{Fore.RED}⚠️ Received Path Issues:{Style.RESET_ALL}")
            for issue in suspicious:
                print(f"  • {issue}")
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    def save_report(self, output_file):
        """Save report to JSON"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"{Fore.GREEN}[✓] Report saved to {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[✗] Error saving report: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Email Analyzer')
    parser.add_argument('-f', '--file', required=True, help='Email file (.eml) to analyze')
    parser.add_argument('-o', '--output', help='Output report file')
    
    args = parser.parse_args()
    
    print(f"""
    {Fore.CYAN}╔═══════════════════════════════════════╗
    ║        Email Analyzer v1.0            ║
    ║     Deep Email Security Analysis      ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    analyzer = EmailAnalyzer()
    results = analyzer.analyze_email(args.file)
    
    if results:
        analyzer.print_report()
        if args.output:
            analyzer.save_report(args.output)

if __name__ == "__main__":
    main()
