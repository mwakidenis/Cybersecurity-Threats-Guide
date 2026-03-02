#!/usr/bin/env python3
"""
Certificate Pinning Implementation
This script demonstrates certificate pinning techniques to prevent MITM attacks
by validating server certificates against known pins.
"""

import ssl
import socket
import hashlib
import hmac
import base64
import json
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import argparse
import os
from datetime import datetime
import sys

class CertificatePinner:
    """
    Certificate Pinning Implementation
    
    Pinning associates a host with their expected certificate or public key.
    This prevents MITM attacks using fraudulent certificates.
    """
    
    def __init__(self, pins_file="pins.json"):
        """
        Initialize certificate pinner
        
        Args:
            pins_file: JSON file containing pinned certificates/public keys
        """
        self.pins_file = pins_file
        self.pins = self.load_pins()
        
    def load_pins(self):
        """Load pinned certificates from file"""
        if os.path.exists(self.pins_file):
            with open(self.pins_file, 'r') as f:
                return json.load(f)
        return {}
    
    def save_pins(self):
        """Save pins to file"""
        with open(self.pins_file, 'w') as f:
            json.dump(self.pins, f, indent=2)
    
    # ==================== PIN GENERATION METHODS ====================
    
    def get_certificate(self, hostname, port=443):
        """Retrieve certificate from server"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    return x509.load_der_x509_certificate(der_cert, default_backend())
        except Exception as e:
            print(f"Error getting certificate: {e}")
            return None
    
    def pin_certificate(self, hostname, port=443):
        """Pin a certificate for a hostname"""
        cert = self.get_certificate(hostname, port)
        if not cert:
            return False
        
        # Calculate certificate fingerprint (SHA-256)
        cert_fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        
        # Calculate public key fingerprint
        public_key = cert.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()
        
        # Store pins
        self.pins[hostname] = {
            'certificate_fingerprint': cert_fingerprint,
            'public_key_fingerprint': public_key_fingerprint,
            'subject': str(cert.subject),
            'issuer': str(cert.issuer),
            'not_before': cert.not_valid_before.isoformat(),
            'not_after': cert.not_valid_after.isoformat(),
            'pinned_at': datetime.now().isoformat()
        }
        
        self.save_pins()
        
        print(f"{Fore.GREEN}[✓] Pinned certificate for {hostname}{Style.RESET_ALL}")
        print(f"    Certificate FP: {cert_fingerprint[:20]}...")
        print(f"    Public Key FP: {public_key_fingerprint[:20]}...")
        
        return True
    
    def pin_public_key(self, hostname, public_key_pem):
        """Pin a specific public key"""
        # Parse public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        
        # Calculate fingerprint
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = hashlib.sha256(public_key_bytes).hexdigest()
        
        self.pins[hostname] = {
            'public_key_fingerprint': fingerprint,
            'pinned_at': datetime.now().isoformat()
        }
        
        self.save_pins()
        return True
    
    # ==================== VALIDATION METHODS ====================
    
    def validate_certificate(self, hostname, cert):
        """Validate certificate against pinned values"""
        if hostname not in self.pins:
            print(f"{Fore.YELLOW}[!] No pins found for {hostname}{Style.RESET_ALL}")
            return False
        
        pins = self.pins[hostname]
        
        # Check certificate fingerprint
        cert_fingerprint = hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        
        if 'certificate_fingerprint' in pins:
            if cert_fingerprint != pins['certificate_fingerprint']:
                print(f"{Fore.RED}[!] Certificate fingerprint mismatch for {hostname}{Style.RESET_ALL}")
                print(f"    Expected: {pins['certificate_fingerprint'][:20]}...")
                print(f"    Got: {cert_fingerprint[:20]}...")
                return False
        
        # Check public key fingerprint
        public_key = cert.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()
        
        if 'public_key_fingerprint' in pins:
            if public_key_fingerprint != pins['public_key_fingerprint']:
                print(f"{Fore.RED}[!] Public key fingerprint mismatch for {hostname}{Style.RESET_ALL}")
                print(f"    Expected: {pins['public_key_fingerprint'][:20]}...")
                print(f"    Got: {public_key_fingerprint[:20]}...")
                return False
        
        print(f"{Fore.GREEN}[✓] Certificate validation passed for {hostname}{Style.RESET_ALL}")
        return True
    
    def validate_connection(self, hostname, port=443):
        """Validate SSL connection with pinning"""
        cert = self.get_certificate(hostname, port)
        if not cert:
            return False
        
        return self.validate_certificate(hostname, cert)
    
    # ==================== REQUEST WRAPPERS ====================
    
    def pinned_session(self):
        """Create requests session with certificate pinning"""
        class PinnedSession(requests.Session):
            def __init__(self, pinner):
                super().__init__()
                self.pinner = pinner
            
            def request(self, method, url, **kwargs):
                # Extract hostname
                from urllib.parse import urlparse
                hostname = urlparse(url).hostname
                
                # Validate certificate before request
                if hostname in self.pinner.pins:
                    if not self.pinner.validate_connection(hostname):
                        raise Exception(f"Certificate validation failed for {hostname}")
                
                return super().request(method, url, **kwargs)
        
        return PinnedSession(self)
    
    def pinned_socket(self, hostname, port=443):
        """Create pinned SSL socket"""
        # Validate certificate first
        if not self.validate_connection(hostname, port):
            raise Exception(f"Certificate validation failed for {hostname}")
        
        # Create SSL socket
        context = ssl.create_default_context()
        sock = socket.create_connection((hostname, port))
        ssock = context.wrap_socket(sock, server_hostname=hostname)
        
        return ssock

# ==================== CLIENT EXAMPLES ====================

class PinnedHTTPClient:
    """HTTP client with certificate pinning"""
    
    def __init__(self, pinner):
        self.pinner = pinner
        self.session = pinner.pinned_session()
    
    def get(self, url, **kwargs):
        """Make GET request with pinning"""
        return self.session.get(url, **kwargs)
    
    def post(self, url, data=None, **kwargs):
        """Make POST request with pinning"""
        return self.session.post(url, data=data, **kwargs)

class PinnedSocketClient:
    """Socket client with certificate pinning"""
    
    def __init__(self, pinner):
        self.pinner = pinner
    
    def connect(self, hostname, port=443):
        """Connect with certificate validation"""
        try:
            ssock = self.pinner.pinned_socket(hostname, port)
            return ssock
        except Exception as e:
            print(f"{Fore.RED}[!] Connection failed: {e}{Style.RESET_ALL}")
            return None
    
    def send_request(self, ssock, request):
        """Send HTTP request over pinned socket"""
        if ssock:
            ssock.send(request.encode())
            response = ssock.recv(4096)
            return response
        return None

# ==================== DEMONSTRATION ====================

def demonstrate_pinning():
    """Demonstrate certificate pinning"""
    
    pinner = CertificatePinner("demo_pins.json")
    
    print(f"""
    {Fore.CYAN}╔═══════════════════════════════════════╗
    ║     Certificate Pinning Demo          ║
    ║       MITM Prevention Example         ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    # Example 1: Pin a certificate
    print(f"\n{Fore.GREEN}1. Pinning certificate for example.com{Style.RESET_ALL}")
    pinner.pin_certificate("example.com")
    
    # Example 2: Validate connection
    print(f"\n{Fore.GREEN}2. Validating connection to example.com{Style.RESET_ALL}")
    pinner.validate_connection("example.com")
    
    # Example 3: Simulate MITM attack (with different certificate)
    print(f"\n{Fore.GREEN}3. Simulating MITM attack with different certificate{Style.RESET_ALL}")
    
    # Create a fake certificate (simplified)
    class FakeCertificate:
        def public_bytes(self, encoding):
            return b"fake_certificate"
        
        def public_key(self):
            class FakeKey:
                def public_bytes(self, encoding, format):
                    return b"fake_public_key"
            return FakeKey()
    
    fake_cert = FakeCertificate()
    
    # This should fail
    pinner.validate_certificate("example.com", fake_cert)
    
    # Example 4: Using pinned HTTP client
    print(f"\n{Fore.GREEN}4. Using pinned HTTP client{Style.RESET_ALL}")
    client = PinnedHTTPClient(pinner)
    
    try:
        response = client.get("https://example.com")
        print(f"   Status: {response.status_code}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Example 5: List all pins
    print(f"\n{Fore.GREEN}5. Current pins:{Style.RESET_ALL}")
    for hostname, pin_data in pinner.pins.items():
        print(f"   {hostname}:")
        if 'certificate_fingerprint' in pin_data:
            print(f"     Cert FP: {pin_data['certificate_fingerprint'][:20]}...")
        if 'public_key_fingerprint' in pin_data:
            print(f"     Key FP: {pin_data['public_key_fingerprint'][:20]}...")
        if 'not_after' in pin_data:
            print(f"     Expires: {pin_data['not_after']}")

def main():
    parser = argparse.ArgumentParser(description='Certificate Pinning Tool')
    parser.add_argument('--pin', metavar='HOSTNAME', help='Pin certificate for hostname')
    parser.add_argument('--check', metavar='HOSTNAME', help='Check pinned certificate')
    parser.add_argument('--demo', action='store_true', help='Run demonstration')
    parser.add_argument('--list', action='store_true', help='List all pins')
    
    args = parser.parse_args()
    
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
    
    pinner = CertificatePinner()
    
    if args.pin:
        pinner.pin_certificate(args.pin)
    
    elif args.check:
        if pinner.validate_connection(args.check):
            print(f"{Fore.GREEN}[✓] Certificate validation passed{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[✗] Certificate validation failed{Style.RESET_ALL}")
    
    elif args.list:
        for hostname in pinner.pins:
            print(hostname)
    
    elif args.demo:
        demonstrate_pinning()
    
    else:
        print("Use --demo for demonstration or --help for options")

if __name__ == "__main__":
    main()
