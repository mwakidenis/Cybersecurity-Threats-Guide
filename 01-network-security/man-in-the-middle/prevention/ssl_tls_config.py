#!/usr/bin/env python3
"""
SSL/TLS Secure Configuration
This script demonstrates secure SSL/TLS configuration for various servers
and provides examples of proper encryption implementation.
"""

import ssl
import socket
import hashlib
import hmac
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import argparse

class SecureTLSConfig:
    """
    Secure SSL/TLS Configuration Examples
    """
    
    def __init__(self):
        self.secure_ciphers = [
            'TLS_AES_256_GCM_SHA384',      # TLS 1.3
            'TLS_CHACHA20_POLY1305_SHA256', # TLS 1.3
            'TLS_AES_128_GCM_SHA256',      # TLS 1.3
            'ECDHE-RSA-AES256-GCM-SHA384',  # TLS 1.2
            'ECDHE-ECDSA-AES256-GCM-SHA384',# TLS 1.2
        ]
        
        self.weak_ciphers = [
            'RC4',
            'DES',
            '3DES',
            'MD5',
            'EXPORT',
            'NULL',
            'anon',
        ]
        
    # ==================== SERVER CONFIGURATIONS ====================
    
    def nginx_secure_config(self):
        """Generate secure Nginx SSL configuration"""
        config = """
# /etc/nginx/nginx.conf or /etc/nginx/sites-available/example.com

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com;

    # SSL Certificate paths
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # Modern SSL/TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;

    # DH parameters (generate with: openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048)
    ssl_dhparam /etc/ssl/certs/dhparam.pem;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/ssl/certs/example.com.chain.crt;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    # Session settings
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Root directory and other configurations
    root /var/www/html;
    index index.html index.htm;
}
"""
        return config
    
    def apache_secure_config(self):
        """Generate secure Apache SSL configuration"""
        config = """
# /etc/apache2/sites-available/example.com-ssl.conf

<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/html

    # SSL Engine
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example.com.crt
    SSLCertificateKeyFile /etc/ssl/private/example.com.key
    SSLCertificateChainFile /etc/ssl/certs/example.com.chain.crt

    # Protocol and Cipher configuration
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder on

    # DH parameters
    SSLOpenSSLConfCmd DHParameters "/etc/ssl/certs/dhparam.pem"

    # OCSP Stapling
    SSLUseStapling on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off
    SSLStaplingCache "shmcb:logs/stapling-cache(150000)"

    # Security headers
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff

    # Session cache
    SSLSessionCache shmcb:/var/run/apache2/ssl_scache(512000)
    SSLSessionCacheTimeout 300
</VirtualHost>
"""
        return config
    
    def iis_secure_config(self):
        """Generate secure IIS SSL configuration (PowerShell)"""
        config = """
# PowerShell script for IIS SSL configuration

# Import IIS module
Import-Module WebAdministration

# Set site name
$siteName = "Default Web Site"

# Disable weak protocols
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" `
    -Name "Enabled" -Value 0 -PropertyType "DWord" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" `
    -Name "Enabled" -Value 0 -PropertyType "DWord" -Force

# Enable TLS 1.2 and 1.3
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" `
    -Name "Enabled" -Value 1 -PropertyType "DWord" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" `
    -Name "DisabledByDefault" -Value 0 -PropertyType "DWord" -Force

# Set cipher suite order (PowerShell 5.0+)
$cipherSuites = @(
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
)

$cipherSuitesString = [string]::Join(",", $cipherSuites)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" `
    -Name "Functions" -Value $cipherSuitesString

# Enable HSTS for the site
Set-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders" `
    -Name "." -Value @{name="Strict-Transport-Security";value="max-age=63072000; includeSubDomains; preload"} `
    -PSPath "IIS:\Sites\$siteName"

# Restart IIS
iisreset
"""
        return config
    
    # ==================== PYTHON SSL EXAMPLES ====================
    
    def create_ssl_context_server(self):
        """Create secure SSL context for Python server"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load certificate and key
        context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        
        # Set minimum TLS version
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Set secure ciphers
        context.set_ciphers(':'.join(self.secure_ciphers))
        
        # Enable perfect forward secrecy
        context.set_ecdh_curve('prime256v1')
        
        # Disable session tickets (less secure)
        context.options |= ssl.OP_NO_TICKET
        
        # Enable OCSP stapling (if available)
        context.options |= ssl.OP_NO_COMPRESSION
        
        return context
    
    def create_ssl_context_client(self):
        """Create secure SSL context for Python client"""
        context = ssl.create_default_context()
        
        # Require server certificate verification
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Set minimum TLS version
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Load system certificates (default)
        context.load_default_certs()
        
        return context
    
    def secure_http_server(self):
        """Example of secure HTTPS server"""
        context = self.create_ssl_context_server()
        
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        server_socket.bind(('0.0.0.0', 443))
        server_socket.listen(5)
        
        # Wrap socket with SSL
        secure_socket = context.wrap_socket(server_socket, server_side=True)
        
        print(f"{Fore.GREEN}[✓] Secure HTTPS server listening on port 443{Style.RESET_ALL}")
        return secure_socket
    
    def secure_http_client(self, hostname, port=443):
        """Example of secure HTTPS client"""
        context = self.create_ssl_context_client()
        
        # Create socket and wrap with SSL
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate info
                cert = ssock.getpeercert()
                
                print(f"{Fore.GREEN}[✓] Connected securely to {hostname}{Style.RESET_ALL}")
                print(f"   Cipher: {ssock.cipher()}")
                print(f"   Protocol: {ssock.version()}")
                
                # Send HTTPS request
                request = f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                ssock.send(request.encode())
                
                # Receive response
                response = ssock.recv(4096)
                return response
    
    # ==================== CERTIFICATE GENERATION ====================
    
    def generate_self_signed_cert(self, cert_file="server.crt", key_file="server.key", days=365):
        """
        Generate self-signed certificate (for development only!)
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
        ])
        
        # Build certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=days)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("example.com"),
                x509.DNSName("*.example.com"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Write private key
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Write certificate
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"{Fore.GREEN}[✓] Generated certificate: {cert_file}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Generated key: {key_file}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] For production, use certificates from trusted CA{Style.RESET_ALL}")
    
    # ==================== SECURITY CHECKS ====================
    
    def check_server_ssl(self, hostname, port=443):
        """Check SSL/TLS configuration of a server"""
        print(f"\n{Fore.CYAN}[*] Checking SSL/TLS configuration for {hostname}:{port}{Style.RESET_ALL}")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    # Check protocol version
                    protocol = ssock.version()
                    print(f"   Protocol: {protocol}")
                    
                    # Check cipher
                    cipher = ssock.cipher()
                    print(f"   Cipher: {cipher[0]}")
                    
                    # Check certificate expiration
                    from datetime import datetime
                    not_after = cert['notAfter']
                    expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry - datetime.now()).days
                    
                    if days_left < 30:
                        print(f"{Fore.RED}   [!] Certificate expires in {days_left} days{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}   [✓] Certificate valid for {days_left} days{Style.RESET_ALL}")
                    
                    # Check for weak protocol
                    if protocol in ['TLSv1', 'TLSv1.1']:
                        print(f"{Fore.RED}   [!] Weak protocol detected: {protocol}{Style.RESET_ALL}")
                    
                    # Check for weak cipher
                    for weak in self.weak_ciphers:
                        if weak in cipher[0]:
                            print(f"{Fore.RED}   [!] Weak cipher detected: {cipher[0]}{Style.RESET_ALL}")
                    
                    return True
                    
        except Exception as e:
            print(f"{Fore.RED}[!] Error checking SSL: {e}{Style.RESET_ALL}")
            return False
    
    def generate_hsts_header(self, max_age=63072000, include_subdomains=True, preload=True):
        """Generate HSTS header value"""
        header = f"max-age={max_age}"
        if include_subdomains:
            header += "; includeSubDomains"
        if preload:
            header += "; preload"
        return header

def demonstrate_configs():
    """Demonstrate SSL/TLS configurations"""
    config = SecureTLSConfig()
    
    print(f"""
    {Fore.CYAN}╔═══════════════════════════════════════╗
    ║     SSL/TLS Secure Configuration     ║
    ║       MITM Prevention Examples       ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    # 1. Nginx Configuration
    print(f"\n{Fore.GREEN}1. Nginx SSL Configuration:{Style.RESET_ALL}")
    print(config.nginx_secure_config())
    
    # 2. Apache Configuration
    print(f"\n{Fore.GREEN}2. Apache SSL Configuration:{Style.RESET_ALL}")
    print(config.apache_secure_config())
    
    # 3. HSTS Header
    print(f"\n{Fore.GREEN}3. HSTS Header:{Style.RESET_ALL}")
    print(f"   {config.generate_hsts_header()}")
    
    # 4. Check a server
    print(f"\n{Fore.GREEN}4. Checking example.com SSL:{Style.RESET_ALL}")
    config.check_server_ssl("example.com")
    
    # 5. Generate test certificate (optional)
    print(f"\n{Fore.GREEN}5. Generate development certificate:{Style.RESET_ALL}")
    print("   Use: python3 ssl_tls_config.py --generate-cert")

def main():
    parser = argparse.ArgumentParser(description='SSL/TLS Secure Configuration')
    parser.add_argument('--generate-cert', action='store_true', 
                       help='Generate self-signed certificate for testing')
    parser.add_argument('--check', metavar='HOSTNAME', 
                       help='Check SSL configuration of a server')
    parser.add_argument('--demo', action='store_true', 
                       help='Run demonstration')
    
    args = parser.parse_args()
    
    config = SecureTLSConfig()
    
    if args.generate_cert:
        config.generate_self_signed_cert()
    
    elif args.check:
        config.check_server_ssl(args.check)
    
    elif args.demo:
        demonstrate_configs()
    
    else:
        print("Use --demo for examples or --help for options")

if __name__ == "__main__":
    from colorama import init, Fore, Style
    init(autoreset=True)
    main()
