
## Detection Scripts

### port_scan_detector.py
#!/usr/bin/env python3
"""
Port Scan Detector
This script detects port scanning activities by monitoring network connections,
analyzing patterns, and identifying suspicious scanning behavior.
"""

import scapy.all as scapy
import threading
import time
import argparse
import os
import sys
import signal
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
import subprocess
import re
from colorama import init, Fore, Style

init(autoreset=True)

class PortScanDetector:
    def __init__(self, interface="eth0", threshold=20, window=60, log_file="scan_alerts.log"):
        """
        Initialize Port Scan Detector
        
        Args:
            interface: Network interface to monitor
            threshold: Number of ports before alert
            window: Time window in seconds
            log_file: File to log alerts
        """
        self.interface = interface
        self.threshold = threshold
        self.window = window
        self.log_file = log_file
        
        # Data structures for tracking
        self.connection_attempts = defaultdict(lambda: deque(maxlen=1000))  # IP -> list of ports
        self.port_count = defaultdict(int)  # IP -> count of ports
        self.scan_patterns = defaultdict(list)  # IP -> scan pattern
        self.blocked_ips = set()
        self.suspicious_ips = set()
        
        # Scan type thresholds
        self.scan_thresholds = {
            'sequential': 10,    # Sequential ports
            'random': 15,        # Random ports
            'sweep': 5,          # Different hosts same port
            'udp': 8,            # UDP scans
            'fin': 5,            # FIN scans
            'xmas': 5,           # XMAS scans
            'null': 5,           # NULL scans
            'ack': 10,           # ACK scans
        }
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'scans_detected': 0,
            'alerts_triggered': 0,
            'blocked_ips': 0,
            'start_time': time.time()
        }
        
        # Control flags
        self.running = True
        
        # Known safe IPs (configure as needed)
        self.whitelist = set(['127.0.0.1', '::1'])
        
    def packet_handler(self, packet):
        """Process captured packets"""
        if not self.running:
            return
        
        self.stats['total_packets'] += 1
        
        # Check for IP layer
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            
            # Skip whitelisted IPs
            if ip_src in self.whitelist:
                return
            
            # TCP packets
            if packet.haslayer(scapy.TCP):
                self.stats['tcp_packets'] += 1
                self.analyze_tcp(packet, ip_src, ip_dst)
            
            # UDP packets
            elif packet.haslayer(scapy.UDP):
                self.stats['udp_packets'] += 1
                self.analyze_udp(packet, ip_src, ip_dst)
            
            # ICMP packets
            elif packet.haslayer(scapy.ICMP):
                self.stats['icmp_packets'] += 1
                self.analyze_icmp(packet, ip_src, ip_dst)
    
    def analyze_tcp(self, packet, ip_src, ip_dst):
        """Analyze TCP packets for scan patterns"""
        tcp = packet[scapy.TCP]
        flags = tcp.flags
        dport = tcp.dport
        
        current_time = time.time()
        
        # Record connection attempt
        self.connection_attempts[ip_src].append({
            'port': dport,
            'time': current_time,
            'flags': flags,
            'type': 'tcp'
        })
        
        # Analyze based on TCP flags
        if flags == 2:  # SYN flag
            self.detect_syn_scan(ip_src, dport)
        elif flags == 1:  # FIN flag
            self.detect_fin_scan(ip_src, dport)
        elif flags == 0:  # NULL scan
            self.detect_null_scan(ip_src, dport)
        elif flags == 41:  # FIN+PSH+URG (XMAS)
            self.detect_xmas_scan(ip_src, dport)
        elif flags == 16:  # ACK flag
            self.detect_ack_scan(ip_src, dport)
        
        # Check for sequential scanning
        self.detect_sequential_scan(ip_src)
        
        # Check for random scanning
        self.detect_random_scan(ip_src)
        
        # Update port count
        self.port_count[ip_src] += 1
        
        # Check if threshold exceeded
        if self.port_count[ip_src] > self.threshold:
            self.trigger_scan_alert(ip_src, "HIGH_VOLUME", 
                                   f"Connected to {self.port_count[ip_src]} ports")
    
    def analyze_udp(self, packet, ip_src, ip_dst):
        """Analyze UDP packets for scan patterns"""
        udp = packet[scapy.UDP]
        dport = udp.dport
        
        # Record UDP attempt
        self.connection_attempts[ip_src].append({
            'port': dport,
            'time': time.time(),
            'type': 'udp'
        })
        
        # Check for UDP scan
        udp_count = len([x for x in self.connection_attempts[ip_src] 
                        if x['type'] == 'udp' and 
                        time.time() - x['time'] < self.window])
        
        if udp_count > self.scan_thresholds['udp']:
            self.trigger_scan_alert(ip_src, "UDP_SCAN", 
                                   f"UDP scan detected: {udp_count} ports")
    
    def analyze_icmp(self, packet, ip_src, ip_dst):
        """Analyze ICMP packets (often used in scan responses)"""
        icmp = packet[scapy.ICMP]
        
        # ICMP unreachable messages can indicate UDP scans
        if icmp.type == 3:  # Destination Unreachable
            self.trigger_scan_alert(ip_src, "ICMP_UNREACHABLE", 
                                   f"ICMP unreachable messages from {ip_src}")
    
    def detect_syn_scan(self, ip_src, dport):
        """Detect SYN scan (half-open)"""
        recent_syn = [x for x in self.connection_attempts[ip_src] 
                     if x.get('flags') == 2 and 
                     time.time() - x['time'] < self.window]
        
        if len(recent_syn) > self.scan_thresholds['sequential']:
            self.trigger_scan_alert(ip_src, "SYN_SCAN", 
                                   f"SYN scan detected: {len(recent_syn)} ports")
    
    def detect_fin_scan(self, ip_src, dport):
        """Detect FIN scan"""
        recent_fin = [x for x in self.connection_attempts[ip_src] 
                     if x.get('flags') == 1 and 
                     time.time() - x['time'] < self.window]
        
        if len(recent_fin) > self.scan_thresholds['fin']:
            self.trigger_scan_alert(ip_src, "FIN_SCAN", 
                                   f"FIN scan detected: {len(recent_fin)} ports")
    
    def detect_null_scan(self, ip_src, dport):
        """Detect NULL scan"""
        recent_null = [x for x in self.connection_attempts[ip_src] 
                      if x.get('flags') == 0 and 
                      time.time() - x['time'] < self.window]
        
        if len(recent_null) > self.scan_thresholds['null']:
            self.trigger_scan_alert(ip_src, "NULL_SCAN", 
                                   f"NULL scan detected: {len(recent_null)} ports")
    
    def detect_xmas_scan(self, ip_src, dport):
        """Detect XMAS scan (FIN+PSH+URG)"""
        recent_xmas = [x for x in self.connection_attempts[ip_src] 
                      if x.get('flags') == 41 and 
                      time.time() - x['time'] < self.window]
        
        if len(recent_xmas) > self.scan_thresholds['xmas']:
            self.trigger_scan_alert(ip_src, "XMAS_SCAN", 
                                   f"XMAS scan detected: {len(recent_xmas)} ports")
    
    def detect_ack_scan(self, ip_src, dport):
        """Detect ACK scan (firewall mapping)"""
        recent_ack = [x for x in self.connection_attempts[ip_src] 
                     if x.get('flags') == 16 and 
                     time.time() - x['time'] < self.window]
        
        if len(recent_ack) > self.scan_thresholds['ack']:
            self.trigger_scan_alert(ip_src, "ACK_SCAN", 
                                   f"ACK scan detected: {len(recent_ack)} ports")
    
    def detect_sequential_scan(self, ip_src):
        """Detect sequential port scanning"""
        recent_ports = [x['port'] for x in self.connection_attempts[ip_src] 
                       if time.time() - x['time'] < self.window]
        
        if len(recent_ports) < 5:
            return
        
        # Check if ports are sequential
        sorted_ports = sorted(recent_ports)
        sequential_count = 1
        max_sequential = 1
        
        for i in range(1, len(sorted_ports)):
            if sorted_ports[i] == sorted_ports[i-1] + 1:
                sequential_count += 1
                max_sequential = max(max_sequential, sequential_count)
            else:
                sequential_count = 1
        
        if max_sequential > self.scan_thresholds['sequential']:
            self.trigger_scan_alert(ip_src, "SEQUENTIAL_SCAN", 
                                   f"Sequential scan detected: {max_sequential} ports in sequence")
    
    def detect_random_scan(self, ip_src):
        """Detect random port scanning"""
        recent_ports = [x['port'] for x in self.connection_attempts[ip_src] 
                       if time.time() - x['time'] < self.window]
        
        if len(recent_ports) < self.scan_thresholds['random']:
            return
        
        # Calculate port distribution
        port_ranges = defaultdict(int)
        for port in recent_ports:
            range_key = port // 1000  # Group by 1000
            port_ranges[range_key] += 1
        
        # If ports are spread across many ranges, it's likely random
        if len(port_ranges) > 3:
            self.trigger_scan_alert(ip_src, "RANDOM_SCAN", 
                                   f"Random scan detected: {len(recent_ports)} ports across {len(port_ranges)} ranges")
    
    def detect_sweep_scan(self):
        """Detect port sweep (same port on multiple hosts)"""
        port_to_ips = defaultdict(set)
        current_time = time.time()
        
        for ip, attempts in self.connection_attempts.items():
            for attempt in attempts:
                if current_time - attempt['time'] < self.window:
                    port_to_ips[attempt['port']].add(ip)
        
        for port, ips in port_to_ips.items():
            if len(ips) > self.scan_thresholds['sweep']:
                self.trigger_scan_alert("MULTIPLE", "PORT_SWEEP", 
                                       f"Port sweep detected on port {port}: {len(ips)} hosts")
    
    def trigger_scan_alert(self, ip_src, scan_type, message):
        """Trigger port scan alert"""
        self.stats['scans_detected'] += 1
        self.stats['alerts_triggered'] += 1
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Add to suspicious IPs
        self.suspicious_ips.add(ip_src)
        
        # Check if we should block
        if len([x for x in self.connection_attempts[ip_src] 
               if time.time() - x['time'] < 300]) > self.threshold * 5:
            self.block_ip(ip_src)
        
        alert = {
            'timestamp': timestamp,
            'type': scan_type,
            'src_ip': ip_src,
            'message': message,
            'port_count': len([x for x in self.connection_attempts[ip_src] 
                              if time.time() - x['time'] < self.window])
        }
        
        # Print alert
        print(f"\n{Fore.RED}🚨 PORT SCAN ALERT [{timestamp}]{Style.RESET_ALL}")
        print(f"{Fore.RED}   Type: {scan_type}{Style.RESET_ALL}")
        print(f"{Fore.RED}   Source IP: {ip_src}{Style.RESET_ALL}")
        print(f"{Fore.RED}   Message: {message}{Style.RESET_ALL}")
        
        # Log to file
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] {scan_type}: {message} (IP: {ip_src})\n")
        
        # Save to JSON
        try:
            with open('scan_alerts.json', 'a') as f:
                f.write(json.dumps(alert) + '\n')
        except:
            pass
    
    def block_ip(self, ip):
        """Block suspicious IP using iptables"""
        if ip in self.blocked_ips or ip in self.whitelist:
            return
        
        try:
            # Add iptables rule
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], 
                         check=True)
            self.blocked_ips.add(ip)
            self.stats['blocked_ips'] += 1
            
            print(f"{Fore.RED}[!] Blocked suspicious IP: {ip}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error blocking IP {ip}: {e}{Style.RESET_ALL}")
    
    def cleanup_old_data(self):
        """Clean up old connection data"""
        while self.running:
            try:
                current_time = time.time()
                
                # Remove old entries
                for ip in list(self.connection_attempts.keys()):
                    self.connection_attempts[ip] = deque(
                        [x for x in self.connection_attempts[ip] 
                         if current_time - x['time'] < 3600],  # Keep 1 hour
                        maxlen=1000
                    )
                    
                    # Remove IP if no recent activity
                    if len(self.connection_attempts[ip]) == 0:
                        del self.connection_attempts[ip]
                        if ip in self.port_count:
                            del self.port_count[ip]
                
                # Check for sweep scans periodically
                self.detect_sweep_scan()
                
                time.sleep(60)  # Clean every minute
                
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error in cleanup: {e}{Style.RESET_ALL}")
                time.sleep(60)
    
    def print_stats(self):
        """Print current statistics"""
        while self.running:
            time.sleep(10)
            os.system('clear' if os.name == 'posix' else 'cls')
            
            print(f"{Fore.CYAN}📊 PORT SCAN DETECTOR STATISTICS{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
            print(f"  Runtime: {int(time.time() - self.stats['start_time'])}s")
            print(f"  Total Packets: {self.stats['total_packets']}")
            print(f"  TCP Packets: {self.stats['tcp_packets']}")
            print(f"  UDP Packets: {self.stats['udp_packets']}")
            print(f"  ICMP Packets: {self.stats['icmp_packets']}")
            print(f"  Scans Detected: {self.stats['scans_detected']}")
            print(f"  Alerts Triggered: {self.stats['alerts_triggered']}")
            print(f"  Blocked IPs: {self.stats['blocked_ips']}")
            print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
            
            # Show recent scanners
            if self.suspicious_ips:
                print(f"\n{Fore.YELLOW}Recent Scanners:{Style.RESET_ALL}")
                for ip in list(self.suspicious_ips)[:5]:
                    count = len([x for x in self.connection_attempts.get(ip, []) 
                               if time.time() - x['time'] < 300])
                    print(f"  {ip}: {count} attempts")
    
    def start_monitoring(self):
        """Start port scan detection"""
        print(f"\n{Fore.CYAN}🚀 Starting Port Scan Detector...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   Interface: {self.interface}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   Threshold: {self.threshold} ports{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   Window: {self.window}s{Style.RESET_ALL}")
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self.cleanup_old_data)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        # Start stats thread
        stats_thread = threading.Thread(target=self.print_stats)
        stats_thread.daemon = True
        stats_thread.start()
        
        print(f"{Fore.GREEN}[*] Monitoring for port scans...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}   Press Ctrl+C to stop{Style.RESET_ALL}\n")
        
        try:
            # Capture packets
            scapy.sniff(iface=self.interface, 
                       prn=self.packet_handler, 
                       store=False)
        except PermissionError:
            print(f"{Fore.RED}[!] Permission denied. Run with sudo.{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
            sys.exit(1)
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        print(f"\n{Fore.GREEN}[*] Detector stopped{Style.RESET_ALL}")

def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    print(f"\n{Fore.YELLOW}[*] Stopping detector...{Style.RESET_ALL}")
    detector.stop()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='Port Scan Detector')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    parser.add_argument('-t', '--threshold', type=int, default=20, 
                       help='Port threshold for alert')
    parser.add_argument('-w', '--window', type=int, default=60, 
                       help='Time window in seconds')
    parser.add_argument('-l', '--log', default='scan_alerts.log', help='Log file')
    parser.add_argument('--whitelist', help='Whitelist file with IPs')
    
    args = parser.parse_args()
    
    print(f"""
    {Fore.CYAN}╔═══════════════════════════════════════╗
    ║        Port Scan Detector            ║
    ║      FOR EDUCATIONAL USE ONLY        ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    # Check root privileges
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] This script requires root privileges.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Please run with: sudo python3 port_scan_detector.py{Style.RESET_ALL}")
        sys.exit(1)
    
    global detector
    detector = PortScanDetector(args.interface, args.threshold, 
                                args.window, args.log)
    
    # Load whitelist if provided
    if args.whitelist:
        try:
            with open(args.whitelist, 'r') as f:
                detector.whitelist.update([line.strip() for line in f])
        except:
            print(f"{Fore.YELLOW}[!] Could not load whitelist{Style.RESET_ALL}")
    
    # Set signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start monitoring
    detector.start_monitoring()

if __name__ == "__main__":
    main()
