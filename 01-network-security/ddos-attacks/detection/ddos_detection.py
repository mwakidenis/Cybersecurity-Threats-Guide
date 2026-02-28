#!/usr/bin/env python3
"""
DDoS Attack Detection Script
Location: 01-network-security/ddos-attacks/detection/ddos_detection.py

This script monitors network traffic and detects potential DDoS attacks
by analyzing packet rates, connection patterns, and traffic anomalies.
"""

import scapy.all as scapy
import time
import threading
from collections import defaultdict, Counter
import argparse
import signal
import sys
import logging
from datetime import datetime
import json

class DDoSDetector:
    def __init__(self, interface="eth0", threshold=1000, window=10, log_file="ddos_alerts.log"):
        """
        Initialize DDoS Detector
        
        Args:
            interface: Network interface to monitor
            threshold: Packets per second threshold for alert
            window: Time window in seconds for analysis
            log_file: File to log alerts
        """
        self.interface = interface
        self.threshold = threshold
        self.window = window
        self.log_file = log_file
        
        # Data structures for traffic analysis
        self.packet_count = 0
        self.ip_counter = defaultdict(int)
        self.syn_counter = defaultdict(int)
        self.udp_counter = defaultdict(int)
        self.icmp_counter = defaultdict(int)
        self.port_counter = defaultdict(int)
        
        # Timing
        self.start_time = time.time()
        self.last_reset = time.time()
        
        # Control flags
        self.running = True
        self.alert_cooldown = {}
        
        # Setup logging
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'alerts_triggered': 0,
            'attack_detected': False,
            'current_attack_type': None
        }
        
    def packet_handler(self, packet):
        """Process each captured packet"""
        if not self.running:
            return
            
        self.packet_count += 1
        self.stats['total_packets'] += 1
        
        # Check if we need to reset counters
        current_time = time.time()
        if current_time - self.last_reset >= self.window:
            self.analyze_traffic()
            self.reset_counters()
            self.last_reset = current_time
        
        # Analyze IP layer
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            
            # Count packets per source IP
            self.ip_counter[ip_src] += 1
            
            # TCP analysis
            if packet.haslayer(scapy.TCP):
                if packet[scapy.TCP].flags == 2:  # SYN flag
                    self.syn_counter[ip_src] += 1
                    self.port_counter[packet[scapy.TCP].dport] += 1
                    
            # UDP analysis
            elif packet.haslayer(scapy.UDP):
                self.udp_counter[ip_src] += 1
                
            # ICMP analysis
            elif packet.haslayer(scapy.ICMP):
                self.icmp_counter[ip_src] += 1
    
    def analyze_traffic(self):
        """Analyze traffic patterns for DDoS indicators"""
        current_time = time.time()
        packet_rate = self.packet_count / self.window
        
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Analysis Window:")
        print(f"  Packets: {self.packet_count} | Rate: {packet_rate:.2f} pps")
        
        # Check if packet rate exceeds threshold
        if packet_rate > self.threshold:
            self.trigger_alert("HIGH_VOLUME", f"Packet rate {packet_rate:.2f} pps exceeds threshold {self.threshold} pps")
        
        # Check for SYN flood
        total_syn = sum(self.syn_counter.values())
        syn_ratio = total_syn / self.packet_count if self.packet_count > 0 else 0
        
        if syn_ratio > 0.5:  # More than 50% SYN packets
            self.trigger_alert("SYN_FLOOD", f"High SYN ratio: {syn_ratio:.2%}")
            
            # Find top SYN attackers
            top_syn = sorted(self.syn_counter.items(), key=lambda x: x[1], reverse=True)[:5]
            print("  Top SYN attackers:")
            for ip, count in top_syn:
                print(f"    {ip}: {count} SYN packets")
        
        # Check for UDP flood
        total_udp = sum(self.udp_counter.values())
        if total_udp > self.threshold * 0.8:  # High UDP traffic
            self.trigger_alert("UDP_FLOOD", f"High UDP traffic: {total_udp} packets")
        
        # Check for ICMP flood
        total_icmp = sum(self.icmp_counter.values())
        if total_icmp > self.threshold * 0.3:  # High ICMP traffic
            self.trigger_alert("ICMP_FLOOD", f"High ICMP traffic: {total_icmp} packets")
        
        # Check for single IP overwhelming
        for ip, count in self.ip_counter.items():
            if count > self.threshold * 0.3:  # Single IP responsible for >30% traffic
                # Check cooldown to avoid alert spam
                if ip not in self.alert_cooldown or (current_time - self.alert_cooldown[ip]) > 60:
                    self.trigger_alert("SINGLE_SOURCE", f"IP {ip} generating {count} packets ({count/self.packet_count:.1%} of traffic)")
                    self.alert_cooldown[ip] = current_time
        
        # Check for port scan behavior (many different ports from same IP)
        if len(self.port_counter) > 100:  # Many ports targeted
            self.trigger_alert("PORT_SCAN", f"Traffic targeting {len(self.port_counter)} different ports")
    
    def trigger_alert(self, alert_type, message):
        """Trigger an alert for detected attack"""
        self.stats['alerts_triggered'] += 1
        self.stats['attack_detected'] = True
        self.stats['current_attack_type'] = alert_type
        
        alert_msg = f"🚨 DDoS ALERT [{alert_type}]: {message}"
        print(f"\n{alert_msg}")
        
        # Log to file
        self.logger.warning(f"{alert_type} - {message}")
        
        # Save to JSON log
        self.save_alert_to_json({
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'message': message,
            'packet_rate': self.packet_count / self.window,
            'total_packets': self.packet_count
        })
    
    def save_alert_to_json(self, alert_data):
        """Save alert to JSON file"""
        try:
            with open('ddos_alerts.json', 'a') as f:
                f.write(json.dumps(alert_data) + '\n')
        except Exception as e:
            print(f"Error saving alert: {e}")
    
    def reset_counters(self):
        """Reset counters for new time window"""
        self.packet_count = 0
        self.ip_counter.clear()
        self.syn_counter.clear()
        self.udp_counter.clear()
        self.icmp_counter.clear()
        self.port_counter.clear()
    
    def start_monitoring(self):
        """Start the packet capture and monitoring"""
        print(f"\n🔍 Starting DDoS Detection on interface {self.interface}")
        print(f"   Threshold: {self.threshold} packets/second")
        print(f"   Analysis window: {self.window} seconds")
        print("   Press Ctrl+C to stop\n")
        
        try:
            # Start packet capture
            scapy.sniff(iface=self.interface, prn=self.packet_handler, store=False)
        except PermissionError:
            print("❌ Permission denied. Run with sudo.")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        print(f"\n📊 Final Statistics:")
        print(f"   Total packets analyzed: {self.stats['total_packets']}")
        print(f"   Alerts triggered: {self.stats['alerts_triggered']}")
        print(f"   Attack detected: {self.stats['attack_detected']}")
        if self.stats['attack_detected']:
            print(f"   Last attack type: {self.stats['current_attack_type']}")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\n🛑 Stopping DDoS Detector...")
    detector.stop()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='DDoS Attack Detection Tool')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface to monitor')
    parser.add_argument('-t', '--threshold', type=int, default=1000, help='Packets per second threshold')
    parser.add_argument('-w', '--window', type=int, default=10, help='Analysis window in seconds')
    parser.add_argument('-l', '--log', default='ddos_alerts.log', help='Log file path')
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════╗
    ║     DDoS Attack Detection Tool        ║
    ║         FOR EDUCATIONAL USE ONLY       ║
    ╚═══════════════════════════════════════╝
    """)
    
    # Check permission
    response = input("[?] Do you have permission to monitor this network? (yes/no): ")
    if response.lower() != 'yes':
        print("[!] Exiting. Only monitor networks you own or have permission to test.")
        return
    
    global detector
    detector = DDoSDetector(args.interface, args.threshold, args.window, args.log)
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start monitoring
    detector.start_monitoring()

if __name__ == "__main__":
    main()
