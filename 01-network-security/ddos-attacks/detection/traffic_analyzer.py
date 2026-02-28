#!/usr/bin/env python3
"""
Network Traffic Analyzer
Location: 01-network-security/ddos-attacks/detection/traffic_analyzer.py

This script analyzes network traffic patterns to identify anomalies
and potential DDoS attack signatures.
"""

import pyshark
import pandas as pd
import numpy as np
from collections import defaultdict
import time
import argparse
import json
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class TrafficAnalyzer:
    def __init__(self, interface='eth0', capture_time=60, output_file='traffic_analysis.json'):
        self.interface = interface
        self.capture_time = capture_time
        self.output_file = output_file
        
        # Data storage
        self.packets = []
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {'in': 0, 'out': 0, 'protocols': defaultdict(int)})
        self.port_stats = defaultdict(int)
        self.packet_sizes = []
        self.time_series = []
        
    def capture_traffic(self):
        """Capture live traffic for analysis"""
        print(f"[*] Capturing traffic on {self.interface} for {self.capture_time} seconds...")
        
        try:
            capture = pyshark.LiveCapture(interface=self.interface)
            start_time = time.time()
            
            for packet in capture.sniff_continuously():
                if time.time() - start_time > self.capture_time:
                    break
                    
                self.process_packet(packet)
                
            capture.close()
            
        except Exception as e:
            print(f"[!] Capture error: {e}")
            
    def process_packet(self, packet):
        """Process and analyze individual packet"""
        packet_info = {
            'time': float(packet.sniff_timestamp),
            'length': int(packet.length),
            'protocol': 'Unknown'
        }
        
        # Update time series
        self.time_series.append(packet_info['time'])
        self.packet_sizes.append(packet_info['length'])
        
        # Extract IP information
        if hasattr(packet, 'ip'):
            packet_info['src_ip'] = packet.ip.src
            packet_info['dst_ip'] = packet.ip.dst
            
            # Update IP stats
            self.ip_stats[packet.ip.src]['out'] += 1
            self.ip_stats[packet.ip.dst]['in'] += 1
            
        # Extract protocol information
        if hasattr(packet, 'tcp'):
            packet_info['protocol'] = 'TCP'
            packet_info['src_port'] = packet.tcp.srcport
            packet_info['dst_port'] = packet.tcp.dstport
            self.protocol_stats['TCP'] += 1
            self.port_stats[int(packet.tcp.dstport)] += 1
            self.ip_stats[packet.ip.src]['protocols']['TCP'] += 1
            
        elif hasattr(packet, 'udp'):
            packet_info['protocol'] = 'UDP'
            packet_info['src_port'] = packet.udp.srcport
            packet_info['dst_port'] = packet.udp.dstport
            self.protocol_stats['UDP'] += 1
            self.port_stats[int(packet.udp.dstport)] += 1
            self.ip_stats[packet.ip.src]['protocols']['UDP'] += 1
            
        elif hasattr(packet, 'icmp'):
            packet_info['protocol'] = 'ICMP'
            self.protocol_stats['ICMP'] += 1
            self.ip_stats[packet.ip.src]['protocols']['ICMP'] += 1
            
        elif hasattr(packet, 'arp'):
            packet_info['protocol'] = 'ARP'
            self.protocol_stats['ARP'] += 1
            
        self.packets.append(packet_info)
        
    def analyze_patterns(self):
        """Analyze captured traffic for patterns and anomalies"""
        print("\n[*] Analyzing traffic patterns...")
        
        # Basic statistics
        total_packets = len(self.packets)
        duration = max(self.time_series) - min(self.time_series) if self.time_series else 1
        packet_rate = total_packets / duration if duration > 0 else 0
        
        # Packet size analysis
        avg_size = np.mean(self.packet_sizes) if self.packet_sizes else 0
        std_size = np.std(self.packet_sizes) if self.packet_sizes else 0
        
        # Identify top talkers
        top_senders = sorted(
            [(ip, stats['out']) for ip, stats in self.ip_stats.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        top_receivers = sorted(
            [(ip, stats['in']) for ip, stats in self.ip_stats.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        # Protocol distribution
        protocol_dist = dict(self.protocol_stats)
        
        # Port scan detection
        unique_ports = len(self.port_stats)
        ports_per_ip = self.calculate_ports_per_ip()
        
        # DDoS detection logic
        ddos_indicators = self.detect_ddos_indicators(packet_rate, protocol_dist, ports_per_ip)
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'total_packets': total_packets,
            'capture_duration': duration,
            'packet_rate': packet_rate,
            'packet_size': {
                'average': avg_size,
                'std_dev': std_size,
                'min': min(self.packet_sizes) if self.packet_sizes else 0,
                'max': max(self.packet_sizes) if self.packet_sizes else 0
            },
            'top_senders': top_senders,
            'top_receivers': top_receivers,
            'protocol_distribution': protocol_dist,
            'unique_ports': unique_ports,
            'ddos_indicators': ddos_indicators
        }
        
        return analysis
    
    def calculate_ports_per_ip(self):
        """Calculate number of unique ports per source IP"""
        ip_ports = defaultdict(set)
        
        for packet in self.packets:
            if 'src_ip' in packet and 'dst_port' in packet:
                ip_ports[packet['src_ip']].add(packet['dst_port'])
        
        return {ip: len(ports) for ip, ports in ip_ports.items()}
    
    def detect_ddos_indicators(self, packet_rate, protocol_dist, ports_per_ip):
        """Detect potential DDoS attack indicators"""
        indicators = {
            'high_volume': False,
            'syn_flood': False,
            'udp_flood': False,
            'icmp_flood': False,
            'port_scan': False,
            'amplification': False
        }
        
        # High volume detection
        if packet_rate > 1000:  # More than 1000 pps
            indicators['high_volume'] = True
            
        # SYN flood detection
        tcp_ratio = protocol_dist.get('TCP', 0) / len(self.packets) if len(self.packets) > 0 else 0
        if tcp_ratio > 0.8:  # Mostly TCP
            # Would need to check SYN flags here - simplified
            indicators['syn_flood'] = True
            
        # UDP flood detection
        udp_ratio = protocol_dist.get('UDP', 0) / len(self.packets) if len(self.packets) > 0 else 0
        if udp_ratio > 0.7:  # Mostly UDP
            indicators['udp_flood'] = True
            
        # ICMP flood detection
        icmp_ratio = protocol_dist.get('ICMP', 0) / len(self.packets) if len(self.packets) > 0 else 0
        if icmp_ratio > 0.3:  # Unusually high ICMP
            indicators['icmp_flood'] = True
            
        # Port scan detection
        for ip, ports in ports_per_ip.items():
            if ports > 100:  # Accessing many ports
                indicators['port_scan'] = True
                break
                
        return indicators
    
    def generate_report(self, analysis):
        """Generate and save analysis report"""
        print("\n" + "="*60)
        print("TRAFFIC ANALYSIS REPORT")
        print("="*60)
        
        print(f"\n📊 Basic Statistics:")
        print(f"  Total Packets: {analysis['total_packets']}")
        print(f"  Capture Duration: {analysis['capture_duration']:.2f} seconds")
        print(f"  Average Packet Rate: {analysis['packet_rate']:.2f} pps")
        
        print(f"\n📦 Packet Size Analysis:")
        print(f"  Average: {analysis['packet_size']['average']:.2f} bytes")
        print(f"  Std Dev: {analysis['packet_size']['std_dev']:.2f}")
        print(f"  Range: {analysis['packet_size']['min']} - {analysis['packet_size']['max']} bytes")
        
        print(f"\n🌐 Protocol Distribution:")
        for protocol, count in analysis['protocol_distribution'].items():
            percentage = (count / analysis['total_packets'] * 100) if analysis['total_packets'] > 0 else 0
            print(f"  {protocol}: {count} ({percentage:.1f}%)")
        
        print(f"\n🔝 Top 5 Senders:")
        for ip, count in analysis['top_senders'][:5]:
            print(f"  {ip}: {count} packets")
        
        print(f"\n🎯 DDoS Indicators:")
        for indicator, detected in analysis['ddos_indicators'].items():
            status = "⚠️ DETECTED" if detected else "✅ Normal"
            print(f"  {indicator.replace('_', ' ').title()}: {status}")
        
        # Save to file
        with open(self.output_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        print(f"\n📁 Full report saved to: {self.output_file}")
        
    def run(self):
        """Main execution method"""
        print("""
        ╔═══════════════════════════════════════╗
        ║     Network Traffic Analyzer           ║
        ║         FOR EDUCATIONAL USE ONLY       ║
        ╚═══════════════════════════════════════╝
        """)
        
        # Capture traffic
        self.capture_traffic()
        
        # Analyze patterns
        if self.packets:
            analysis = self.analyze_patterns()
            self.generate_report(analysis)
        else:
            print("[!] No packets captured")

def main():
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    parser.add_argument('-t', '--time', type=int, default=60, help='Capture time in seconds')
    parser.add_argument('-o', '--output', default='traffic_analysis.json', help='Output file')
    
    args = parser.parse_args()
    
    analyzer = TrafficAnalyzer(args.interface, args.time, args.output)
    analyzer.run()

if __name__ == "__main__":
    main()
