#!/usr/bin/env python3
"""
Network Security Monitor - Packet Capture Analyzer
Professional packet analysis tool for captured network traffic
"""

import sys
import argparse
from scapy.all import rdpcap, IP, TCP, UDP, ARP, ICMP
from collections import defaultdict
import json

def analyze_protocols(packets):
    """Analyze protocol distribution"""
    protocols = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}
    
    for pkt in packets:
        if TCP in pkt:
            protocols["TCP"] += 1
        elif UDP in pkt:
            protocols["UDP"] += 1
        elif ICMP in pkt:
            protocols["ICMP"] += 1
        elif ARP in pkt:
            protocols["ARP"] += 1
        else:
            protocols["Other"] += 1
    
    return protocols

def analyze_traffic_patterns(packets):
    """Analyze traffic patterns and top talkers"""
    src_ips = defaultdict(int)
    dst_ips = defaultdict(int)
    conversations = defaultdict(int)
    
    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            src_ips[src] += 1
            dst_ips[dst] += 1
            conversations[f"{src} -> {dst}"] += 1
        elif ARP in pkt:
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst
            conversations[f"{src} -> {dst} (ARP)"] += 1
    
    return {
        "src_ips": dict(sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
        "dst_ips": dict(sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
        "conversations": dict(sorted(conversations.items(), key=lambda x: x[1], reverse=True)[:10])
    }

def detect_anomalies(packets):
    """Simple anomaly detection"""
    anomalies = []
    
    # Check for ARP spoofing
    arp_responses = {}
    for i, pkt in enumerate(packets):
        if ARP in pkt and pkt[ARP].op == 2:  # ARP Reply
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            
            if ip in arp_responses and arp_responses[ip] != mac:
                anomalies.append({
                    "type": "potential_arp_spoofing",
                    "packet": i,
                    "ip": ip,
                    "original_mac": arp_responses[ip],
                    "new_mac": mac
                })
            else:
                arp_responses[ip] = mac
    
    return anomalies

def generate_report(filename, output_format="text"):
    """Generate comprehensive analysis report"""
    try:
        packets = rdpcap(filename)
        total_packets = len(packets)
        
        if total_packets == 0:
            print("No packets found in capture file")
            return
        
        # Perform analysis
        protocols = analyze_protocols(packets)
        traffic = analyze_traffic_patterns(packets)
        anomalies = detect_anomalies(packets)
        
        if output_format == "json":
            report = {
                "summary": {
                    "filename": filename,
                    "total_packets": total_packets,
                    "protocols": protocols
                },
                "traffic_analysis": traffic,
                "anomalies": anomalies
            }
            print(json.dumps(report, indent=2))
            
        else:
            # Text report
            print("=" * 60)
            print(f"NETWORK SECURITY ANALYSIS REPORT")
            print("=" * 60)
            print(f"File: {filename}")
            print(f"Total Packets: {total_packets}")
            print()
            
            print("PROTOCOL DISTRIBUTION:")
            for proto, count in protocols.items():
                if count > 0:
                    percentage = (count / total_packets) * 100
                    print(f"  {proto:>6}: {count:>4} packets ({percentage:>5.1f}%)")
            print()
            
            print("TOP SOURCE IPs:")
            for ip, count in list(traffic["src_ips"].items())[:5]:
                print(f"  {ip:>15}: {count:>3} packets")
            print()
            
            print("TOP DESTINATION IPs:")
            for ip, count in list(traffic["dst_ips"].items())[:5]:
                print(f"  {ip:>15}: {count:>3} packets")
            print()
            
            print("TOP CONVERSATIONS:")
            for conv, count in list(traffic["conversations"].items())[:5]:
                print(f"  {conv}: {count} packets")
            print()
            
            if anomalies:
                print("SECURITY ANOMALIES DETECTED:")
                for anomaly in anomalies:
                    print(f"  {anomaly['type'].upper()}: Packet {anomaly['packet']}")
                    if 'ip' in anomaly:
                        print(f"    IP: {anomaly['ip']}")
                        print(f"    Original MAC: {anomaly['original_mac']}")
                        print(f"    New MAC: {anomaly['new_mac']}")
            else:
                print("No anomalies detected.")
            
            print("=" * 60)
            
    except Exception as e:
        print(f"Error analyzing capture file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Network Security Monitor - Packet Analyzer")
    parser.add_argument("filename", help="PCAP file to analyze")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text",
                       help="Output format (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"Analyzing file: {args.filename}")
        print(f"Output format: {args.format}")
        print()
    
    generate_report(args.filename, args.format)

if __name__ == "__main__":
    main()