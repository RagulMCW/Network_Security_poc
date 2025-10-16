#!/usr/bin/env python3
"""
Network Security Monitor - Packet Capture Analyzer
Professional packet analysis tool for captured network traffic
"""

import sys
import argparse
import os
import glob
from pathlib import Path
from scapy.all import rdpcap, IP, TCP, UDP, ARP, ICMP
from collections import defaultdict
from datetime import datetime
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

def detect_dos_ddos(packets, threshold_pps=100, time_window=1.0):
    """
    Detect potential DoS/DDoS attacks by analyzing packet rates
    
    Args:
        packets: List of captured packets
        threshold_pps: Packets per second threshold to trigger alert (default: 100)
        time_window: Time window in seconds to analyze (default: 1.0)
    
    Returns:
        List of detected DoS/DDoS anomalies
    """
    dos_anomalies = []
    
    if len(packets) < 2:
        return dos_anomalies
    
    # Group packets by source IP and analyze rates
    src_packets = defaultdict(list)
    
    for i, pkt in enumerate(packets):
        if IP in pkt and hasattr(pkt, 'time'):
            src_ip = pkt[IP].src
            src_packets[src_ip].append((pkt.time, i))
    
    # Analyze each source IP for high packet rates
    for src_ip, pkt_list in src_packets.items():
        if len(pkt_list) < threshold_pps * time_window:
            continue
            
        # Sort by timestamp
        pkt_list.sort(key=lambda x: x[0])
        
        # Sliding window analysis
        for i in range(len(pkt_list)):
            window_start_time = pkt_list[i][0]
            window_end_time = window_start_time + time_window
            
            # Count packets in this time window
            packets_in_window = 0
            window_end_idx = i
            
            for j in range(i, len(pkt_list)):
                if pkt_list[j][0] <= window_end_time:
                    packets_in_window += 1
                    window_end_idx = j
                else:
                    break
            
            # Check if rate exceeds threshold
            pps = packets_in_window / time_window
            
            if pps >= threshold_pps:
                dos_anomalies.append({
                    "type": "high_packet_rate",
                    "severity": "high" if pps > threshold_pps * 5 else "medium",
                    "source_ip": src_ip,
                    "packets_per_second": round(pps, 2),
                    "packets_in_window": packets_in_window,
                    "time_window": time_window,
                    "start_packet": pkt_list[i][1],
                    "end_packet": pkt_list[window_end_idx][1],
                    "timestamp": datetime.fromtimestamp(window_start_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                })
                # Skip ahead to avoid duplicate alerts for the same burst
                break
    
    return dos_anomalies

def detect_syn_flood(packets):
    """Detect potential SYN flood attacks"""
    # Track SYN packets by destination and source
    syn_by_target = defaultdict(lambda: defaultdict(int))  # dst_ip -> {src_ip: count}
    syn_ack_counts = defaultdict(int)
    
    for pkt in packets:
        if TCP in pkt and IP in pkt:
            flags = pkt[TCP].flags
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # Count SYN packets (track source)
            if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
                syn_by_target[dst_ip][src_ip] += 1
            # Count SYN-ACK packets
            elif flags & 0x02 and flags & 0x10:  # SYN + ACK
                syn_ack_counts[dst_ip] += 1
    
    syn_flood_anomalies = []
    for dst_ip, src_dict in syn_by_target.items():
        total_syn = sum(src_dict.values())
        syn_ack_count = syn_ack_counts.get(dst_ip, 0)
        
        # If significantly more SYN than SYN-ACK, possible SYN flood
        if total_syn > 50 and total_syn > syn_ack_count * 3:
            # Find the top attacker(s)
            top_attackers = sorted(src_dict.items(), key=lambda x: x[1], reverse=True)[:3]
            attacker_list = [f"{ip} ({count} SYNs)" for ip, count in top_attackers]
            
            syn_flood_anomalies.append({
                "type": "potential_syn_flood",
                "severity": "high",
                "target_ip": dst_ip,
                "attacker_ips": attacker_list,
                "top_attacker": top_attackers[0][0] if top_attackers else "unknown",
                "syn_packets": total_syn,
                "syn_ack_packets": syn_ack_count,
                "ratio": round(total_syn / max(syn_ack_count, 1), 2)
            })
    
    return syn_flood_anomalies

def detect_anomalies(packets):
    """Enhanced anomaly detection including DoS/DDoS detection"""
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
                    "severity": "high",
                    "packet": i,
                    "ip": ip,
                    "original_mac": arp_responses[ip],
                    "new_mac": mac
                })
            else:
                arp_responses[ip] = mac
    
    # Detect DoS/DDoS attacks (high packet rates)
    dos_anomalies = detect_dos_ddos(packets, threshold_pps=100, time_window=1.0)
    anomalies.extend(dos_anomalies)
    
    # Detect SYN flood attacks
    syn_flood_anomalies = detect_syn_flood(packets)
    anomalies.extend(syn_flood_anomalies)
    
    return anomalies

def cleanup_old_captures(captures_dir="captures", keep_count=5, silent=False):
    """
    Delete old pcap files, keeping only the most recent ones
    
    Args:
        captures_dir: Directory containing pcap files
        keep_count: Number of most recent files to keep (default: 5)
        silent: If True, suppress output (default: False)
    
    Returns:
        Tuple of (deleted_count, kept_count)
    """
    try:
        # Find all pcap files
        pcap_pattern = os.path.join(captures_dir, "*.pcap*")
        pcap_files = glob.glob(pcap_pattern)
        
        if len(pcap_files) <= keep_count:
            if not silent:
                print(f"Found {len(pcap_files)} capture files. No cleanup needed.")
            return 0, len(pcap_files)
        
        # Sort by modification time (most recent last)
        pcap_files.sort(key=lambda x: os.path.getmtime(x))
        
        # Files to delete (all except the last keep_count)
        files_to_delete = pcap_files[:-keep_count]
        
        deleted_count = 0
        for file_path in files_to_delete:
            try:
                os.remove(file_path)
                deleted_count += 1
            except Exception as e:
                if not silent:
                    print(f"Warning: Failed to delete {os.path.basename(file_path)}: {e}")
        
        if not silent and deleted_count > 0:
            print(f"Cleaned up {deleted_count} old capture files (kept last {keep_count}).")
        
        return deleted_count, keep_count
        
    except Exception as e:
        if not silent:
            print(f"Error during cleanup: {e}")
        return 0, 0

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
                print()
                
                # Group by severity
                high_severity = [a for a in anomalies if a.get('severity') == 'high']
                medium_severity = [a for a in anomalies if a.get('severity') == 'medium']
                other_anomalies = [a for a in anomalies if 'severity' not in a]
                
                if high_severity:
                    print("    HIGH SEVERITY:")
                    for anomaly in high_severity:
                        print(f"    - {anomaly['type'].upper().replace('_', ' ')}")
                        if anomaly['type'] == 'high_packet_rate':
                            print(f"       ATTACKER IP: {anomaly['source_ip']}")
                            print(f"      Rate: {anomaly['packets_per_second']} packets/second")
                            print(f"      Packets in {anomaly['time_window']}s window: {anomaly['packets_in_window']}")
                            print(f"      Time: {anomaly['timestamp']}")
                        elif anomaly['type'] == 'potential_syn_flood':
                            print(f"       ATTACKER IP: {anomaly['top_attacker']}")
                            print(f"       Target IP: {anomaly['target_ip']}")
                            print(f"      SYN packets: {anomaly['syn_packets']}")
                            print(f"      SYN-ACK packets: {anomaly['syn_ack_packets']}")
                            print(f"      Ratio: {anomaly['ratio']}:1")
                            if len(anomaly['attacker_ips']) > 1:
                                print(f"      All attackers: {', '.join(anomaly['attacker_ips'])}")
                        elif anomaly['type'] == 'potential_arp_spoofing':
                            print(f"       ATTACKER IP: {anomaly['ip']}")
                            print(f"      Original MAC: {anomaly['original_mac']}")
                            print(f"      New MAC: {anomaly['new_mac']}")
                        print()
                
                if medium_severity:
                    print("    MEDIUM SEVERITY:")
                    for anomaly in medium_severity:
                        print(f"    - {anomaly['type'].upper().replace('_', ' ')}")
                        if anomaly['type'] == 'high_packet_rate':
                            print(f"       ATTACKER IP: {anomaly['source_ip']}")
                            print(f"      Rate: {anomaly['packets_per_second']} packets/second")
                        print()
                
                if other_anomalies:
                    for anomaly in other_anomalies:
                        print(f"  {anomaly['type'].upper()}: Packet {anomaly.get('packet', 'N/A')}")
            else:
                print(" No anomalies detected.")
            
            print("=" * 60)
            
    except Exception as e:
        print(f"Error analyzing capture file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Network Security Monitor - Packet Analyzer")
    parser.add_argument("filename", nargs="?", help="PCAP file to analyze")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text",
                       help="Output format (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")
    parser.add_argument("--cleanup", action="store_true",
                       help="Cleanup old pcap files (keep only last 5)")
    parser.add_argument("--keep", type=int, default=5,
                       help="Number of recent files to keep during cleanup (default: 5)")
    parser.add_argument("--captures-dir", default="captures",
                       help="Directory containing pcap files (default: captures)")
    parser.add_argument("--silent", action="store_true",
                       help="Suppress cleanup output messages")
    
    args = parser.parse_args()
    
    # Handle cleanup mode
    if args.cleanup:
        cleanup_old_captures(args.captures_dir, args.keep, args.silent)
        return
    
    # Require filename if not in cleanup mode
    if not args.filename:
        parser.error("filename is required unless using --cleanup")
    
    if args.verbose:
        print(f"Analyzing file: {args.filename}")
        print(f"Output format: {args.format}")
        print()
    
    generate_report(args.filename, args.format)

if __name__ == "__main__":
    main()