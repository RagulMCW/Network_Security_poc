#!/usr/bin/env python3
"""
Simple PCAP generator - creates realistic network traffic like Wireshark captures
"""

import time
import random
from datetime import datetime
from scapy.all import Ether, ARP, IP, TCP, wrpcap
import os

# Simple configuration
output_dir = "pcap_output"
os.makedirs(output_dir, exist_ok=True)

def create_arp_request(src_ip, dst_ip, src_mac):
    """Create ARP request: Who has dst_ip? Tell src_ip"""
    return Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) / ARP(
        op=1, 
        hwsrc=src_mac, 
        psrc=src_ip, 
        hwdst="00:00:00:00:00:00", 
        pdst=dst_ip
    )

def create_arp_reply(src_ip, dst_ip, src_mac, dst_mac):
    """Create ARP reply: src_ip is at src_mac"""
    return Ether(dst=dst_mac, src=src_mac) / ARP(
        op=2, 
        hwsrc=src_mac, 
        psrc=src_ip, 
        hwdst=dst_mac, 
        pdst=dst_ip
    )

def create_tcp_syn(src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port):
    """Create TCP SYN packet"""
    return Ether(dst=dst_mac, src=src_mac) / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=src_port, 
        dport=dst_port, 
        flags="S", 
        seq=random.randint(1000, 999999)
    )

def generate_simple_traffic():
    """Generate simple network traffic like your example"""
    packets = []
    base_time = time.time()
    
    # Network details
    client_ip = "192.168.1.2"
    server_ip = "192.168.1.1"
    client_mac = "aa:bb:cc:dd:ee:01"
    server_mac = "aa:bb:cc:dd:ee:ff"
    
    # 1. ARP Request: Who has 192.168.1.1? Tell 192.168.1.2
    pkt1 = create_arp_request(client_ip, server_ip, client_mac)
    pkt1.time = base_time + 0.000001
    packets.append(pkt1)
    
    # 2. ARP Reply: 192.168.1.1 is at aa:bb:cc:dd:ee:ff
    pkt2 = create_arp_reply(server_ip, client_ip, server_mac, client_mac)
    pkt2.time = base_time + 0.001234
    packets.append(pkt2)
    
    # 3. TCP SYN
    pkt3 = create_tcp_syn(client_ip, server_ip, client_mac, server_mac, 50000, 80)
    pkt3.time = base_time + 0.002345
    packets.append(pkt3)
    
    # Add more realistic traffic
    current_time = base_time + 0.003000
    
    # Generate 10 more packets with varied traffic
    for i in range(10):
        current_time += random.uniform(0.001, 0.05)
        
        if i % 3 == 0:  # ARP traffic
            if random.choice([True, False]):
                pkt = create_arp_request(f"192.168.1.{random.randint(2,50)}", 
                                       f"192.168.1.{random.randint(2,50)}", 
                                       f"aa:bb:cc:dd:ee:{random.randint(1,99):02x}")
            else:
                pkt = create_arp_reply(f"192.168.1.{random.randint(2,50)}", 
                                     f"192.168.1.{random.randint(2,50)}", 
                                     f"aa:bb:cc:dd:ee:{random.randint(1,99):02x}",
                                     f"aa:bb:cc:dd:ee:{random.randint(1,99):02x}")
        else:  # TCP traffic
            pkt = create_tcp_syn(f"192.168.1.{random.randint(2,50)}", 
                               f"192.168.1.{random.randint(2,50)}", 
                               f"aa:bb:cc:dd:ee:{random.randint(1,99):02x}",
                               f"aa:bb:cc:dd:ee:{random.randint(1,99):02x}",
                               random.randint(1024, 65535), 
                               random.choice([80, 443, 22, 21, 25]))
        
        pkt.time = current_time
        packets.append(pkt)
    
    return packets

def main():
    print("Simple PCAP Generator - Creating realistic network traffic")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            # Generate traffic
            packets = generate_simple_traffic()
            
            # Save to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(output_dir, f"traffic_{timestamp}.pcap")
            wrpcap(filename, packets)
            
            print(f"✓ Generated {len(packets)} packets -> {filename}")
            print("  Sample packets:")
            for i, pkt in enumerate(packets[:3]):
                print(f"    {i+1}: {pkt.summary()}")
            print()
            
            time.sleep(10)  # Generate new file every 10 seconds
            
    except KeyboardInterrupt:
        print("Stopped.")

if __name__ == "__main__":
    main()