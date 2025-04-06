# network_monitor.py
from scapy.all import *
import threading
from utils import log_alert, send_log_file, print_packet_details
from config import SSH_THRESHOLD, SCANNING_THRESHOLD, ICMP_LARGE_PAYLOAD_SIZE, HTTP_CONNECTION_THRESHOLD, TRUSTED_IPS, server_ip, malicious_domains

ssh_activity_counter = {}
scanning_attempts = {}

def detect_suspicious_ssh(packet):
    src = packet[IP].src
    dst = packet[IP].dst
    if TCP in packet and packet[TCP].dport == 22:
        ssh_activity_counter[src] = ssh_activity_counter.get(src, 0) + 1
        if ssh_activity_counter[src] >= SSH_THRESHOLD:
            log_alert("suspicious_ssh", src, f'Suspicious SSH activity detected: {src} -> {dst} on port 22')
            ssh_activity_counter[src] = 0

def packet_analysis(packet):
    src = packet[IP].src if IP in packet else "N/A"
    dst = packet[IP].dst if IP in packet else "N/A"
    proto = packet[IP].proto if IP in packet else "N/A"
    
    # Only log and analyze packets if criteria are met, e.g., suspicious SSH, excessive connections, etc.
    if TCP in packet:
        dst_port = packet[TCP].dport
        if dst_port == 23:
            log_alert("telnet_activity", src, f'Suspicious Telnet activity: {src} -> {dst} on port 23')
        elif dst_port == 22:
            detect_suspicious_ssh(packet)
    if src == server_ip or dst == server_ip or src in TRUSTED_IPS:
        return

    print_packet_details(packet, src, dst, packet[IP].proto if IP in packet else "N/A")

    if TCP in packet:
        dst_port = packet[TCP].dport
        if dst_port == 23:
            log_alert("telnet_activity", src, f'Suspicious Telnet activity: {src} -> {dst} on port 23')
        elif dst_port == 22:
            detect_suspicious_ssh(packet)

    if packet.haslayer(DNS):
        queried_domain = packet[DNS].qd.qname.decode('utf-8')
        if any(domain in queried_domain for domain in malicious_domains):
            log_alert("dns_query", src, f'Suspicious DNS query: {src} queried {queried_domain}')

    if packet.haslayer(ARP):
        arp_src_ip = packet[ARP].psrc
        arp_src_mac = packet[ARP].hwsrc
        scanning_attempts.setdefault(arp_src_ip, {})
        scanning_attempts[arp_src_ip][arp_src_mac] = scanning_attempts[arp_src_ip].get(arp_src_mac, 0) + 1
        if scanning_attempts[arp_src_ip][arp_src_mac] > SCANNING_THRESHOLD:
            log_alert("arp_spoofing", arp_src_ip, f'Potential ARP Spoofing from {arp_src_ip} ({arp_src_mac})')

    if packet.haslayer(ICMP) and len(packet[ICMP].payload) > ICMP_LARGE_PAYLOAD_SIZE:
        log_alert("large_icmp", src, f'Large ICMP packet from {src} to {dst} with size {len(packet[ICMP].payload)} bytes')

    if packet.haslayer(Raw) and TCP in packet:
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if "POST" in payload:
            log_alert("http_post", src, f'Suspicious HTTP POST: {src} -> {dst} | Payload: {payload[:50]}...')
        elif any(keyword in payload for keyword in ['malware', 'exploit', 'hack']):
            log_alert("http_suspicious", src, f'Suspicious HTTP traffic: {src} -> {dst} | Payload: {payload[:50]}...')

    packet_analysis.counter += 1
    if packet_analysis.counter % 10 == 0:
        send_log_file()

packet_analysis.counter = 0

def start_sniffing_on_all_interfaces():
    interfaces = get_if_list()
    print(f'Starting packet sniffing on interfaces: {interfaces}')
    threads = [threading.Thread(target=sniff, kwargs={'iface': interface, 'prn': packet_analysis, 'store': False}) for interface in interfaces]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()