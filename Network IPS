from scapy.all import rdpcap, IP, TCP, ICMP, Raw
from collections import defaultdict
import re


connection_counts = defaultdict(int)
multi_port_attempts = defaultdict(set)


suspicious_payloads = [
    re.compile(rb"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),  
    re.compile(rb"(\%3C)|<script>", re.IGNORECASE),              
    re.compile(rb"union.*select", re.IGNORECASE),                  
]


def detect_packet(pkt, idx):
    if not pkt.haslayer(IP):
        return "ALLOW"

    src = pkt[IP].src
    dst = pkt[IP].dst

    # ICMP detection
    if pkt.haslayer(ICMP):
        return "BLOCK: ICMP flood/ping"

    # TCP checks
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags

        key = (src, dst, dport)
        connection_counts[key] += 1

        # SYN flood
        if flags == "S":
            if connection_counts[key] > 3:
                return "BLOCK: SYN flood"

        # NULL scan
        if flags == 0:
            return "BLOCK: NULL scan"

        # FIN scan
        if flags == "F":
            return "BLOCK: FIN scan"

        # Xmas scan
        if flags == "FPU":
            return "BLOCK: Xmas scan"

        # Multi-port scan
        multi_port_attempts[src].add(dport)
        if len(multi_port_attempts[src]) > 10:
            return "BLOCK: multi-port scan"

        # Payload inspection
        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            for pattern in suspicious_payloads:
                if pattern.search(data):
                    return "BLOCK: suspicious payload"

    return "ALLOW"


def run_ips(pcap_file):
    print(f"\n[*] Reading packets from {pcap_file} ...")
    packets = rdpcap(pcap_file)
    print(f"[*] Total packets: {len(packets)}\n")

    for i, pkt in enumerate(packets):
        verdict = detect_packet(pkt, i)
        if pkt.haslayer(IP):
            print(f"[{i}] {pkt[IP].src} -> {pkt[IP].dst} : {verdict}")
        else:
            print(f"[{i}] Non-IP packet : {verdict}")

if __name__ == "__main__":
  
    run_ips("nmap_zombie_scan.pcap")
