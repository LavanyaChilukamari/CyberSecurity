from scapy.all import sniff, PcapReader, IP, TCP, ICMP
from collections import defaultdict, deque
import time

# Sliding counter (last 10s)
class SlidingCounter:
    def __init__(self, window=10):
        self.window = window
        self.events = deque()
        self.total = 0

    def add(self, now, count=1):
        self.events.append((now, count))
        self.total += count
        self.trim(now)

    def trim(self, now):
        while self.events and now - self.events[0][0] > self.window:
            _, c = self.events.popleft()
            self.total -= c

    def get(self, now):
        self.trim(now)
        return self.total

class SimpleIDS:
    def __init__(self):
        self.icmp_counter = defaultdict(SlidingCounter)
        self.syn_counter = defaultdict(SlidingCounter)
        self.syn_ports = defaultdict(set)
        self.syn_sent = defaultdict(int)
        self.syn_ack = defaultdict(int)

    def alert(self, msg):
        ts = time.strftime("%H:%M:%S", time.localtime())
        print(f"[{ts}] ALERT: {msg}")

    def handle_packet(self, pkt):
        now = time.time()

        if IP not in pkt:
            return
        src = pkt[IP].src

        # ICMP Ping flood detection
        if ICMP in pkt and pkt[ICMP].type == 8:
            self.icmp_counter[src].add(now, 1)
            if self.icmp_counter[src].get(now) > 20:
                self.alert(f"ICMP Flood from {src}")

        # TCP SYN detection
        if TCP in pkt:
            flags = pkt[TCP].flags
            dport = pkt[TCP].dport

            # SYN packet (no ACK yet)
            if flags == "S":
                self.syn_counter[src].add(now, 1)
                self.syn_ports[src].add(dport)
                self.syn_sent[(src, dport)] += 1

                if self.syn_counter[src].get(now) > 30:
                    self.alert(f"High SYN rate from {src}")

                if len(self.syn_ports[src]) > 10:
                    self.alert(f"SYN Scan from {src}, unique ports={len(self.syn_ports[src])}")

            # ACK packet (means handshake completed)
            if "A" in flags and "S" not in flags:
                self.syn_ack[(src, dport)] += 1

    def check_half_open(self):
        """Detect half-open connections (many SYNs but few ACKs)."""
        for (src, dport), syns in self.syn_sent.items():
            acks = self.syn_ack.get((src, dport), 0)
            if syns > 10:
                ratio = (syns - acks) / float(syns)
                if ratio > 0.7:
                    self.alert(f"High half-open ratio from {src}: SYNs={syns}, ACKs={acks}, ratio={ratio:.2f}")

    def run_live(self, iface="eth0"):
        print(f"🚀 Starting IDS on {iface}... Press Ctrl+C to stop.")
        last_check = time.time()

        def pkt_handler(pkt):
            nonlocal last_check
            self.handle_packet(pkt)
            now = time.time()
            if now - last_check > 10:
                self.check_half_open()
                last_check = now

        sniff(iface=iface, prn=pkt_handler, store=False)

    def run_pcap(self, pcap_file):
        print(f"📂 Reading PCAP: {pcap_file}")
        last_check = time.time()
        with PcapReader(pcap_file) as pcap:
            for pkt in pcap:
                self.handle_packet(pkt)
                now = time.time()
                if now - last_check > 10:
                    self.check_half_open()
                    last_check = now

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", help="Live interface to sniff")
    parser.add_argument("--pcap", help="Path to PCAP file")
    args = parser.parse_args()

    ids = SimpleIDS()
    if args.iface:
        ids.run_live(args.iface)
    elif args.pcap:
        ids.run_pcap(args.pcap)
    else:
        print("❌ Please provide --iface or --pcap")
