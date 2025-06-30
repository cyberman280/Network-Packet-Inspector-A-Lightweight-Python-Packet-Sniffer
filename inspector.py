#!/usr/bin/env python3

# === Imports ===
from scapy.all import sniff, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from collections import defaultdict
import argparse
import csv
import time
import signal
import sys
import plotext as plt

# === Globals ===
protocol_counts = defaultdict(int)
log_file = "packet_log.csv"
running = True

# === Signal Handling (Ctrl+C Graceful Exit) ===
def handle_exit(sig, frame):
    global running
    running = False
    print("\nExiting... saving logs and drawing final graph.")
    draw_graph()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)

# === Classifier ===
def classify_protocol(pkt):
    if pkt.haslayer(ICMP):
        return "ICMP"
    elif pkt.haslayer(DNS):
        return "DNS"
    elif pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse):
        return "HTTP"
    elif pkt.haslayer(TCP) and (pkt[TCP].dport in [80, 443] or pkt[TCP].sport in [80, 443]):
        return "HTTP"
    else:
        return "Other"

# === Live Packet Handler ===
def packet_callback(pkt):
    proto = classify_protocol(pkt)
    if args.filter == "All" or args.filter == proto:
        print(f"[{proto}] {pkt.summary()}")
    protocol_counts[proto] += 1
    writer.writerow([time.strftime('%H:%M:%S'), proto, pkt.summary()])

# === Graph Drawing ===
def draw_graph():
    plt.clear_figure()
    plt.bar(protocol_counts.keys(), protocol_counts.values())
    plt.title("Protocol Packet Count Summary")
    plt.show()

# === Argparse ===
parser = argparse.ArgumentParser(description="Network Packet Inspector")
parser.add_argument('--iface', default='eth0', help="Interface to sniff on (default: eth0)")
parser.add_argument('--filter', choices=["ICMP", "DNS", "HTTP", "Other", "All"], default="All")
parser.add_argument('--count', type=int, default=0, help="Number of packets to capture (0 = infinite)")
args = parser.parse_args()

# === CSV Setup ===
f = open(log_file, "w", newline="")
writer = csv.writer(f)
writer.writerow(["Time", "Protocol", "Summary"])

# === Main ===
print(f"[*] Starting packet capture on {args.iface}, filter={args.filter}... Press Ctrl+C to stop.")
sniff(prn=packet_callback, iface=args.iface, store=False, count=args.count)
f.close()
