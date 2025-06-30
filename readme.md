Network Packet Inspector — A Lightweight Python Packet Sniffer
A minimal yet powerful packet inspection tool built using Python + Scapy, inspired by Wireshark and tcpdump.
Capture live packets on your LAN, filter by protocol (DNS, HTTP, ICMP), log them, and get a real-time visual summary via the terminal.

📌 Features
📡 Live Packet Sniffing using scapy

🎯 Protocol Classification: DNS, HTTP, ICMP, and Others

🧾 CSV Logging with timestamps and packet summaries

🎛️ Protocol Filter (optional)

📊 Live Bar Graph Summary on exit (using plotext)

💻 Single Python File — Easy to run and modify



⚙️ Requirements
Python 3.6+

scapy

plotext

Install dependencies:

pip install scapy plotext

Usage
python3 inspector.py --iface <interface> [--filter <protocol>] [--count <n>]

ARGUMENTS
| Flag       | Description                                     | Default |
| ---------- | ----------------------------------------------- | ------- |
| `--iface`  | Network interface to sniff on                   | `eth0`  |
| `--filter` | Filter by protocol: DNS, HTTP, ICMP, Other, All | `All`   |
| `--count`  | Number of packets to capture (0 = infinite)     | `0`     |

🧠 Inspired By
Wireshark

tcpdump

Scapy Tools

🛡️ For Security Learners & Packet Geeks
Use this tool as a base for:

Writing your own NIDS/packet analysis logic

Detecting anomalies like ping floods, suspicious DNS traffic

Studying how network protocols behave in real-time