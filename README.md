# 🛰️ Basic Network Sniffer

A Python-based network packet sniffer built with **Scapy**, developed as part of the **CodeAlpha Cybersecurity Internship**. This tool captures live network traffic and displays useful, human-readable information about each packet — helping you understand how data flows across a network and how core protocols (TCP, UDP, ICMP, ARP) are structured.

---

## 📌 Project Overview

This project captures packets flowing through a network interface in real time and breaks each one down into readable details: source and destination addresses, ports, protocol type, TCP flags, and (optionally) a preview of the payload. It's built for learning — a hands-on way to see what's actually happening under the hood every time a device sends or receives data.

---

## ✨ Features

- 🔍 **Live packet capture** on any available network interface
- 🧩 **Protocol detection** — TCP, UDP, ICMP, and ARP are parsed separately
- 🏷️ **Well-known port labeling** (e.g. `80 (HTTP)`, `443 (HTTPS)`, `53 (DNS)`)
- 🎯 **BPF filtering** — capture only the traffic you care about (`tcp port 80`, `udp`, `icmp`, etc.)
- 📦 **Payload preview** — printable snippet of packet contents (optional, `-v` flag)
- 💾 **Save to `.pcap`** — export captures for deeper analysis in Wireshark
- 📊 **Session summary** — packet counts broken down by protocol when you stop the capture
- ⏱️ **Timestamped output** for every packet

---

## 🛠️ Requirements

- Python 3.7 or higher
- [Scapy](https://scapy.net/)
- **Windows only:** [Npcap](https://npcap.com/) (install with "WinPcap API-compatible mode" checked)
- Administrator / root privileges (required for raw packet capture)

---

## 📥 Installation

1. **Clone this repository**
   ```bash
   git clone https://github.com/<your-username>/CodeAlpha_NetworkSniffer.git
   cd CodeAlpha_NetworkSniffer
   ```

2. **Install dependencies**
   ```bash
   pip install scapy
   ```

3. **Windows users only** — install [Npcap](https://npcap.com/) before running the script.

---

## ▶️ Usage

Run the script with elevated privileges — packet capture requires it.

**Linux / macOS**
```bash
sudo python3 network_sniffer.py
```

**Windows** (PowerShell run *as Administrator*)
```powershell
python network_sniffer.py
```

### Options

| Flag | Description | Example |
|------|-------------|---------|
| `-i`, `--interface` | Choose a specific network interface | `-i eth0` |
| `-f`, `--filter` | Apply a BPF filter to narrow captured traffic | `-f "tcp port 80"` |
| `-c`, `--count` | Stop after capturing N packets | `-c 50` |
| `-v`, `--verbose` | Show a printable preview of each packet's payload | `-v` |
| `--save` | Save captured packets to a `.pcap` file | `--save capture.pcap` |

### Examples

```bash
# Capture all traffic on the default interface
sudo python3 network_sniffer.py

# Capture only HTTP traffic, with payload preview
sudo python3 network_sniffer.py -f "tcp port 80" -v

# Capture 100 packets and save them for Wireshark
sudo python3 network_sniffer.py -c 100 --save capture.pcap

# Watch only ICMP (ping) traffic
sudo python3 network_sniffer.py -f "icmp"
```

Stop the sniffer anytime with **Ctrl+C** — it will print a summary of packets captured, broken down by protocol.

---

## 📸 Sample Output

```
======================================================================
 Basic Network Sniffer
 Interface: (default)
 Filter:    tcp port 80
 Count:     unlimited (Ctrl+C to stop)
======================================================================
TIME          PROTO    SOURCE                      DESTINATION              EXTRA
----------------------------------------------------------------------
[14:32:10.221] TCP     192.168.1.5:52344 (52344)  -> 93.184.216.34:80 (HTTP) flags=S
[14:32:10.245] TCP     93.184.216.34:80 (HTTP)    -> 192.168.1.5:52344       flags=SA
----------------------------------------------------------------------
Total packets captured: 2
  TCP      2
```

---

## ⚠️ Disclaimer

This tool is built **strictly for educational purposes**. Only run it on networks and devices you own or have explicit permission to monitor. Unauthorized packet interception may be illegal in your jurisdiction.

---

## 🎓 About

Built as part of the **CodeAlpha Cybersecurity Internship** — Task: *Basic Network Sniffer*.

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).
