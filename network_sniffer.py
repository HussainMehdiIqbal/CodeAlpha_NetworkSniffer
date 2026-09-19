#!/usr/bin/env python3
"""
Basic Network Sniffer
======================
A learning project for capturing and analyzing network packets.

Requires:
    pip install scapy

Must be run with elevated privileges (root/sudo on Linux/macOS,
Administrator on Windows) because raw packet capture requires it.

Usage:
    sudo python3 network_sniffer.py                # sniff all traffic
    sudo python3 network_sniffer.py -i eth0         # choose interface
    sudo python3 network_sniffer.py -f "tcp port 80"  # BPF filter
    sudo python3 network_sniffer.py -c 50           # stop after 50 packets
    sudo python3 network_sniffer.py --save capture.pcap  # save to file
"""

import argparse
import datetime
import sys

try:
    from scapy.all import (
        sniff, wrpcap, Raw,
        IP, IPv6, TCP, UDP, ICMP, ARP, Ether
    )
except ImportError:
    print("[!] scapy is not installed. Install it with: pip install scapy")
    sys.exit(1)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

# A handful of well-known ports, just to make output more readable.
WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5353: "mDNS", 8080: "HTTP-ALT",
}


def port_label(port):
    name = WELL_KNOWN_PORTS.get(port)
    return f"{port} ({name})" if name else str(port)


def safe_payload_preview(raw_bytes, max_len=64):
    """
    Render payload bytes as a printable preview without dumping
    raw binary junk into the terminal. Non-printable bytes become '.'.
    """
    if not raw_bytes:
        return ""
    snippet = raw_bytes[:max_len]
    printable = "".join(
        chr(b) if 32 <= b < 127 else "." for b in snippet
    )
    suffix = "..." if len(raw_bytes) > max_len else ""
    return f"{printable}{suffix}"


# ----------------------------------------------------------------------
# Core packet handler
# ----------------------------------------------------------------------

class PacketStats:
    def __init__(self):
        self.total = 0
        self.by_proto = {}

    def record(self, proto_name):
        self.total += 1
        self.by_proto[proto_name] = self.by_proto.get(proto_name, 0) + 1

    def summary(self):
        lines = [f"Total packets captured: {self.total}"]
        for proto, count in sorted(self.by_proto.items(), key=lambda x: -x[1]):
            lines.append(f"  {proto:<8} {count}")
        return "\n".join(lines)


def make_packet_handler(stats: PacketStats, verbose: bool):
    """
    Returns a callback function scapy's sniff() will call for every
    packet it captures.
    """

    def handle_packet(pkt):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Layer 2 info (Ethernet) - useful on a local network
        eth_info = ""
        if pkt.haslayer(Ether):
            eth_info = f"{pkt[Ether].src} -> {pkt[Ether].dst}"

        # ARP is a special case: no IP layer at all
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            op = "who-has" if arp.op == 1 else "is-at" if arp.op == 2 else str(arp.op)
            stats.record("ARP")
            print(f"[{timestamp}] ARP     {arp.psrc:<15} {op:<8} {arp.pdst}")
            return

        # Determine IP layer (v4 or v6)
        ip_layer = None
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]

        if ip_layer is None:
            # Non-IP, non-ARP traffic (e.g. STP, LLDP) - just note it briefly
            stats.record("OTHER")
            if verbose:
                print(f"[{timestamp}] OTHER   {pkt.summary()}")
            return

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Transport layer
        if pkt.haslayer(TCP):
            proto_name = "TCP"
            layer = pkt[TCP]
            src_desc = f"{src_ip}:{port_label(layer.sport)}"
            dst_desc = f"{dst_ip}:{port_label(layer.dport)}"
            flags = str(layer.flags)
            extra = f"flags={flags}"
        elif pkt.haslayer(UDP):
            proto_name = "UDP"
            layer = pkt[UDP]
            src_desc = f"{src_ip}:{port_label(layer.sport)}"
            dst_desc = f"{dst_ip}:{port_label(layer.dport)}"
            extra = ""
        elif pkt.haslayer(ICMP):
            proto_name = "ICMP"
            layer = pkt[ICMP]
            src_desc = src_ip
            dst_desc = dst_ip
            extra = f"type={layer.type} code={layer.code}"
        else:
            proto_name = PROTO_NAMES.get(getattr(ip_layer, "proto", None), "IP-OTHER")
            src_desc = src_ip
            dst_desc = dst_ip
            extra = ""

        stats.record(proto_name)

        line = f"[{timestamp}] {proto_name:<7} {src_desc:<24} -> {dst_desc:<24} {extra}"
        print(line)

        # Show a short printable preview of the payload, if present
        if verbose and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            preview = safe_payload_preview(payload)
            if preview:
                print(f"            payload: {preview}")

    return handle_packet


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="A basic educational network packet sniffer built with scapy."
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface to sniff on (default: scapy's default interface)"
    )
    parser.add_argument(
        "-f", "--filter", default=None,
        help='BPF filter string, e.g. "tcp port 80" or "udp" or "icmp"'
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Number of packets to capture (default: 0 = unlimited, stop with Ctrl+C)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show a printable preview of each packet's payload"
    )
    parser.add_argument(
        "--save", default=None, metavar="FILE.pcap",
        help="Save captured packets to a .pcap file for later analysis (e.g. in Wireshark)"
    )
    args = parser.parse_args()

    stats = PacketStats()
    handler = make_packet_handler(stats, args.verbose)

    print("=" * 70)
    print(" Basic Network Sniffer")
    print(" Interface:", args.interface or "(default)")
    print(" Filter:   ", args.filter or "(none - all traffic)")
    print(" Count:    ", args.count or "unlimited (Ctrl+C to stop)")
    print("=" * 70)
    print(f"{'TIME':<13} {'PROTO':<8} {'SOURCE':<24}    {'DESTINATION':<24} EXTRA")
    print("-" * 70)

    captured_packets = []

    def collecting_handler(pkt):
        handler(pkt)
        if args.save:
            captured_packets.append(pkt)

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=collecting_handler,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("\n[!] Permission denied. Packet capture requires elevated privileges.")
        print("    Try running with 'sudo' (Linux/macOS) or as Administrator (Windows).")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n" + "-" * 70)
        print(stats.summary())
        if args.save and captured_packets:
            wrpcap(args.save, captured_packets)
            print(f"\n[+] Saved {len(captured_packets)} packets to {args.save}")


if __name__ == "__main__":
    main()
