"""
NetScope — Packet Parser
------------------------
Receives a raw Scapy packet and returns a structured dict with all fields
needed by the dashboard and logger.  Handles malformed packets gracefully.
"""

from __future__ import annotations

import datetime
from typing import Any

# Scapy imports are deferred inside the function so this module can be
# imported without triggering Scapy's interface-scanning side-effects.
try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.packet import Raw
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


def parse(packet: Any) -> dict | None:
    """
    Parse a raw Scapy packet into a structured dict.

    Returns None if the packet has no IP layer (e.g. ARP, raw Ethernet frames
    we cannot usefully display) or if parsing fails entirely.

    Returned dict keys:
        timestamp (str)   — ISO-8601 capture time
        src_ip    (str)
        dst_ip    (str)
        protocol  (str)   — TCP | UDP | ICMP | DNS | HTTP | Other
        length    (int)   — total packet length in bytes
        info      (str)   — short human-readable summary
    """
    try:
        return _parse_inner(packet)
    except Exception:
        # Never crash the sniffer thread on a malformed packet.
        return None


def _parse_inner(packet: Any) -> dict | None:
    if not _SCAPY_AVAILABLE:
        return None

    # We only visualise IP traffic.
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src_ip: str = ip_layer.src
    dst_ip: str = ip_layer.dst
    length: int = len(packet)
    timestamp: str = datetime.datetime.now().isoformat(timespec="milliseconds")

    protocol, info = _classify(packet, src_ip, dst_ip)

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "length": length,
        "info": info,
    }


def _classify(packet: Any, src_ip: str, dst_ip: str) -> tuple[str, str]:
    """Return (protocol_label, info_string) for the packet."""

    # --- DNS (must come before generic UDP check) ---
    if packet.haslayer(UDP) and packet.haslayer(DNS):
        return _classify_dns(packet, src_ip, dst_ip)

    # --- HTTP (must come before generic TCP check) ---
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        if (tcp.dport == 80 or tcp.sport == 80) and packet.haslayer(Raw):
            return _classify_http(packet, tcp, src_ip, dst_ip)

    # --- ICMP ---
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        type_map = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable",
                    11: "TTL Exceeded"}
        icmp_type = type_map.get(icmp.type, f"Type {icmp.type}")
        return "ICMP", f"ICMP {icmp_type}: {src_ip} → {dst_ip}"

    # --- TCP ---
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = _tcp_flags(tcp.flags)
        return "TCP", f"TCP {src_ip}:{tcp.sport} → {dst_ip}:{tcp.dport} [{flags}]"

    # --- UDP ---
    if packet.haslayer(UDP):
        udp = packet[UDP]
        return "UDP", f"UDP {src_ip}:{udp.sport} → {dst_ip}:{udp.dport}"

    return "Other", f"Non-IP or unknown: {src_ip} → {dst_ip}"


def _classify_dns(packet: Any, src_ip: str, dst_ip: str) -> tuple[str, str]:
    dns = packet[DNS]
    # qr == 0 → query; qr == 1 → response
    if dns.qr == 0 and dns.qdcount > 0 and packet.haslayer(DNSQR):
        try:
            name = packet[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
        except Exception:
            name = "?"
        return "DNS", f"DNS Query: {name}"
    elif dns.qr == 1:
        return "DNS", f"DNS Response from {src_ip}"
    return "DNS", f"DNS {src_ip} → {dst_ip}"


def _classify_http(packet: Any, tcp: Any, src_ip: str, dst_ip: str) -> tuple[str, str]:
    try:
        payload = packet[Raw].load.decode("utf-8", errors="replace")
        first_line = payload.split("\r\n")[0][:120]
        # Detect HTTP request methods
        for method in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            if first_line.startswith(method):
                path = first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else "/"
                return "HTTP", f"HTTP {method} {path}"
        # Detect HTTP responses
        if first_line.startswith("HTTP/"):
            return "HTTP", f"HTTP Response: {first_line}"
    except Exception:
        pass
    return "HTTP", f"HTTP {src_ip}:{tcp.sport} → {dst_ip}:{tcp.dport}"


def _tcp_flags(flags: Any) -> str:
    """Convert Scapy TCP flags field to a readable string like SYN, ACK."""
    flag_map = {
        "F": "FIN", "S": "SYN", "R": "RST",
        "P": "PSH", "A": "ACK", "U": "URG",
    }
    try:
        # Scapy flags can be an int or a FlagValue object
        active = []
        flags_str = str(flags)
        for char, name in flag_map.items():
            if char in flags_str:
                active.append(name)
        return "+".join(active) if active else "NONE"
    except Exception:
        return str(flags)
