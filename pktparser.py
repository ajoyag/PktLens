# pktparser.py
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from scapy.all import Packet, Ether, IP, IPv6, TCP, UDP, Raw, ICMP

@dataclass
class PacketSummary:
    timestamp: str
    iface: Optional[str]
    eth_src: Optional[str]
    eth_dst: Optional[str]
    eth_type: Optional[int]
    ip_version: Optional[int]
    ip_src: Optional[str]
    ip_dst: Optional[str]
    protocol: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    tcp_flags: Optional[str]
    payload_len: int
    http_info: Optional[Dict[str, Any]]

    def to_dict(self):
        return asdict(self)

    def human_summary(self) -> str:
        parts = []
        t = self.timestamp
        parts.append(f"[{t}] {self.protocol} {self.ip_src}:{self.src_port} -> {self.ip_dst}:{self.dst_port} len={self.payload_len}")
        if self.tcp_flags:
            parts.append(f"flags={self.tcp_flags}")
        if self.http_info:
            # short HTTP summary
            if "request_line" in self.http_info:
                parts.append(f"HTTP REQ: {self.http_info['request_line']}")
            elif "status_line" in self.http_info:
                parts.append(f"HTTP RESP: {self.http_info['status_line']}")
        return " | ".join(parts)

    def line_summary(self) -> str:
        return f"{self.timestamp} proto={self.protocol} src={self.ip_src}:{self.src_port} dst={self.ip_dst}:{self.dst_port} len={self.payload_len}"

def safe_hex(bytes_data: bytes) -> str:
    try:
        return bytes_data.hex()
    except Exception:
        return ""

def parse_packet(pkt: Packet) -> PacketSummary:
    ts = datetime.now(timezone.utc).isoformat()
    iface = getattr(pkt, "sniffed_on", None)
    eth_src = eth_dst = eth_type = None
    ip_version = None
    ip_src = ip_dst = None
    protocol = "UNKNOWN"
    src_port = dst_port = None
    tcp_flags = None
    payload_len = 0
    http_info = None

    # Ethernet layer
    if pkt.haslayer(Ether):
        eth = pkt.getlayer(Ether)
        eth_src = eth.src
        eth_dst = eth.dst
        eth_type = eth.type

    # IPv4
    if pkt.haslayer(IP):
        ip = pkt.getlayer(IP)
        ip_version = 4
        ip_src = ip.src
        ip_dst = ip.dst
        payload_len = len(ip.payload)
        if pkt.haslayer(TCP):
            protocol = "TCP"
            tcp = pkt.getlayer(TCP)
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_flags = str(tcp.flags)
            # check for HTTP in raw payload
            if pkt.haslayer(Raw):
                rawb = pkt.getlayer(Raw).load
                try:
                    text = rawb.decode("utf-8", errors="ignore")
                    # crude HTTP detection
                    lines = text.splitlines()
                    if lines:
                        first = lines[0].strip()
                        if first.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")):
                            http_info = {"request_line": first}
                        elif first.startswith("HTTP/"):
                            # status line
                            http_info = {"status_line": first}
                except Exception:
                    pass
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            udp = pkt.getlayer(UDP)
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            if pkt.haslayer(Raw):
                payload_len = len(pkt.getlayer(Raw).load)
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
            ic = pkt.getlayer(ICMP)
            payload_len = len(ic.payload)
        else:
            # other IP protocol
            payload_len = len(ip.payload)
            protocol = str(ip.proto)
    # IPv6
    elif pkt.haslayer(IPv6):
        ip6 = pkt.getlayer(IPv6)
        ip_version = 6
        ip_src = ip6.src
        ip_dst = ip6.dst
        payload_len = len(ip6.payload)
        if pkt.haslayer(TCP):
            protocol = "TCP"
            tcp = pkt.getlayer(TCP)
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_flags = str(tcp.flags)
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            udp = pkt.getlayer(UDP)
            src_port = int(udp.sport)
            dst_port = int(udp.dport)

    # Raw payload-only frames (no IP)
    elif pkt.haslayer(Raw):
        protocol = "RAW"
        payload_len = len(pkt.getlayer(Raw).load)

    return PacketSummary(
        timestamp=ts,
        iface=iface,
        eth_src=eth_src,
        eth_dst=eth_dst,
        eth_type=eth_type,
        ip_version=ip_version,
        ip_src=ip_src,
        ip_dst=ip_dst,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        payload_len=payload_len or 0,
        http_info=http_info,
    )
