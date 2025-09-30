#!/usr/bin/env python3
"""
PktLens - single-file packet sniffer (ready-to-run)

Features
- Live packet capture (scapy/libpcap)
- Streaming pcap writer (no big memory usage)
- JSONL per-packet summaries
- Human-readable stdout summaries
- CLI args: iface, bpf filter, count, duration, pcap output, jsonl output
- Graceful stop on SIGINT/SIGTERM or reached limits

Usage (Linux/macOS):
    sudo python3 pktlens.py --iface lo --duration 15 --pretty --pcap demo.pcap --jsonl demo.jsonl
"""

import argparse
import json
import logging
import logging.handlers
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

from scapy.all import (
    sniff,
    Ether,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    Raw,
)
from scapy.utils import PcapWriter

# ---------- Globals ----------
STOP = False
PACKETS_WRITTEN = 0
START_TIME = None

# ---------- Signal handling ----------
def _on_signal(signum, frame):
    global STOP
    STOP = True
    logging.getLogger().info("Signal received: stopping capture...")

signal.signal(signal.SIGINT, _on_signal)
signal.signal(signal.SIGTERM, _on_signal)

# ---------- Utilities ----------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def tcp_flags_to_str(tcp_layer: TCP) -> str:
    try:
        return str(tcp_layer.flags)
    except Exception:
        return ""

def safe_decode(payload: bytes, max_len: int = 512) -> str:
    try:
        txt = payload.decode("utf-8", errors="replace")
    except Exception:
        txt = str(payload[:max_len])
    return txt if len(txt) <= max_len else txt[:max_len] + "..."

# ---------- Packet parsing ----------
def parse_pkt(pkt) -> Dict[str, Any]:
    """
    Returns a dict summary for JSONL and printing.
    """
    summary = {
        "timestamp": now_iso(),
        "eth_src": None,
        "eth_dst": None,
        "eth_type": None,
        "ip_version": None,
        "ip_src": None,
        "ip_dst": None,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
        "payload_len": 0,
        "http": None,
    }

    # Ethernet
    if pkt.haslayer(Ether):
        eth = pkt.getlayer(Ether)
        summary["eth_src"] = eth.src
        summary["eth_dst"] = eth.dst
        summary["eth_type"] = int(eth.type)

    # IPv4
    if pkt.haslayer(IP):
        ip = pkt.getlayer(IP)
        summary["ip_version"] = 4
        summary["ip_src"] = ip.src
        summary["ip_dst"] = ip.dst
        # TCP
        if pkt.haslayer(TCP):
            summary["protocol"] = "TCP"
            tcp = pkt.getlayer(TCP)
            summary["src_port"] = int(tcp.sport)
            summary["dst_port"] = int(tcp.dport)
            summary["tcp_flags"] = tcp_flags_to_str(tcp)
            if pkt.haslayer(Raw):
                raw = pkt.getlayer(Raw).load
                summary["payload_len"] = len(raw)
                # crude HTTP detection
                try:
                    text = raw.decode("utf-8", errors="ignore")
                    first_line = text.splitlines()[0].strip() if text.splitlines() else ""
                    if first_line.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")):
                        summary["http"] = {"type": "request", "line": first_line}
                    elif first_line.startswith("HTTP/"):
                        summary["http"] = {"type": "response", "line": first_line}
                except Exception:
                    pass
        # UDP
        elif pkt.haslayer(UDP):
            summary["protocol"] = "UDP"
            udp = pkt.getlayer(UDP)
            summary["src_port"] = int(udp.sport)
            summary["dst_port"] = int(udp.dport)
            if pkt.haslayer(Raw):
                raw = pkt.getlayer(Raw).load
                summary["payload_len"] = len(raw)
        elif pkt.haslayer(ICMP):
            summary["protocol"] = "ICMP"
            icmp = pkt.getlayer(ICMP)
            summary["payload_len"] = len(icmp.payload)
        else:
            summary["protocol"] = f"IP_PROTO_{ip.proto}"
    # IPv6
    elif pkt.haslayer(IPv6):
        ip6 = pkt.getlayer(IPv6)
        summary["ip_version"] = 6
        summary["ip_src"] = ip6.src
        summary["ip_dst"] = ip6.dst
        if pkt.haslayer(TCP):
            summary["protocol"] = "TCP"
            tcp = pkt.getlayer(TCP)
            summary["src_port"] = int(tcp.sport)
            summary["dst_port"] = int(tcp.dport)
            summary["tcp_flags"] = tcp_flags_to_str(tcp)
        elif pkt.haslayer(UDP):
            summary["protocol"] = "UDP"
            udp = pkt.getlayer(UDP)
            summary["src_port"] = int(udp.sport)
            summary["dst_port"] = int(udp.dport)
    else:
        # Non-IP frames (ARPs etc.)
        if pkt.haslayer(Raw):
            summary["protocol"] = "RAW"
            summary["payload_len"] = len(pkt.getlayer(Raw).load)
        else:
            summary["protocol"] = pkt.summary()

    return summary

def human_summary(s: Dict[str, Any]) -> str:
    proto = s.get("protocol", "UNKNOWN")
    src = f"{s.get('ip_src') or s.get('eth_src') or '?'}:{s.get('src_port') or ''}".rstrip(":")
    dst = f"{s.get('ip_dst') or s.get('eth_dst') or '?'}:{s.get('dst_port') or ''}".rstrip(":")
    parts = [f"[{s.get('timestamp')}] {proto} {src} -> {dst} len={s.get('payload_len',0)}"]
    if s.get("tcp_flags"):
        parts.append(f"flags={s.get('tcp_flags')}")
    if s.get("http"):
        parts.append(f"HTTP: {s['http'].get('line')}")
    return " | ".join(parts)

# ---------- Main ----------
def main():
    global STOP, PACKETS_WRITTEN, START_TIME

    ap = argparse.ArgumentParser(prog="PktLens", description="PktLens - lightweight packet sniffer")
    ap.add_argument("--iface", "-i", help="Interface to sniff (default: scapy default, use 'lo' for loopback)", default=None)
    ap.add_argument("--filter", "-f", help="BPF filter string (e.g. 'tcp and port 80')", default=None)
    ap.add_argument("--count", "-c", type=int, help="Stop after this many packets written (0 = no limit)", default=0)
    ap.add_argument("--duration", "-t", type=int, help="Duration in seconds to run capture (0 = no limit)", default=0)
    ap.add_argument("--pcap", help="Write streaming pcap to this file (optional)", default=None)
    ap.add_argument("--jsonl", help="Write JSONL packet summaries to this file (optional)", default=None)
    ap.add_argument("--pretty", action="store_true", help="Print human-readable summaries to stdout")
    ap.add_argument("--log", help="Log file (rotating)", default="pktlens.log")
    args = ap.parse_args()

    # Logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    rh = logging.handlers.RotatingFileHandler(args.log, maxBytes=5*1024*1024, backupCount=2)
    rh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(rh)

    # Check privileges early
    try:
        # minimal check: attempt to open a pcap writer if requested
        if args.pcap:
            Path(args.pcap).parent.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        print("Permission error: run this script with root/administrator privileges.", file=sys.stderr)
        sys.exit(2)

    pcap_writer: Optional[PcapWriter] = None
    if args.pcap:
        # appendable pcap writer (streaming)
        pcap_writer = PcapWriter(args.pcap, append=True, sync=True)
        logging.info("PcapWriter opened: %s", args.pcap)

    jsonl_fp = None
    if args.jsonl:
        Path(args.jsonl).parent.mkdir(parents=True, exist_ok=True)
        jsonl_fp = open(args.jsonl, "a", encoding="utf-8")
        logging.info("JSONL output: %s", args.jsonl)

    START_TIME = time.time()
    logging.info("Starting PktLens capture (iface=%s filter=%s count=%s duration=%s)",
                 args.iface, args.filter, args.count, args.duration)

    # callback and stop_filter
    def on_pkt(pkt):
        nonlocal pcap_writer, jsonl_fp, args
        global PACKETS_WRITTEN

        # parse
        s = parse_pkt(pkt)

        # write jsonl
        if jsonl_fp:
            jsonl_fp.write(json.dumps(s, ensure_ascii=False) + "\n")
            jsonl_fp.flush()

        # print human summary
        if args.pretty:
            print(human_summary(s))

        # write to pcap (streaming)
        if pcap_writer:
            try:
                pcap_writer.write(pkt)
            except Exception as e:
                logging.exception("Failed writing packet to pcap: %s", e)

        PACKETS_WRITTEN += 1
        logging.info("Packet captured: proto=%s src=%s dst=%s",
                     s.get("protocol"), s.get("ip_src") or s.get("eth_src"), s.get("ip_dst") or s.get("eth_dst"))

    def stop_filter(pkt):
        # Called for every packet; returning True stops sniff
        if STOP:
            return True
        if args.count and PACKETS_WRITTEN >= args.count:
            logging.info("Reached packet count limit: %d", PACKETS_WRITTEN)
            return True
        if args.duration and (time.time() - START_TIME) >= args.duration:
            logging.info("Reached duration limit: %ds", args.duration)
            return True
        return False

    # Run sniff
    try:
        sniff_kwargs = {
            "prn": on_pkt,
            "store": False,
            "stop_filter": stop_filter,
        }
        if args.iface:
            sniff_kwargs["iface"] = args.iface
        if args.filter:
            sniff_kwargs["filter"] = args.filter

        sniff(**sniff_kwargs)

    except PermissionError:
        print("Permission denied. Run with root/administrator privileges (sudo).", file=sys.stderr)
        logging.exception("Permission denied while sniffing")
        sys.exit(2)
    except Exception as e:
        logging.exception("Exception during sniff: %s", e)
        print("Error during sniff:", e, file=sys.stderr)
    finally:
        if jsonl_fp:
            jsonl_fp.close()
        if pcap_writer:
            pcap_writer.close()
        logging.info("PktLens finished. Packets written: %d", PACKETS_WRITTEN)
        if args.pretty:
            print(f"PktLens finished. Packets captured: {PACKETS_WRITTEN}")

if __name__ == "__main__":
    main()
