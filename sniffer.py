#!/usr/bin/env python3
"""
sniffer.py
Simple production-friendly packet sniffer using scapy.

Features:
- Capture on an interface (or any)
- BPF filter support
- Save to pcap
- Save JSONL per-packet
- Basic HTTP summary for plaintext HTTP
- Rotating log file
"""

import argparse
import logging
import logging.handlers
import json
import os
import signal
import sys
from datetime import datetime, timezone
from typing import Optional, List

from scapy.all import sniff, wrpcap, Packet
from pktparser import parse_packet, PacketSummary

DEFAULT_LOG = "sniffer.log"

stop_sniffing = False

def signal_handler(sig, frame):
    global stop_sniffing
    stop_sniffing = True
    logging.info("Received stop signal, finishing current capture...")

def setup_logging(logfile: str):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(logfile, maxBytes=5*1024*1024, backupCount=3)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)

def write_jsonl_line(path: str, obj: dict):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, default=str) + "\n")

def main():
    parser = argparse.ArgumentParser(description="Packet sniffer (scapy) - safe lab use only")
    parser.add_argument("-i", "--iface", default=None, help="Interface to sniff (default: scapy default)")
    parser.add_argument("-f", "--filter", default=None, help="BPF filter (e.g. 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-t", "--duration", type=int, default=0, help="Capture duration in seconds (0 = no limit)")
    parser.add_argument("-w", "--write", default=None, help="Write captured packets to pcap file")
    parser.add_argument("-j", "--jsonl", default=None, help="Write packet summaries to JSONL file")
    parser.add_argument("--pretty", action="store_true", help="Print human readable summaries to stdout")
    parser.add_argument("--log", default=DEFAULT_LOG, help="Log file (rotating)")
    parser.add_argument("--promisc", action="store_true", help="Enable promiscuous mode (if supported)")
    args = parser.parse_args()

    # Logging
    setup_logging(args.log)
    logging.info("Starting sniffer")
    logging.info("Args: %s", vars(args))

    # Handle signals
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    packets_collected: List[Packet] = []
    jsonl_path = args.jsonl

    start_time = datetime.now(timezone.utc)

    def scapy_callback(pkt: Packet):
        nonlocal packets_collected
        if stop_sniffing:
            return True  # scapy will stop if callback returns True

        parsed: PacketSummary = parse_packet(pkt)
        # Log JSON line if requested
        if jsonl_path:
            write_jsonl_line(jsonl_path, parsed.to_dict())

        if args.pretty:
            print(parsed.human_summary())

        # Always log summary
        logging.info(parsed.line_summary())

        if args.write:
            packets_collected.append(pkt)

        # If count set and we've collected enough saved packets, stop
        if args.count and len(packets_collected) >= args.count:
            logging.info("Reached packet count limit")
            return True

        # If duration set and time exceeded, stop
        if args.duration:
            now = datetime.now(timezone.utc)
            elapsed = (now - start_time).total_seconds()
            if elapsed >= args.duration:
                logging.info("Reached duration limit")
                return True

        return False

    sniff_kwargs = dict(prn=scapy_callback, store=False)
    if args.filter:
        sniff_kwargs["filter"] = args.filter
    if args.iface:
        sniff_kwargs["iface"] = args.iface
    if args.promisc:
        sniff_kwargs["promisc"] = True
    if args.count:
        # scapy count is total packets seen, but we manage stop via callback to capture written-only count.
        sniff_kwargs["count"] = 0

    try:
        sniff(**sniff_kwargs)
    except PermissionError as e:
        logging.error("Permission error - run with root/admin privileges: %s", e)
        print("Permission error - run with root/admin privileges.", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        logging.exception("Unhandled exception in sniff: %s", e)
        raise

    # Write pcap if requested
    if args.write and packets_collected:
        try:
            wrpcap(args.write, packets_collected)
            logging.info("Saved %d packets to %s", len(packets_collected), args.write)
            print(f"Wrote {len(packets_collected)} packets to {args.write}")
        except Exception as e:
            logging.exception("Failed to write pcap: %s", e)
            print("Failed to write pcap:", e)

    logging.info("Sniffer finished")

if __name__ == "__main__":
    main()




'''
Notes on sniffer.py

Run with root: sudo ./sniffer.py -i lo -c 0 -t 30 --pretty -w capture.pcap -j capture.jsonl

--pretty prints readable summaries to stdout.

--jsonl writes JSON lines for each packet (good for ingestion).

The callback returns True to stop sniffing gracefully when limits reached or signal received.
'''