#!/usr/bin/env python3
# pktlens.py - PktLens Advanced Packet Sniffer Dashboard

import argparse
import socket
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout

console = Console()

# Cache for hostname resolution
ip_hostname_cache = {}

def resolve_ip(ip):
    if ip in ip_hostname_cache:
        return ip_hostname_cache[ip]
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = None
    ip_hostname_cache[ip] = hostname
    return hostname

# Stats & tracking
stats = {"TCP":0, "UDP":0, "ICMP":0, "Total":0, "Throughput":0}
recent_packets = []
MAX_RECENT = 15  # show last 15 packets
top_talkers = Counter()
top_domains = Counter()
dns_queries = defaultdict(list)
alerts = []

# Thresholds for alerts
NXDOMAIN_THRESHOLD = 10  # NXDOMAIN queries in time window
TIME_WINDOW = 60  # seconds

def packet_handler(pkt):
    proto = "OTHER"
    src = dst = ""
    length = len(pkt)
    
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_name = resolve_ip(src_ip) or src_ip
        dst_name = resolve_ip(dst_ip) or dst_ip
        src = f"{src_ip} ({src_name})"
        dst = f"{dst_ip} ({dst_name})"

        if TCP in pkt:
            proto = "TCP"
            stats["TCP"] += 1
        elif UDP in pkt:
            proto = "UDP"
            stats["UDP"] += 1
            if DNS in pkt:
                proto = "DNS"
                dns_layer = pkt[DNS]
                if hasattr(dns_layer, "qd") and dns_layer.qd is not None:
                    qname = str(dns_layer.qd.qname.decode()).rstrip('.')
                    top_domains[qname] += 1
                    dns_queries[src_ip].append(datetime.now())
                    # check NXDOMAIN alert
                    dns_rcode = pkt[DNS].rcode
                    if dns_rcode == 3:  # NXDOMAIN
                        # remove old timestamps
                        dns_queries[src_ip] = [t for t in dns_queries[src_ip] if (datetime.now()-t).seconds <= TIME_WINDOW]
                        if len(dns_queries[src_ip]) >= NXDOMAIN_THRESHOLD:
                            alerts.append(f"[ALERT][DNS NXDOMAIN] {src_ip} had {len(dns_queries[src_ip])} NXDOMAINs in {TIME_WINDOW}s")
        elif ICMP in pkt:
            proto = "ICMP"
            stats["ICMP"] += 1
    else:
        src = "N/A"
        dst = "N/A"

    stats["Total"] += 1
    stats["Throughput"] += length  # bytes

    top_talkers[src_ip] += 1

    # Recent packets
    recent_packets.append({
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "proto": proto,
        "src": src,
        "dst": dst,
        "len": length
    })
    if len(recent_packets) > MAX_RECENT:
        recent_packets.pop(0)

def render_dashboard():
    throughput_mbps = round(stats["Throughput"]*8/1_000_000, 2)
    # Stats Panel
    top_talkers_list = ", ".join([f"{ip}" for ip, _ in top_talkers.most_common(5)])
    top_domains_list = ", ".join([f"{domain}" for domain, _ in top_domains.most_common(5)])
    stats_panel = Panel(
        f"Total Packets: {stats['Total']}\n"
        f"TCP: {stats['TCP']} | UDP: {stats['UDP']} | ICMP: {stats['ICMP']}\n"
        f"Throughput: {throughput_mbps} Mbps\n"
        f"Top Talkers: {top_talkers_list}\n"
        f"Top Domains: {top_domains_list}",
        title="Stats",
        border_style="green"
    )
    # Alerts Panel
    alerts_panel = Panel("\n".join(alerts[-5:]) if alerts else "No Alerts", title="Alerts", border_style="red")
    # Recent Packets Table
    table = Table(title="Recent Packets", expand=True)
    table.add_column("Time", justify="center")
    table.add_column("Proto", justify="center")
    table.add_column("Source", justify="left")
    table.add_column("Destination", justify="left")
    table.add_column("Len", justify="right")
    for pkt in recent_packets:
        table.add_row(pkt["time"], pkt["proto"], pkt["src"], pkt["dst"], str(pkt["len"]))
    return stats_panel, alerts_panel, table

def main():
    parser = argparse.ArgumentParser(description="PktLens - Advanced Packet Sniffer")
    parser.add_argument("--interface", "-i", default=None, help="Network interface to sniff")
    parser.add_argument("--minimum", action="store_true", help="Minimal mode")
    parser.add_argument("--full", action="store_true", help="Full mode")
    args = parser.parse_args()

    console.print("[bold green]Starting PktLens... Press Ctrl+C to stop[/bold green]")

    try:
        with Live(refresh_per_second=2) as live:
            def update_live(pkt):
                packet_handler(pkt)
                stats_panel, alerts_panel, table = render_dashboard()
                if args.minimum:
                    live.update(stats_panel)
                else:
                    layout = Layout()
                    layout.split_column(
                        Layout(stats_panel, size=8),
                        Layout(alerts_panel, size=6),
                        Layout(table)
                    )
                    live.update(layout)
            sniff(prn=update_live, iface=args.interface, store=False)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Stopping PktLens...[/bold yellow]")

if __name__ == "__main__":
    main()
