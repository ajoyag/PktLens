#!/usr/bin/env python3
# pktlens.py
# Live packet sniffer with stats, alerts, and recent packets (Bettercap-style)

import argparse
from collections import defaultdict, deque
from datetime import datetime
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

console = Console()

# Store packets and metrics
stats = defaultdict(int)
recent_packets = deque(maxlen=15)
alerts = deque(maxlen=5)
unique_src = set()
unique_dst = set()
start_time = time.time()


# ---------- ALERT RULES ----------
def check_alerts(pkt, window_data, thresholds):
    now = time.time()
    src_ip = pkt[IP].src if IP in pkt else None

    # Clean old entries (sliding window)
    for k, times in list(window_data.items()):
        window_data[k] = [t for t in times if now - t <= thresholds["window"]]

    # DNS NXDOMAIN (rcode=3)
    if pkt.haslayer(DNS) and pkt[DNS].qr == 1 and pkt[DNS].rcode == 3:
        window_data[f"dns_nxdomain:{src_ip}"].append(now)
        if len(window_data[f"dns_nxdomain:{src_ip}"]) >= thresholds["dns_nxdomain"]:
            alerts.append(("[red bold][HIGH][/red bold] DNS NXDOMAIN Spike",
                           f"Source: {src_ip}\nCount: {len(window_data[f'dns_nxdomain:{src_ip}'])} NXDOMAIN in last {thresholds['window']}s\nAction: Check misconfig or suspicious domains"))

    # ICMP flood
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # echo-request
        window_data[f"icmp_flood:{src_ip}"].append(now)
        if len(window_data[f"icmp_flood:{src_ip}"]) >= thresholds["icmp_flood"]:
            alerts.append(("[yellow][MEDIUM][/yellow] ICMP Flood Attempt",
                           f"Source: {src_ip}\nPackets in last {thresholds['window']}s: {len(window_data[f'icmp_flood:{src_ip}'])}\nAction: Investigate DoS attempt"))

    # TCP RST spike
    if pkt.haslayer(TCP) and pkt[TCP].flags == "R":
        window_data[f"tcp_rst:{src_ip}"].append(now)
        if len(window_data[f"tcp_rst:{src_ip}"]) >= thresholds["tcp_rst"]:
            alerts.append(("[yellow][MEDIUM][/yellow] TCP Reset Spike",
                           f"Source: {src_ip}\nCount: {len(window_data[f'tcp_rst:{src_ip}'])}\nAction: Possible scan or broken sessions"))

    # SYN flood detection
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        window_data[f"tcp_syn:{src_ip}"].append(now)
        if len(window_data[f"tcp_syn:{src_ip}"]) >= thresholds["tcp_syn"]:
            alerts.append(("[red bold][HIGH][/red bold] SYN Flood Suspicion",
                           f"Source: {src_ip}\nSYN packets in last {thresholds['window']}s: {len(window_data[f'tcp_syn:{src_ip}'])}\nAction: Check for flood attack"))


# ---------- PACKET HANDLER ----------
def process_packet(pkt, window_data, thresholds):
    global stats, recent_packets, unique_src, unique_dst

    stats["total"] += 1
    proto = "OTHER"

    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        unique_src.add(src)
        unique_dst.add(dst)
    else:
        src, dst = "-", "-"

    if TCP in pkt:
        proto = "TCP"
        stats["tcp"] += 1
    elif UDP in pkt:
        proto = "UDP"
        stats["udp"] += 1
    elif ICMP in pkt:
        proto = "ICMP"
        stats["icmp"] += 1
    else:
        stats["other"] += 1

    # store packet in recent
    recent_packets.appendleft({
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "proto": proto,
        "src": src,
        "dst": dst,
        "len": len(pkt)
    })

    # run alerts
    check_alerts(pkt, window_data, thresholds)


# ---------- RENDERING ----------
def render_layout():
    # Stats Panel
    elapsed = time.time() - start_time
    throughput = (stats["total"] * 64 * 8 / elapsed / 1e6) if elapsed > 0 else 0
    stats_text = Text()
    stats_text.append(f"Total Packets: {stats['total']}\n", style="bold cyan")
    stats_text.append(f"TCP: {stats['tcp']} | UDP: {stats['udp']} | ICMP: {stats['icmp']} | Other: {stats['other']}\n", style="green")
    stats_text.append(f"Throughput: {throughput:.2f} Mbps\n", style="yellow")
    stats_text.append(f"Unique Sources: {len(unique_src)} | Unique Destinations: {len(unique_dst)}", style="magenta")
    stats_panel = Panel(stats_text, title="Stats", border_style="cyan")

    # Alerts Panel
    if alerts:
        alert_text = Text()
        for title, detail in list(alerts)[-3:]:
            alert_text.append(f"{title}\n", style="bold")
            alert_text.append(f"  {detail}\n\n", style="white")
        alerts_panel = Panel(alert_text, title="Alerts", border_style="red")
    else:
        alerts_panel = Panel(Text("No active alerts", style="green"), title="Alerts", border_style="red")

    # Recent Packets Table
    pkt_table = Table(title="Recent Packets", expand=True, box=None, show_lines=True)
    pkt_table.add_column("Time", style="cyan")
    pkt_table.add_column("Proto")
    pkt_table.add_column("Source")
    pkt_table.add_column("Destination")
    pkt_table.add_column("Len", justify="right")

    proto_colors = {"TCP": "blue", "UDP": "cyan", "ICMP": "yellow", "DNS": "green", "TLS": "magenta"}

    for pkt in list(recent_packets):
        proto_style = proto_colors.get(pkt["proto"], "white")
        pkt_table.add_row(pkt["time"],
                          f"[{proto_style}]{pkt['proto']}[/{proto_style}]",
                          pkt["src"], pkt["dst"], str(pkt["len"]))

    return Panel(stats_panel.renderable, title="PktLens", border_style="bright_white"), alerts_panel, pkt_table


# ---------- MAIN ----------
def main():
    parser = argparse.ArgumentParser(
        description="PktLens: Live terminal packet sniffer with stats, alerts, and colored output."
    )
    parser.add_argument("-i", "--iface", required=True, help="Interface to sniff (e.g. eth0, lo)")
    parser.add_argument("-t", "--duration", type=int, default=60, help="Duration in seconds (default: 60)")
    parser.add_argument("--pcap", default=None, help="Optional output pcap file")
    parser.add_argument("--window", type=int, default=60, help="Sliding window for alerts (default: 60s)")
    args = parser.parse_args()

    thresholds = {
        "window": args.window,
        "dns_nxdomain": 10,
        "icmp_flood": 50,
        "tcp_rst": 30,
        "tcp_syn": 80
    }

    window_data = defaultdict(list)

    def pkt_callback(pkt):
        process_packet(pkt, window_data, thresholds)

    with Live(refresh_per_second=4, console=console, screen=True):
        sniff(iface=args.iface, prn=pkt_callback, store=False, timeout=args.duration)

        stats_panel, alerts_panel, pkt_table = render_layout()
        console.print(stats_panel)
        console.print(alerts_panel)
        console.print(pkt_table)


if __name__ == "__main__":
    main()
