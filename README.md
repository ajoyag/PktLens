# PktLens - Packet Sniffer Dashboard

PktLens is a terminal-based, live-updating packet sniffer designed for **network monitoring, analysis, and security research**. It captures packets, displays real-time statistics, recent traffic, top talkers, domains, and generates alerts for suspicious activity.

This project is ideal for cybersecurity enthusiasts, penetration testers, and anyone learning network traffic analysis.

---

## Features

- Live dashboard with **Stats, Alerts, and Recent Packets**.
- Displays **IP addresses along with hostnames/domains**.
- Tracks **protocol distribution, throughput, top talkers, top domains**.
- Generates **dynamic alerts** (e.g., NXDOMAIN spikes, unusual packet behavior).
- Supports **minimal mode** (`--minimum`) for quick stats.
- Supports **full mode** (`--full`) for detailed analysis.
- Terminal-based, clean, and user-friendly interface using **Rich**.

---

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/YourUsername/PktLens.git
cd PktLens
````

### 2. Install Dependencies

Make sure you have Python 3.8+ installed.

```bash
pip install -r requirements.txt
```

`requirements.txt` includes:

```
scapy
rich
```

---

## Usage

### Minimal Mode (Stats Only)

```bash
sudo python3 pktlens.py --minimum -i eth0
```

### Full Mode (Stats + Alerts + Recent Packets)

```bash
sudo python3 pktlens.py --full -i eth0
```

### Help

```bash
python3 pktlens.py -h
```

---

## Sample Output (Full Mode)

```
╔════════════════════════════════════╗
║              Stats                 ║
╠════════════════════════════════════╣
║ Total Packets: 347                 ║
║ TCP: 218 | UDP: 92 | ICMP: 37      ║
║ Throughput: 1.9 Mbps               ║
║ Top Talkers: 192.168.0.101, 192.168.0.102 ║
║ Top Domains: google.com, youtube.com, example.com ║
╚════════════════════════════════════╝

╔════════════════════════════════════════════════════════════╗
║                         Alerts                               ║
╠════════════════════════════════════════════════════════════╣
║ [ALERT][DNS NXDOMAIN] 192.168.0.5 had 12 NXDOMAINs in 60s  ║
║ [ALERT][TCP RST] 192.168.0.10 sent 10 RST packets          ║
╚════════════════════════════════════════════════════════════╝

╔═════════════╦═══════╦════════════════════════════════╦══════════════════════════════╦═════╗
║ Time        ║ Proto ║ Source                         ║ Destination                  ║ Len ║
╠═════════════╬═══════╬════════════════════════════════╬══════════════════════════════╬═════╣
║ 12:01:15.123║ TCP   ║ 192.168.0.101 (Laptop-A)       ║ 142.250.185.14 (google.com)  ║ 64  ║
║ 12:01:15.124║ TLS   ║ 192.168.0.101 (Laptop-A)       ║ 142.250.185.14 (google.com)  ║ 512 ║
║ 12:01:15.200║ HTTP  ║ 10.0.0.12 (Workstation-12)    ║ 127.0.0.1 (localhost)        ║ 128 ║
║ 12:01:16.001║ DNS   ║ 192.168.0.5 (Device-5)        ║ 8.8.8.8 (dns.google)         ║ 48  ║
╚═════════════╩═══════╩════════════════════════════════╩══════════════════════════════╩═════╝
```

> Note: The recent packets table scrolls dynamically as new packets arrive, while stats and alerts remain fixed.

---

## Contributing

1. Fork the repository.
2. Create your feature branch: `git checkout -b feature/MyFeature`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature/MyFeature`
5. Open a Pull Request.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Author

Ajoy A G – Cybersecurity Enthusiast & Developer

LinkedIn: [https://www.linkedin.com/in/ajoyag](https://www.linkedin.com/in/ajoyag)

