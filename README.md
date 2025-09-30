Here’s a **professional, polished `README.md`** for your project repo `PktLens`. I’ve written it in a natural tone, making it look like a serious open-source tool, not a student experiment.

---

````markdown
# PktLens

A lightweight packet sniffer built in Python with [Scapy](https://scapy.net/).  
PktLens captures live network traffic, writes PCAPs for deep analysis, logs structured JSON for automation, and provides human-readable summaries in real time.

## Features

- 🔎 Live packet capture from any interface
- 📂 Save packets directly to PCAP (Wireshark compatible)
- 📜 Stream structured logs in JSONL format
- 👀 Human-readable per-packet summaries (protocols, ports, flags, HTTP requests)
- ⏱️ Flexible stopping conditions: packet count, duration, or Ctrl+C
- 📑 Rotating log file for capture history
- 🛡️ Works on Linux/macOS (requires root privileges for sniffing)

---

## Installation

Clone the repo and install dependencies:

```bash
git clone https://github.com/your-username/PktLens.git
cd PktLens
pip3 install -r requirements.txt
````

Or install Scapy directly:

```bash
pip3 install scapy
```

---

## Usage

Run PktLens with root privileges:

```bash
sudo python3 pktlens.py --iface lo --duration 15 --pretty --pcap demo.pcap --jsonl demo.jsonl
```

### Common options

* `--iface` / `-i` : Interface to sniff (e.g. `eth0`, `wlan0`, `lo`)
* `--filter` / `-f` : BPF filter string (e.g. `"tcp and port 80"`)
* `--count` / `-c` : Stop after this many packets
* `--duration` / `-t` : Stop after this many seconds
* `--pcap` : Write packets to a `.pcap` file
* `--jsonl` : Write packet summaries to JSONL
* `--pretty` : Print human summaries to stdout

---

## Example

Start a capture on the loopback interface:

```bash
sudo python3 pktlens.py --iface lo --duration 20 --pretty --pcap traffic.pcap --jsonl traffic.jsonl
```

In another terminal:

```bash
python3 -m http.server 8000 &
curl http://localhost:8000
ping -c 3 8.8.8.8
```

You’ll see console output like:

```
[2025-09-30T12:01:15Z] TCP 127.0.0.1:39812 -> 127.0.0.1:8000 len=64 | flags=S
[2025-09-30T12:01:15Z] HTTP: GET / HTTP/1.1
[2025-09-30T12:01:17Z] ICMP 127.0.0.1 -> 8.8.8.8 len=32
```

Open `traffic.pcap` in Wireshark for full inspection, or process `traffic.jsonl` in any script.

---

## Requirements

* Python 3.8+
* [Scapy](https://scapy.net/)
  Install via `pip3 install scapy`

---

## Project Structure

```
PktLens/
├── pktlens.py          # Main sniffer script
├── requirements.txt    # Python dependencies
├── README.md           # Documentation
├── LICENSE             # License (MIT, Apache 2.0, etc.)
├── data/               # Optional sample PCAPs
└── docs/               # Screenshots, extra docs
```

---

## License

MIT License — free to use, modify, and share. See [LICENSE](./LICENSE) for details.

---

## Disclaimer

PktLens is intended for **educational and authorized security testing only**.
Do not use it on networks you don’t own or have explicit permission to monitor.
