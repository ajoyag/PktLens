# PktLens

PktLens is a beginner-friendly packet sniffer written in Python.  
It captures and analyzes network traffic at a low level, helping you understand how data flows across networks.

## ✨ Features
- Capture live packets using Python
- View source/destination IP addresses and ports
- Inspect packet payloads
- Lightweight and easy to use
- Great for learning networking and cybersecurity basics

## ⚡ Requirements
- Python 3.8+
- Administrator/root privileges (needed for raw socket access)
- Works on Linux, macOS, and Windows

## 📦 Installation
Clone the repo:
```bash
git clone https://github.com/your-username/PktLens.git
cd PktLens
Install dependencies:

bash
Copy code
pip install -r requirements.txt
⚙️ Configuration
Make sure you run the script with root/administrator privileges

On Linux/macOS:

bash
Copy code
sudo python pktlens.py
On Windows, run Command Prompt as Administrator

You can also specify:

Network interface to listen on

Packet count limit

Output file (optional, for saving captured packets)

🚀 Usage
Run:

bash
Copy code
python pktlens.py
Example output:

yaml
Copy code
[+] Packet captured:
    Source IP: 192.168.1.5
    Destination IP: 142.250.72.14
    Protocol: TCP
    Payload: b'GET / HTTP/1.1...'
🛠️ Roadmap
Add filtering (capture only TCP/UDP/ICMP)

Save packets in .pcap format

Simple GUI for beginners

📚 Learning Goals
PktLens isn’t about replacing tools like Wireshark.
It’s about learning how sniffers work under the hood, strengthening networking knowledge, and building a strong cybersecurity foundation.

yaml
Copy code

---

## 🔹 What to Configure  

Before running PktLens, you’ll need:  

1. **Python setup**  
   - Make sure you’re running Python 3.8 or later.  
   - Install `scapy` if we extend features later.  

2. **Privileges**  
   - Packet sniffers require raw socket access.  
   - On Linux/macOS: `sudo python pktlens.py`  
   - On Windows: Run PowerShell/CMD as Admin.  

3. **Network interface selection (optional)**  
   - By default, it will sniff the default interface.  
   - You can add an argument like `--iface eth0` to choose a specific one.  

---

Do you want me to also drop the **first working version of pktlens.py** (step-by-step explained, not a messy script) so you can immediately test and commit it?

