#!/usr/bin/env python3
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

def create_sample_pcap(path="examples_sample.pcap"):
    packets = []
    # Simple HTTP GET (plaintext) from 10.0.0.1:12345 -> 10.0.0.2:80
    http_get = (
        Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=12345, dport=80, flags="PA")/
        Raw(load=b"GET / HTTP/1.1\r\nHost: example.local\r\n\r\n")
    )
    packets.append(http_get)

    # Simple UDP packet
    udp_pkt = Ether()/IP(src="10.0.0.3", dst="10.0.0.4")/UDP(sport=5555, dport=53)/Raw(load=b"\x12\x34")
    packets.append(udp_pkt)

    wrpcap(path, packets)
    print("Wrote sample pcap to", path)

if __name__ == "__main__":
    create_sample_pcap()
