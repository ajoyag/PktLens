# tests/test_parser.py
import os
import tempfile
from scapy.all import rdpcap
from pktparser import parse_packet
from generate_sample_pcap import create_sample_pcap

def test_parse_sample_pcap(tmp_path):
    pcap_path = tmp_path/"sample.pcap"
    # generate sample
    create_sample_pcap(str(pcap_path))
    packets = rdpcap(str(pcap_path))
    assert len(packets) >= 2

    parsed0 = parse_packet(packets[0])
    assert parsed0.protocol == "TCP"
    assert parsed0.ip_src == "10.0.0.1"
    assert parsed0.ip_dst == "10.0.0.2"
    assert parsed0.http_info is not None
    assert "request_line" in parsed0.http_info

    parsed1 = parse_packet(packets[1])
    assert parsed1.protocol == "UDP"
    assert parsed1.ip_src == "10.0.0.3"
