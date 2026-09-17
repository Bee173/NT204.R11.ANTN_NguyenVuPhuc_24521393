from pathlib import Path
from scapy.all import PcapReader, sniff

def capture_live(interface, packet_handler, count=0):
    sniff(iface=interface, prn=packet_handler, count=count, store=False)

def capture_pcap(file_path, packet_handler):
    if not Path(file_path).is_file():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    with PcapReader(file_path) as packets:
        for packet in packets:
            packet_handler(packet)