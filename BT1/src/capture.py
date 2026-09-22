from pathlib import Path
from scapy.all import PcapReader, sniff

def safe_handle_packet(packet, packet_handler):
    try:
        packet_handler(packet)
    except Exception as e:
        print(f"Error handling packet: {e}")

def capture_live(interface, packet_handler, count=0):
    sniff(iface=interface, prn=lambda packet: safe_handle_packet(packet, packet_handler), count=count, store=False,)

def capture_pcap(file_path, packet_handler):
    pcap_path = Path(file_path)

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    
    try:
        with PcapReader(pcap_path) as packets:
            for packet in packets:
                safe_handle_packet(packet, packet_handler)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
