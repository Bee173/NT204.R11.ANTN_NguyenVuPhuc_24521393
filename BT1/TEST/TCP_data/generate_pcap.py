from pathlib import Path
from scapy.all import Ether, IP, Raw, TCP, wrpcap

output = Path(__file__).parent / "tcp_data.pcap"
payload = b"Hello IDS"

packet = (
    Ether()
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=40000, dport=5000, flags="PA")
    / Raw(payload)
)

wrpcap(str(output), [packet])
print(f"Created: {output}")
print(f"Payload length: {len(payload)} bytes")