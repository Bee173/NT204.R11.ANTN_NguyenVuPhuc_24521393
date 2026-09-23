from pathlib import Path
from scapy.all import Ether, IP, Raw, UDP, wrpcap

output = Path(__file__).parent / "udp.pcap"
payload = b"Hello UDP"

packet = (
    Ether()
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / UDP(sport=40000, dport=5000)
    / Raw(payload)
)

wrpcap(str(output), [packet])
print(f"Created: {output}")
print(f"Payload length: {len(payload)} bytes")