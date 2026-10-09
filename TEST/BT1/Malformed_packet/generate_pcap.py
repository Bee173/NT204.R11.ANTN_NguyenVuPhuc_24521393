from pathlib import Path
from scapy.utils import RawPcapWriter

output = Path(__file__).parent / "malformed_packet.pcap"

ethernet_header = (
    b"\x66\x77\x88\x99\xaa\xbb"
    b"\x00\x11\x22\x33\x44\x55"
    b"\x08\x00"
)

truncated_ipv4_header = b"\x45\x00\x00\x28"
malformed_packet = ethernet_header + truncated_ipv4_header

writer = RawPcapWriter(str(output), linktype=1)
writer.write(malformed_packet)
writer.close()

print(f"Created: {output}")
print(f"Packet length: {len(malformed_packet)} bytes")
print("The IPv4 header is intentionally truncated")