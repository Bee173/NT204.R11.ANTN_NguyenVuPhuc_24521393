from pathlib import Path
from scapy.all import Ether, ICMP, IP, Raw, wrpcap

output = Path(__file__).parent / "unknown_protocol.pcap"

packet = (
    Ether(
        src="00:11:22:33:44:55",
        dst="66:77:88:99:aa:bb",
    )
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / ICMP(type=8, code=0)
    / Raw(b"Unknown protocol test")
)

wrpcap(str(output), [packet])
print(f"Created: {output}")
print("Protocol: ICMP")