from pathlib import Path
from scapy.all import DNS, DNSQR, Ether, IP, UDP, wrpcap

output = Path(__file__).parent / "dns_query.pcap"

packet = (
    Ether()
    / IP(src="10.0.0.1", dst="8.8.8.8")
    / UDP(sport=40000, dport=53)
    / DNS(
        id=0x1234,
        qr=0,
        rd=1,
        qd=DNSQR(qname="example.com", qtype="A"),
    )
)

wrpcap(str(output), [packet])
print(f"Created: {output}")
print("Query: example.com")
print("Query type: A")