from pathlib import Path
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, wrpcap

folder = Path(__file__).resolve().parent

query = (
    Ether()
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / UDP(sport=12345, dport=53)
    / DNS(
        id=100,
        qr=0,
        rd=1,
        qd=DNSQR(qname="example.com"),
    )
)

response = (
    Ether()
    / IP(src="10.0.0.2", dst="10.0.0.1")
    / UDP(sport=53, dport=12345)
    / DNS(
        id=100,
        qr=1,
        rd=1,
        ra=1,
        qd=DNSQR(qname="example.com"),
        an=DNSRR(
            rrname="example.com",
            type="A",
            ttl=60,
            rdata="93.184.216.34",
        ),
    )
)

query.time = 1000
response.time = 1001

wrpcap(str(folder / "udp_dns.pcap"), [query, response])
print("Created udp_dns.pcap")
