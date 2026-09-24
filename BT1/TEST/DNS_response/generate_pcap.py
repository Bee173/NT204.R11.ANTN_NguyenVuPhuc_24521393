from pathlib import Path
from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP, wrpcap

output = Path(__file__).parent / "dns_response.pcap"

packet = (
    Ether(
        src="66:77:88:99:aa:bb",
        dst="00:11:22:33:44:55",
    )
    / IP(src="8.8.8.8", dst="10.0.0.1")
    / UDP(sport=53, dport=40000)
    / DNS(
        id=0x1234,
        qr=1,
        aa=1,
        ra=1,
        qd=DNSQR(qname="example.com", qtype="A"),
        an=DNSRR(
            rrname="example.com",
            type="A",
            ttl=300,
            rdata="93.184.216.34",
        ),
    )
)

wrpcap(str(output), [packet])
print(f"Created: {output}")
print("Answer: example.com -> 93.184.216.34")