from pathlib import Path
from scapy.all import Ether, IP, Raw, TCP, wrpcap

output = Path(__file__).parent / "http_get.pcap"

payload = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: IDPS-Test\r\n"
    b"\r\n"
)

packet = (
    Ether()
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=40000, dport=9000, flags="PA")
    / Raw(payload)
)

wrpcap(str(output), [packet])
print(f"Created: {output}")
print("HTTP method: GET")
print("Destination port: 9000")