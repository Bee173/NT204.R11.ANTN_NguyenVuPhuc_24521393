from pathlib import Path
from scapy.all import Ether, IP, Raw, TCP, wrpcap

output = Path(__file__).parent / "http_response.pcap"
body = b"Hello"

payload = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    b"Server: IDPS-Test\r\n"
    b"\r\n" + body
)

packet = (
    Ether()
    / IP(src="10.0.0.2", dst="10.0.0.1")
    / TCP(sport=80, dport=40000, flags="PA")
    / Raw(payload)
)

wrpcap(str(output), [packet])
print(f"Created: {output}")
print("Status: 200 OK")