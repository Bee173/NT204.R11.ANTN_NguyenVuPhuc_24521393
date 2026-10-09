from pathlib import Path
from scapy.all import Ether, IP, Raw, TCP, wrpcap

output = Path(__file__).parent / "http_post.pcap"
body = b"username=test&pass=1"

payload = (
    b"POST /login HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    b"\r\n" + body
)

packet = (
    Ether()
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=40000, dport=80, flags="PA")
    / Raw(payload)
)

wrpcap(str(output), [packet])
print(f"Created: {output}")
print(f"Body: {body.decode()}")
print(f"Body length: {len(body)} bytes")