from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

folder = Path(__file__).resolve().parent

body = (
    b"name=Nguyen+Vu+Phuc"
    b"&message=%27+OR+1%3D1"
    b"&tag=a&tag=b&empty="
)

payload = (
    b"POST /submit HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    + f"Content-Length: {len(body)}\r\n".encode("ascii")
    + b"\r\n"
    + body
)

packet = (
    Ether()
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=12345, dport=80, flags="PA", seq=1, ack=1)
    / Raw(load=payload)
)

wrpcap(str(folder / "http_form_decode.pcap"), [packet])
print("Created http_form_decode.pcap")
