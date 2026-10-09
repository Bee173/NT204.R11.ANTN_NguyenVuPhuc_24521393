from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

folder = Path(__file__).resolve().parent

payload = (
    b"GET /search?q=%27%20OR%201%3D1 HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)

packet = (
    Ether()
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=12345, dport=80, flags="PA", seq=1, ack=1)
    / Raw(load=payload)
)

wrpcap(str(folder / "http_url_decode.pcap"), [packet])
print("Created http_url_decode.pcap")