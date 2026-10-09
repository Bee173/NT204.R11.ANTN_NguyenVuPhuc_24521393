from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

folder = Path(__file__).resolve().parent
packets = []

for index, body in enumerate([b"hello\xff\xfe", b"hello"]):
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )

    packets.append(
        Ether()
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=12345 + index, flags="PA")
        / Raw(load=payload)
    )

wrpcap(str(folder / "invalid_bytes.pcap"), packets)
print("Created invalid_bytes.pcap")
