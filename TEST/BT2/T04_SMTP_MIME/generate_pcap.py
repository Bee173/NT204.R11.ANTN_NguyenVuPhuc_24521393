import base64
import quopri
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

folder = Path(__file__).resolve().parent
text = "Xin chào Phúc"
raw_body = text.encode("utf-8")

cases = [
    ("base64", base64.b64encode(raw_body)),
    ("quoted-printable", quopri.encodestring(raw_body)),
]

packets = []

for index, (encoding, body) in enumerate(cases):
    payload = (
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Transfer-Encoding: {encoding}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )

    packets.append(
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345 + index, dport=25, flags="PA")
        / Raw(load=payload)
    )

wrpcap(str(folder / "smtp_mime.pcap"), packets)
print("Created smtp_mime.pcap: Base64 and Quoted-Printable")
