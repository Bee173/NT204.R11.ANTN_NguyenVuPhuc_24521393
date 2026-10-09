from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

folder = Path(__file__).resolve().parent
body = b"&lt;script&gt;hello&lt;/script&gt; &amp; &#39;test&#39;"

payload = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    + f"Content-Length: {len(body)}\r\n".encode("ascii")
    + b"\r\n"
    + body
)

packet = (
    Ether()
    / IP(src="10.0.0.2", dst="10.0.0.1")
    / TCP(sport=80, dport=12345, flags="PA", seq=1, ack=1)
    / Raw(load=payload)
)

wrpcap(str(folder / "html_entity.pcap"), [packet])
print("Created html_entity.pcap")
