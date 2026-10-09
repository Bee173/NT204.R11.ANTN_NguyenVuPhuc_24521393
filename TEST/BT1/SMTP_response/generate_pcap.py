from pathlib import Path
from scapy.all import Ether, IP, Raw, TCP, wrpcap

output = Path(__file__).parent / "smtp_response.pcap"
payload = b"250 OK\r\n"

packet = (
    Ether(
        src="66:77:88:99:aa:bb",
        dst="00:11:22:33:44:55",
    )
    / IP(src="10.0.0.2", dst="10.0.0.1")
    / TCP(sport=25, dport=40000, flags="PA", seq=2000, ack=1000)
    / Raw(payload)
)

wrpcap(str(output), [packet])
print(f"Created: {output}")
print("SMTP response: 250 OK")