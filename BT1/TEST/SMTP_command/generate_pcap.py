from pathlib import Path
from scapy.all import Ether, IP, Raw, TCP, wrpcap

output = Path(__file__).parent / "smtp_command.pcap"

commands = [
    b"EHLO client.example.com\r\n",
    b"MAIL FROM:<sender@example.com>\r\n",
    b"RCPT TO:<receiver@example.com>\r\n",
]

packets = []

for index, command in enumerate(commands):
    packet = (
        Ether(
            src="00:11:22:33:44:55",
            dst="66:77:88:99:aa:bb",
        )
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(
            sport=40000,
            dport=25,
            flags="PA",
            seq=1000 + index * 100,
            ack=2000,
        )
        / Raw(command)
    )

    packets.append(packet)

wrpcap(str(output), packets)
print(f"Created: {output}")
print("Commands: EHLO, MAIL FROM, RCPT TO")