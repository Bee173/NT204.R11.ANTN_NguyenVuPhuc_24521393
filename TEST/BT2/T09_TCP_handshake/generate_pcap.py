from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

folder = Path(__file__).resolve().parent

packets = [
    Ether()
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=12345, dport=80, flags="S", seq=100),

    Ether()
    / IP(src="10.0.0.2", dst="10.0.0.1")
    / TCP(sport=80, dport=12345, flags="SA", seq=200, ack=101),

    Ether()
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=12345, dport=80, flags="A", seq=101, ack=201),
]

for index, packet in enumerate(packets):
    packet.time = 1000 + index

wrpcap(str(folder / "tcp_handshake.pcap"), packets)
print("Created tcp_handshake.pcap")
