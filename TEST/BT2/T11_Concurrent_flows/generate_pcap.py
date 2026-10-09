from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, wrpcap

folder = Path(__file__).resolve().parent

# protocol, source IP, destination IP, source port, destination port
flows = [
    ("TCP", "10.0.0.1", "10.0.0.2", 12000, 9000),
    ("TCP", "10.0.0.1", "10.0.0.2", 12001, 9000),
    ("UDP", "10.0.0.1", "10.0.0.2", 12000, 9000),
    ("TCP", "10.0.0.1", "10.0.0.3", 12000, 9000),
]

packets = []

# Gửi lượt đi của cả 4 flow, rồi lượt về của cả 4 flow.
for reverse in (False, True):
    for protocol, src, dst, sport, dport in flows:
        if reverse:
            src, dst = dst, src
            sport, dport = dport, sport

        if protocol == "TCP":
            transport = TCP(
                sport=sport,
                dport=dport,
                flags="SA" if reverse else "S",
            )
        else:
            transport = UDP(sport=sport, dport=dport)

        packet = Ether() / IP(src=src, dst=dst) / transport
        packet.time = 1000 + len(packets)
        packets.append(packet)

wrpcap(str(folder / "concurrent_flows.pcap"), packets)
print("Created concurrent_flows.pcap: 4 flows, 8 packets")
