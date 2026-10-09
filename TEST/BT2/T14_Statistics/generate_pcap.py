from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

folder = Path(__file__).resolve().parent

# reverse, flags, sequence, acknowledgment, payload, timestamp
cases = [
    (False, "S",  100, 0,   b"",       1000),
    (True,  "SA", 200, 101, b"",       1001),
    (False, "A",  101, 201, b"",       1002),
    (False, "PA", 101, 201, b"hello",  1003),
    (True,  "PA", 201, 106, b"world!", 1004),
    (False, "FA", 106, 207, b"",       1005),
    (True,  "FA", 207, 107, b"",       1006),
    (False, "A",  107, 208, b"",       1007),
]

packets = []

for reverse, flags, seq, ack, payload, timestamp in cases:
    src, dst = "10.0.0.1", "10.0.0.2"
    sport, dport = 12000, 9000

    if reverse:
        src, dst = dst, src
        sport, dport = dport, sport

    packet = (
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    )

    if payload:
        packet = packet / Raw(load=payload)

    packet.time = timestamp
    packets.append(packet)

wrpcap(str(folder / "statistics.pcap"), packets)
print("Created statistics.pcap: 8 packets")
