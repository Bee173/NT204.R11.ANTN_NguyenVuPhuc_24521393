from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

folder = Path(__file__).resolve().parent
packets = []

def add(sport, reverse, flags, seq, ack):
    src, dst = "10.0.0.1", "10.0.0.2"
    source_port, destination_port = sport, 9000

    if reverse:
        src, dst = dst, src
        source_port, destination_port = destination_port, source_port

    packet = (
        Ether()
        / IP(src=src, dst=dst)
        / TCP(
            sport=source_port,
            dport=destination_port,
            flags=flags,
            seq=seq,
            ack=ack,
        )
    )
    packet.time = 1000 + len(packets)
    packets.append(packet)

# Flow 1: handshake rồi đóng bằng FIN hai chiều.
add(12000, False, "S", 100, 0)
add(12000, True, "SA", 200, 101)
add(12000, False, "A", 101, 201)
add(12000, False, "FA", 101, 201)
add(12000, True, "A", 201, 102)
add(12000, True, "FA", 201, 102)
add(12000, False, "A", 102, 202)

# Flow 2: handshake rồi reset.
add(12001, False, "S", 300, 0)
add(12001, True, "SA", 400, 301)
add(12001, False, "A", 301, 401)
add(12001, True, "RA", 401, 301)

wrpcap(str(folder / "tcp_close.pcap"), packets)
print("Created tcp_close.pcap: FIN close and RST")
