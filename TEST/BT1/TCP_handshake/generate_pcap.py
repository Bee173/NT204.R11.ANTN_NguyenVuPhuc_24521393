from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

OUTPUT_FILE = Path(__file__).parent / "tcp_handshake.pcap"

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 40000
SERVER_PORT = 5000


def create_tcp_handshake():
    client_mac = "00:11:22:33:44:55"
    server_mac = "66:77:88:99:aa:bb"

    syn = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=1000)
    )

    syn_ack = (
        Ether(src=server_mac, dst=client_mac)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(
            sport=SERVER_PORT,
            dport=CLIENT_PORT,
            flags="SA",
            seq=2000,
            ack=1001,
        )
    )

    ack = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            flags="A",
            seq=1001,
            ack=2001,
        )
    )

    packets = [syn, syn_ack, ack]
    wrpcap(str(OUTPUT_FILE), packets)

    print(f"Created: {OUTPUT_FILE}")
    print(f"Number of packets: {len(packets)}")


if __name__ == "__main__":
    create_tcp_handshake()