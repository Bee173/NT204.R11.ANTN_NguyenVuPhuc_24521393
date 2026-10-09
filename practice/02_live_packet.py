from scapy.all import sniff

def handle_packet(packet):
    print(packet.summary())

sniff(iface="en0", count=10, prn=handle_packet, store=False,)