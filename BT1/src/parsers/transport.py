from scapy.layers.inet import TCP, UDP


def get_payload_length(layer):
    try:
        return len(bytes(layer.payload))
    except Exception:
        return 0


def classify_tcp_state(flags):
    flag_value = int(flags)

    syn = bool(flag_value & 0x02)
    ack = bool(flag_value & 0x10)
    rst = bool(flag_value & 0x04)
    fin = bool(flag_value & 0x01)

    if syn and ack:
        return "SYN/ACK"
    if syn:
        return "SYN"
    if rst:
        return "RST"
    if fin:
        return "FIN"
    if ack:
        return "ACK"
    return "OTHER"


def parse_tcp(packet):
    tcp = packet[TCP]

    return {
        "protocol": "TCP",
        "src_port": int(tcp.sport),
        "dst_port": int(tcp.dport),
        "sequence_number": int(tcp.seq),
        "acknowledgment_number": int(tcp.ack),
        "tcp_flags": str(tcp.flags),
        "tcp_state": classify_tcp_state(tcp.flags),
        "window_size": int(tcp.window),
        "header_length": (
            int(tcp.dataofs * 4)
            if tcp.dataofs is not None
            else None
        ),
        "length": None,
        "payload_length": get_payload_length(tcp),
    }


def parse_udp(packet):
    udp = packet[UDP]

    return {
        "protocol": "UDP",
        "src_port": int(udp.sport),
        "dst_port": int(udp.dport),
        "sequence_number": None,
        "acknowledgment_number": None,
        "tcp_flags": None,
        "tcp_state": None,
        "window_size": None,
        "header_length": 8,
        "length": int(udp.len) if udp.len is not None else len(udp),
        "payload_length": get_payload_length(udp),
    }


def parse_transport(packet):
    if TCP in packet:
        return parse_tcp(packet)

    if UDP in packet:
        return parse_udp(packet)

    return {
        "protocol": "UNKNOWN",
        "src_port": None,
        "dst_port": None,
        "sequence_number": None,
        "acknowledgment_number": None,
        "tcp_flags": None,
        "tcp_state": None,
        "window_size": None,
        "header_length": None,
        "length": None,
        "payload_length": 0,
    }