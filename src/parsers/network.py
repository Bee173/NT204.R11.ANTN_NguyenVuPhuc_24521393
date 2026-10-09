from scapy.layers.inet import IP


def parse_network(packet):
    result = {
        "protocol": "UNKNOWN",
        "src_ip": None,
        "dst_ip": None,
        "ttl": None,
        "ip_protocol": None,
        "total_length": None,
        "ip_id": None,
        "flags": None,
        "fragment_offset": None,
        "header_length": None,
    }

    if IP not in packet:
        return result

    ip = packet[IP]

    result.update({
        "protocol": "IPv4",
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "ttl": int(ip.ttl),
        "ip_protocol": int(ip.proto),
        "total_length": int(ip.len) if ip.len is not None else len(ip),
        "ip_id": int(ip.id),
        "flags": str(ip.flags),
        "fragment_offset": int(ip.frag),
        "header_length": int(ip.ihl * 4) if ip.ihl is not None else None,
    })

    return result