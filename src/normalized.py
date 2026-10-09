def normalize_event(
    packet_id,
    timestamp,
    network,
    transport,
    application_protocol,
    application,
    errors=None,
):
    network = network or {}
    transport = transport or {}
    application = application or {}

    return {
        "packet_id": packet_id,
        "timestamp": timestamp,
        "src_ip": network.get("src_ip"),
        "dst_ip": network.get("dst_ip"),
        "network_protocol": network.get("protocol", "UNKNOWN"),
        "transport_protocol": transport.get("protocol", "UNKNOWN"),
        "application_protocol": application_protocol or "UNKNOWN",
        "src_port": transport.get("src_port"),
        "dst_port": transport.get("dst_port"),
        "payload_length": transport.get("payload_length", 0),
        "network": network,
        "transport": transport,
        "application": application,
        "parse_errors": errors or [],
    }