from src.parsers.network import parse_network
from src.parsers.transport import parse_transport
from src.parsers.application_detector import detect_application_protocol
from src.parsers.application import parse_application
from src.normalized import normalize_event


def parse_packet(packet, packet_id):
    errors = []

    try:
        timestamp = float(packet.time)
    except Exception as e:
        timestamp = None
        errors.append(f"timestamp: {e}")

    try:
        network = parse_network(packet)
    except Exception as e:
        network = {}
        errors.append(f"network: {e}")

    try:
        transport = parse_transport(packet)
    except Exception as e:
        transport = {}
        errors.append(f"transport: {e}")

    try:
        application_protocol = detect_application_protocol(packet, transport,)
    except Exception as e:
        application_protocol = "UNKNOWN"
        errors.append(f"application_detector: {e}")

    try:
        application = parse_application(packet, application_protocol,)
    except Exception as e:
        application = {}
        errors.append(f"application_parser: {e}")

    return normalize_event(
        packet_id=packet_id,
        timestamp=timestamp,
        network=network,
        transport=transport,
        application_protocol=application_protocol,
        application=application,
        errors=errors,
    )