from scapy.layers.dns import DNS
from scapy.packet import Raw


HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
)

SMTP_COMMANDS = (
    b"HELO ",
    b"EHLO ",
    b"MAIL FROM:",
    b"RCPT TO:",
    b"DATA",
    b"QUIT",
    b"RSET",
    b"NOOP",
)


def get_payload(packet):
    if Raw not in packet:
        return b""

    try:
        return bytes(packet[Raw].load)
    except Exception:
        return b""


def is_http(payload):
    if not payload:
        return False

    upper_payload = payload.upper()

    # HTTP request: GET, POST, PUT,...
    if upper_payload.startswith(HTTP_METHODS):
        return True

    # HTTP response: HTTP/1.1 200 OK
    if upper_payload.startswith(b"HTTP/"):
        return True

    return False


def is_smtp(payload):
    """
    Kiểm tra payload có giống SMTP command hay không.
    """
    if not payload:
        return False

    upper_payload = payload.upper().lstrip()

    for command in SMTP_COMMANDS:
        if upper_payload.startswith(command):
            return True

    return False


def is_smtp_response(payload):
    payload = payload.lstrip()

    if len(payload) < 4:
        return False

    return (
        payload[:3].isdigit()
        and payload[3:4] in (b" ", b"-")
    )


def detect_application_protocol(packet, transport):
    if DNS in packet:
        return "DNS"

    payload = get_payload(packet)

    if is_http(payload):
        return "HTTP"

    if is_smtp(payload):
        return "SMTP"

    src_port = transport.get("src_port")
    dst_port = transport.get("dst_port")

    ports = {src_port, dst_port}

    # DNS
    if 53 in ports:
        return "DNS"

    # HTTP
    if ports.intersection({80, 8000, 8080}):
        return "HTTP"

    # SMTP
    smtp_ports = {25, 465, 587, 2525}

    if ports.intersection(smtp_ports):
        if is_smtp_response(payload):
            return "SMTP"

        return "SMTP"

    return "UNKNOWN"