from .http import parse_http
from .dns import parse_dns
from .smtp import parse_smtp


def parse_application(packet, protocol):
    if protocol == "HTTP":
        return parse_http(packet)

    if protocol == "DNS":
        return parse_dns(packet)

    if protocol == "SMTP":
        return parse_smtp(packet)

    return {}