from ipaddress import IPv4Address, ip_address, ip_network

from src.core_engine.rule_model import RuleStatus, SnortRule


def _match_ip(specification, value):
    if not isinstance(value, str):
        return False
    try:
        address = ip_address(value)
    except ValueError:
        return False
    if not isinstance(address, IPv4Address):
        return False
    if specification.lower() == "any":
        return True
    try:
        return address in ip_network(specification, strict=False)
    except ValueError:
        return False


def _match_port(specification, value):
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    if not 0 <= value <= 65535:
        return False
    if specification.lower() == "any":
        return True

    parts = specification.split(":")
    try:
        ports = [int(part) for part in parts]
    except ValueError:
        return False
    if len(ports) == 1:
        return value == ports[0]
    if len(ports) == 2:
        return ports[0] <= value <= ports[1]
    return False


def _match_orientation(header, event, reverse=False):
    if reverse:
        src_ip, src_port = event.get("dst_ip"), event.get("dst_port")
        dst_ip, dst_port = event.get("src_ip"), event.get("src_port")
    else:
        src_ip, src_port = event.get("src_ip"), event.get("src_port")
        dst_ip, dst_port = event.get("dst_ip"), event.get("dst_port")

    return (
        _match_ip(header.src_ip, src_ip)
        and _match_port(header.src_port, src_port)
        and _match_ip(header.dst_ip, dst_ip)
        and _match_port(header.dst_port, dst_port)
    )


def match_rule_header(rule: SnortRule, event):
    if (
        not isinstance(event, dict)
        or rule.status != RuleStatus.VALID
        or rule.header is None
    ):
        return False

    protocol = event.get("transport_protocol")
    if not isinstance(protocol, str):
        return False
    if protocol.strip().lower() != rule.header.protocol:
        return False

    if _match_orientation(rule.header, event):
        return True
    return (
        rule.header.direction == "<>"
        and _match_orientation(rule.header, event, reverse=True)
    )
