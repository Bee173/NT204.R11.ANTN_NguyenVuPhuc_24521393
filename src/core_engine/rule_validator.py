from dataclasses import replace
from ipaddress import IPv4Network, ip_network

from src.core_engine.rule_loader import RuleCandidate
from src.core_engine.rule_model import RuleStatus, SnortRule
from src.core_engine.rule_parser import parse_rule


SUPPORTED_ACTIONS = {"alert"}
SUPPORTED_PROTOCOLS = {"tcp", "udp"}
SUPPORTED_DIRECTIONS = {"->", "<>"}
SUPPORTED_KEYWORDS = {
    "msg", "sid", "rev", "content", "nocase", "offset", "depth",
    "distance", "within", "flags", "dsize", "flow", "classtype",
    "priority",
}
REQUIRED_KEYWORDS = {"msg", "sid", "rev"}
SINGLE_VALUE_KEYWORDS = {
    "msg", "sid", "rev", "flags", "dsize", "flow", "classtype",
    "priority",
}
CONTENT_MODIFIERS = {"nocase", "offset", "depth", "distance", "within"}
TCP_FLAGS = set("FSRPAUEC")


def _validate_ip(value, field, invalid, unsupported):
    if value.lower() == "any":
        return
    if value.startswith(("!", "[")):
        unsupported.append(f"{field}: unsupported address expression {value}")
        return
    try:
        network = ip_network(value, strict=False)
    except ValueError:
        invalid.append(f"{field}: invalid IPv4 or CIDR {value}")
        return
    if not isinstance(network, IPv4Network):
        unsupported.append(f"{field}: IPv6 is unsupported")


def _validate_port(value, field, invalid, unsupported):
    if value.lower() == "any":
        return
    if value.startswith(("!", "[")):
        unsupported.append(f"{field}: unsupported port expression {value}")
        return

    parts = value.split(":")
    if len(parts) > 2 or any(not part for part in parts):
        invalid.append(f"{field}: invalid port or range {value}")
        return
    if any(not part.isascii() or not part.isdigit() for part in parts):
        invalid.append(f"{field}: invalid port or range {value}")
        return
    ports = [int(part) for part in parts]
    if any(port < 0 or port > 65535 for port in ports):
        invalid.append(f"{field}: port outside 0-65535")
    elif len(ports) == 2 and ports[0] > ports[1]:
        invalid.append(f"{field}: range start exceeds range end")


def _validate_integer(value, keyword, invalid, minimum=0):
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdigit()
    ):
        invalid.append(f"{keyword}: integer required")
        return
    number = int(value)
    if number < minimum:
        invalid.append(f"{keyword}: must be at least {minimum}")


def _group_options(rule):
    grouped = {}
    for option in rule.options:
        grouped.setdefault(option.keyword, []).append(option)
    return grouped


def validate_rule(rule: SnortRule):
    invalid = []
    unsupported = []
    header = rule.header

    if header is None:
        return replace(
            rule,
            status=RuleStatus.INVALID,
            reasons=("header: missing",),
        )

    if header.action not in SUPPORTED_ACTIONS:
        unsupported.append(f"action: unsupported {header.action}")
    if header.protocol not in SUPPORTED_PROTOCOLS:
        unsupported.append(f"protocol: unsupported {header.protocol}")
    if header.direction not in SUPPORTED_DIRECTIONS:
        unsupported.append(f"direction: unsupported {header.direction}")

    _validate_ip(header.src_ip, "src_ip", invalid, unsupported)
    _validate_ip(header.dst_ip, "dst_ip", invalid, unsupported)
    _validate_port(header.src_port, "src_port", invalid, unsupported)
    _validate_port(header.dst_port, "dst_port", invalid, unsupported)

    grouped = _group_options(rule)
    for keyword in grouped:
        if keyword not in SUPPORTED_KEYWORDS:
            unsupported.append(f"keyword: unsupported {keyword}")

    for keyword in REQUIRED_KEYWORDS:
        if keyword not in grouped:
            invalid.append(f"{keyword}: required option missing")

    for keyword in SINGLE_VALUE_KEYWORDS:
        if len(grouped.get(keyword, [])) > 1:
            invalid.append(f"{keyword}: duplicate option")

    for keyword in ("msg", "content", "flags", "classtype"):
        for option in grouped.get(keyword, []):
            if option.value is None or not option.value.strip():
                invalid.append(f"{keyword}: non-empty value required")

    for option in grouped.get("flags", []):
        if option.value and option.value.strip():
            flags = option.value.strip().upper()
            if header.protocol == "udp":
                invalid.append("flags: requires TCP protocol")
            elif header.protocol == "tcp" and not set(flags) <= TCP_FLAGS:
                invalid.append(f"flags: invalid TCP flags {flags}")

    for keyword in ("sid", "rev", "priority"):
        for option in grouped.get(keyword, []):
            _validate_integer(option.value, keyword, invalid, minimum=1)

    for keyword in ("offset", "depth", "distance", "within", "dsize"):
        for option in grouped.get(keyword, []):
            _validate_integer(option.value, keyword, invalid)

    for option in grouped.get("nocase", []):
        if option.value is not None:
            invalid.append("nocase: option does not take a value")

    for option in grouped.get("flow", []):
        if option.value is None:
            invalid.append("flow: value required")
            continue
        values = {value.strip().lower() for value in option.value.split(",")}
        allowed = {
            "to_server", "to_client", "established", "not_established",
        }
        for value in sorted(values - allowed):
            unsupported.append(f"flow: unsupported value {value}")
        if {"to_server", "to_client"}.issubset(values):
            invalid.append("flow: conflicting directions")
        if {"established", "not_established"}.issubset(values):
            invalid.append("flow: conflicting states")

    content_count = 0
    for option in rule.options:
        if option.keyword == "content":
            content_count += 1
        elif option.keyword in {"distance", "within"} and content_count < 2:
            invalid.append(
                f"{option.keyword}: requires a previous content option"
            )
        elif option.keyword in CONTENT_MODIFIERS and not content_count:
            invalid.append(
                f"{option.keyword}: requires a preceding content option"
            )

    reasons = tuple(invalid + unsupported)
    if invalid:
        status = RuleStatus.INVALID
    elif unsupported:
        status = RuleStatus.UNSUPPORTED
    else:
        status = RuleStatus.VALID
    return replace(rule, status=status, reasons=reasons)


def parse_and_validate_rule(candidate: RuleCandidate):
    try:
        return validate_rule(parse_rule(candidate))
    except (AttributeError, TypeError, ValueError) as error:
        return SnortRule(
            raw=candidate.raw,
            source=candidate.source,
            line_number=candidate.line_number,
            status=RuleStatus.INVALID,
            reasons=(f"syntax: {error}",),
        )
