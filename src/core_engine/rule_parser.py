from src.core_engine.rule_loader import RuleCandidate
from src.core_engine.rule_model import (
    RuleHeader,
    RuleOption,
    RuleStatus,
    SnortRule,
)


def _split_options(options_text):
    segments = []
    current = []
    in_quotes = False
    escaped = False

    for character in options_text:
        if escaped:
            current.append(character)
            escaped = False
            continue

        if character == "\\" and in_quotes:
            current.append(character)
            escaped = True
            continue

        if character == '"':
            current.append(character)
            in_quotes = not in_quotes
            continue

        if character == ";" and not in_quotes:
            segment = "".join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            continue

        current.append(character)

    if in_quotes:
        raise ValueError("unterminated quoted option")
    if escaped:
        raise ValueError("dangling escape in quoted option")
    if "".join(current).strip():
        raise ValueError("rule option must end with semicolon")

    return segments


def _decode_option_value(value):
    value = value.strip()
    if not value.startswith('"'):
        return value
    if len(value) < 2 or not value.endswith('"'):
        raise ValueError("invalid quoted option value")

    decoded = []
    escaped = False
    for character in value[1:-1]:
        if escaped:
            decoded.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            decoded.append(character)

    if escaped:
        raise ValueError("dangling escape in quoted option value")
    return "".join(decoded)


def _parse_option(segment):
    keyword, separator, value = segment.partition(":")
    keyword = keyword.strip().lower()
    if not keyword:
        raise ValueError("rule option keyword is empty")
    return RuleOption(
        keyword=keyword,
        value=_decode_option_value(value) if separator else None,
    )


def parse_rule(candidate: RuleCandidate):
    raw = candidate.raw.strip()
    option_start = raw.find("(")
    option_end = raw.rfind(")")

    if option_start < 0 or option_end < option_start:
        raise ValueError("rule must contain an option block")
    if raw[option_end + 1:].strip():
        raise ValueError("unexpected text after option block")

    header_fields = raw[:option_start].split()
    if len(header_fields) != 7:
        raise ValueError("rule header must contain seven fields")

    action, protocol, src_ip, src_port, direction, dst_ip, dst_port = (
        header_fields
    )
    header = RuleHeader(
        action=action.lower(),
        protocol=protocol.lower(),
        src_ip=src_ip,
        src_port=src_port,
        direction=direction,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )
    options = tuple(
        _parse_option(segment)
        for segment in _split_options(raw[option_start + 1:option_end])
    )

    return SnortRule(
        raw=candidate.raw,
        source=candidate.source,
        line_number=candidate.line_number,
        status=RuleStatus.VALID,
        header=header,
        options=options,
    )
