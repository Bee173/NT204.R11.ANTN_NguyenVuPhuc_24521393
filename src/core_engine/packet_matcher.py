from src.core_engine.rule_model import RuleStatus, SnortRule


TCP_FLAGS = set("FSRPAUEC")


def _match_flags(expected, event):
    protocol = event.get("transport_protocol")
    transport = event.get("transport")
    if (
        not isinstance(protocol, str)
        or protocol.strip().upper() != "TCP"
        or not isinstance(transport, dict)
    ):
        return False

    actual = transport.get("tcp_flags")
    if not isinstance(actual, str):
        return False
    expected = expected.strip().upper()
    actual = actual.strip().upper()
    if not expected or not actual:
        return False
    if not set(expected) <= TCP_FLAGS or not set(actual) <= TCP_FLAGS:
        return False
    return set(expected) == set(actual)


def match_rule_packet(rule: SnortRule, event):
    if rule.status != RuleStatus.VALID or not isinstance(event, dict):
        return False

    flags = rule.first_option_value("flags")
    if flags is not None and not _match_flags(flags, event):
        return False

    dsize = rule.first_option_value("dsize")
    if dsize is not None:
        payload_length = event.get("payload_length")
        if (
            isinstance(payload_length, bool)
            or not isinstance(payload_length, int)
            or payload_length < 0
            or payload_length != int(dsize)
        ):
            return False
    return True
