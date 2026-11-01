from src.core_engine.rule_model import RuleStatus, SnortRule


FLOW_STATES = {
    "new", "handshake", "established", "active", "closing",
    "closed", "reset", "expired",
}


def _normalized(context, field):
    value = context.get(field)
    return value.strip().lower() if isinstance(value, str) else None


def match_rule_flow(rule: SnortRule, flow_context):
    if rule.status != RuleStatus.VALID:
        return False

    flow = rule.first_option_value("flow")
    if flow is None:
        return True
    if not isinstance(flow_context, dict):
        return False

    requirements = {value.strip().lower() for value in flow.split(",")}
    direction = _normalized(flow_context, "direction")
    state = _normalized(flow_context, "state")

    if "to_server" in requirements and direction != "to_server":
        return False
    if "to_client" in requirements and direction != "to_client":
        return False
    if "established" in requirements and state != "established":
        return False
    if "not_established" in requirements:
        if state not in FLOW_STATES or state == "established":
            return False
    return True
