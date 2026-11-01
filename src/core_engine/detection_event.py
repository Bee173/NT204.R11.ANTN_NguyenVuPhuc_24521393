from src.core_engine.matching_engine import RuleMatchResult


def generate_detection_event(event, match_result: RuleMatchResult):
    if not isinstance(event, dict) or not match_result.matched:
        return None

    return {
        "timestamp": event.get("timestamp"),
        "sid": match_result.sid,
        "rev": match_result.rev,
        "msg": match_result.msg,
        "priority": match_result.priority,
        "classtype": match_result.classtype,
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dst_ip": event.get("dst_ip"),
        "dst_port": event.get("dst_port"),
        "protocol": event.get("transport_protocol"),
        "application_protocol": event.get("application_protocol"),
        "flow_id": event.get("flow_id"),
        "matched_information": dict(match_result.matched_information),
    }
