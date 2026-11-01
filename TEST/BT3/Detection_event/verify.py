import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.detection_event import generate_detection_event
    from src.core_engine.matching_engine import match_rule
    from src.core_engine.rule_loader import RuleCandidate
    from src.core_engine.rule_validator import parse_and_validate_rule
except ModuleNotFoundError as error:
    print(f"FAIL: Detection Event Generator chưa được triển khai: {error}")
    raise SystemExit(1) from error


rule = parse_and_validate_rule(RuleCandidate(
    raw=(
        "alert tcp any any -> any 80 "
        '(msg:"Directory traversal"; content:"../"; '
        "classtype:web-application-attack; priority:1; "
        "sid:101200; rev:2;)"
    ),
    source="detection.rules",
    line_number=1,
))
event = {
    "timestamp": 1700000000.25,
    "transport_protocol": "TCP",
    "application_protocol": "HTTP",
    "src_ip": "10.0.0.5",
    "src_port": 52133,
    "dst_ip": "192.168.1.20",
    "dst_port": 80,
    "flow_id": "F123",
    "payload_length": 3,
    "transport": {"tcp_flags": "PA"},
}

match = match_rule(rule, event, application_data=b"../")
assert (match.rev, match.msg, match.priority, match.classtype) == (
    2,
    "Directory traversal",
    1,
    "web-application-attack",
)
assert generate_detection_event(event, match) == {
    "timestamp": 1700000000.25,
    "sid": 101200,
    "rev": 2,
    "msg": "Directory traversal",
    "priority": 1,
    "classtype": "web-application-attack",
    "src_ip": "10.0.0.5",
    "src_port": 52133,
    "dst_ip": "192.168.1.20",
    "dst_port": 80,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "flow_id": "F123",
    "matched_information": {
        "content": [{"content": "../", "start": 0, "end": 3}],
    },
}

no_match = match_rule(rule, {**event, "dst_port": 443}, application_data=b"../")
assert generate_detection_event(event, no_match) is None
assert generate_detection_event(None, match) is None

print("PASS: Detection Event có đủ rule, flow, 5-tuple và match info")
