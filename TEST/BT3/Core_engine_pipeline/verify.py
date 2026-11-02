import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.core_engine import CoreEngine
    from src.core_engine.rule_loader import RuleCandidate
    from src.core_engine.rule_model import RuleStatus
    from src.core_engine.rule_validator import parse_and_validate_rule
except ModuleNotFoundError as error:
    print(f"FAIL: Core Engine pipeline chưa được triển khai: {error}")
    raise SystemExit(1) from error


engine = CoreEngine.from_rule_files([folder / "input.rules"])
assert engine.rule_count == 2
assert engine.load_issues == ()
assert [rule.status for rule in engine.rejected_rules] == [
    RuleStatus.UNSUPPORTED,
    RuleStatus.INVALID,
]

event = {
    "timestamp": 1700000000.5,
    "transport_protocol": "TCP",
    "application_protocol": "HTTP",
    "src_ip": "10.0.0.5",
    "src_port": 52133,
    "dst_ip": "192.168.1.20",
    "dst_port": 80,
    "flow_id": "F1300",
    "payload_length": 8,
    "transport": {"tcp_flags": "PA"},
    "application": {"decoded_path": "/../../etc/passwd"},
}
flow_context = {"direction": "to_server", "state": "ESTABLISHED"}
detections = engine.process_event(event, flow_context)

assert [detection["sid"] for detection in detections] == [101300, 101301]
assert all(detection["flow_id"] == "F1300" for detection in detections)
assert detections[0]["matched_information"]["content"][0]["content"] == "../"
assert engine.statistics == {
    "events_evaluated": 1,
    "candidate_rules": 2,
    "matches": 2,
}

configured_engine = CoreEngine.from_rule_files(
    [folder / "input.rules"],
    disabled_sids={101300},
)
assert configured_engine.rule_count == 1
assert [
    int(rule.first_option_value("sid"))
    for rule in configured_engine.rejected_rules
    if rule.first_option_value("sid") is not None
] == [101300, 101302]
assert [
    detection["sid"]
    for detection in configured_engine.process_event(event, flow_context)
] == [101301]

field_rule = parse_and_validate_rule(RuleCandidate(
    raw=(
        'alert tcp any any -> any 80 (msg:"Field isolation"; '
        'content:"A"; content:"B"; distance:1; within:3; '
        "sid:101303; rev:1;)"
    ),
    source="field.rules",
    line_number=1,
))
field_engine = CoreEngine((field_rule,))
field_event = dict(event)
field_event["application"] = {"decoded_path": "A", "decoded_body": "B"}
assert field_engine.process_event(field_event) == ()

field_event["application"] = {"decoded_path": "A_B"}
detection = field_engine.process_event(field_event)[0]
assert detection["matched_information"]["matched_field"] == "decoded_path"

print("PASS: Core Engine nối rule files, evaluation và detection pipeline đúng")
