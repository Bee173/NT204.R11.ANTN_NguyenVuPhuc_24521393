import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.core_engine import CoreEngine
    from src.core_engine.rule_model import RuleStatus
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

print("PASS: Core Engine nối rule files, evaluation và detection pipeline đúng")
