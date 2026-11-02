import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))

from src.core_engine.core_engine import CoreEngine  # noqa: E402
from src.core_engine.rule_loader import RuleCandidate  # noqa: E402
from src.core_engine.rule_validator import parse_and_validate_rule  # noqa: E402
from src.flow_tracker import FlowTracker  # noqa: E402


def make_event(timestamp, src_ip, src_port, dst_ip, dst_port, flags):
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "transport_protocol": "TCP",
        "application_protocol": "HTTP",
        "packet_length": 60,
        "payload_length": 0,
        "transport": {
            "tcp_flags": flags,
            "sequence_number": 1,
            "acknowledgment_number": 2,
        },
        "processing_action": "continue",
    }


tracker = FlowTracker()
syn = tracker.track_event(make_event(
    1.0, "10.0.0.10", 50000, "10.0.0.20", 80, "S",
))
syn_ack = tracker.track_event(make_event(
    2.0, "10.0.0.20", 80, "10.0.0.10", 50000, "SA",
))
ack = tracker.track_event(make_event(
    3.0, "10.0.0.10", 50000, "10.0.0.20", 80, "A",
))

assert [event["direction"] for event in (syn, syn_ack, ack)] == [
    "forward", "backward", "forward",
]
assert [
    event["flow_context"]["direction"]
    for event in (syn, syn_ack, ack)
] == ["to_server", "to_client", "to_server"]
assert ack["flow_context"] == {
    "direction": "to_server",
    "state": "ESTABLISHED",
    "flow_id": ack["flow_id"],
}

rule = parse_and_validate_rule(RuleCandidate(
    raw=(
        'alert tcp any any -> any 80 (msg:"Established request"; '
        "flow:to_server,established; sid:100801; rev:1;)"
    ),
    source="integration.rules",
    line_number=1,
))
engine = CoreEngine((rule,))

assert [
    detection["sid"]
    for detection in engine.process_event(ack, application_data=b"")
] == [100801]
assert engine.process_event(
    ack,
    {"direction": "to_client", "state": "ESTABLISHED"},
    b"",
) == ()

print("PASS: FlowTracker context is consumed directly by Core Engine")
