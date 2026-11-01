import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.evaluation_engine import RuleEvaluationEngine
    from src.core_engine.rule_loader import RuleCandidate
    from src.core_engine.rule_repository import RuleRepository
    from src.core_engine.rule_validator import parse_and_validate_rule
except ModuleNotFoundError as error:
    print(f"FAIL: Evaluation Engine chưa được triển khai: {error}")
    raise SystemExit(1) from error


def make_rule(raw, line_number):
    return parse_and_validate_rule(RuleCandidate(
        raw=raw,
        source="evaluation.rules",
        line_number=line_number,
    ))


rules = [
    make_rule(
        "alert tcp any any -> any 80 "
        '(msg:"Lowercase"; content:"evil"; sid:101101; rev:1;)',
        1,
    ),
    make_rule(
        "alert tcp any any -> any 80 "
        '(msg:"Nocase"; content:"EVIL"; nocase; sid:101102; rev:1;)',
        2,
    ),
    make_rule(
        "alert tcp any any -> any 80 "
        '(msg:"No match"; content:"safe"; sid:101103; rev:1;)',
        3,
    ),
    make_rule(
        "alert udp any any -> any 53 "
        '(msg:"DNS"; sid:101104; rev:1;)',
        4,
    ),
]
engine = RuleEvaluationEngine(RuleRepository(rules))

tcp_event = {
    "transport_protocol": "TCP",
    "src_ip": "10.0.0.1",
    "src_port": 50000,
    "dst_ip": "10.0.0.2",
    "dst_port": 80,
    "payload_length": 4,
    "transport": {"tcp_flags": "PA"},
}
results = engine.evaluate(tcp_event, application_data=b"evil")
assert [result.sid for result in results] == [101101, 101102]
assert engine.statistics == {
    "events_evaluated": 1,
    "candidate_rules": 3,
    "matches": 2,
}

udp_event = {
    "transport_protocol": "UDP",
    "src_ip": "10.0.0.1",
    "src_port": 53000,
    "dst_ip": "8.8.8.8",
    "dst_port": 53,
    "payload_length": 10,
    "transport": {},
}
assert [result.sid for result in engine.evaluate(udp_event)] == [101104]
assert engine.statistics == {
    "events_evaluated": 2,
    "candidate_rules": 4,
    "matches": 3,
}

snapshot = engine.statistics
snapshot["matches"] = 999
assert engine.statistics["matches"] == 3

print("PASS: Evaluation Engine trả mọi match và theo dõi statistics đúng")
