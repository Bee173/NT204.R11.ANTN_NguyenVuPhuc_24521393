import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.matching_engine import match_rule
    from src.core_engine.rule_loader import RuleCandidate
    from src.core_engine.rule_validator import parse_and_validate_rule
except ModuleNotFoundError as error:
    print(f"FAIL: Matching Engine chưa được triển khai: {error}")
    raise SystemExit(1) from error


def make_rule(options):
    return parse_and_validate_rule(RuleCandidate(
        raw=(
            "alert tcp 10.0.0.1 any -> 10.0.0.2 80 "
            f'(msg:"Engine match"; {options} sid:101000; rev:1;)'
        ),
        source="engine.rules",
        line_number=1,
    ))


rule = make_rule(
    'flow:to_server,established; flags:PA; dsize:4; '
    'content:"evil"; nocase;'
)
event = {
    "transport_protocol": "TCP",
    "src_ip": "10.0.0.1",
    "src_port": 50000,
    "dst_ip": "10.0.0.2",
    "dst_port": 80,
    "payload_length": 4,
    "transport": {"tcp_flags": "AP"},
}
flow_context = {"direction": "to_server", "state": "ESTABLISHED"}

matched = match_rule(rule, event, flow_context, b"EVIL")
assert matched.to_dict() == {
    "matched": True,
    "reason": "matched",
    "sid": 101000,
    "rev": 1,
    "msg": "Engine match",
    "priority": None,
    "classtype": None,
    "matched_information": {
        "flow": "to_server,established",
        "flags": "PA",
        "dsize": 4,
        "content": [{"content": "evil", "start": 0, "end": 4}],
    },
}

assert match_rule(
    rule,
    {**event, "dst_port": 81},
    flow_context,
    b"EVIL",
).reason == "header"
assert match_rule(
    rule,
    event,
    {"direction": "to_server", "state": "HANDSHAKE"},
    b"EVIL",
).reason == "flow"
assert match_rule(
    rule,
    {**event, "payload_length": 5},
    flow_context,
    b"EVIL",
).reason == "packet"
assert match_rule(rule, event, flow_context, b"safe").reason == "content"

header_only = make_rule("")
assert match_rule(header_only, event).matched

unsupported = parse_and_validate_rule(RuleCandidate(
    raw=(
        "alert tcp any any -> any any "
        '(msg:"Unsupported"; pcre:"/x/"; sid:101001; rev:1;)'
    ),
    source="engine.rules",
    line_number=2,
))
assert match_rule(unsupported, event).reason == "rule"

print("PASS: Matching Engine kết hợp các matcher và trả result thống nhất")
