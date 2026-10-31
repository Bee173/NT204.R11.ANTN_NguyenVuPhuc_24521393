import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.header_matcher import match_rule_header
    from src.core_engine.rule_loader import RuleCandidate
    from src.core_engine.rule_validator import parse_and_validate_rule
except ModuleNotFoundError as error:
    print(f"FAIL: Header Matcher chưa được triển khai: {error}")
    raise SystemExit(1) from error


def make_rule(direction):
    return parse_and_validate_rule(RuleCandidate(
        raw=(
            f"alert tcp 10.0.0.0/24 1000:2000 {direction} "
            "192.168.1.10 80 "
            '(msg:"Header match"; sid:100500; rev:1;)'
        ),
        source="matcher.rules",
        line_number=1,
    ))


forward_event = {
    "transport_protocol": "TCP",
    "src_ip": "10.0.0.5",
    "src_port": 1500,
    "dst_ip": "192.168.1.10",
    "dst_port": 80,
}
reverse_event = {
    "transport_protocol": "TCP",
    "src_ip": "192.168.1.10",
    "src_port": 80,
    "dst_ip": "10.0.0.5",
    "dst_port": 1500,
}

forward_rule = make_rule("->")
bidirectional_rule = make_rule("<>")
udp_rule = parse_and_validate_rule(RuleCandidate(
    raw=(
        "alert udp any any -> any 53 "
        '(msg:"DNS header"; sid:100501; rev:1;)'
    ),
    source="matcher.rules",
    line_number=2,
))

assert match_rule_header(forward_rule, forward_event)
assert not match_rule_header(forward_rule, reverse_event)
assert match_rule_header(bidirectional_rule, forward_event)
assert match_rule_header(bidirectional_rule, reverse_event)
assert match_rule_header(udp_rule, {
    "transport_protocol": "UDP",
    "src_ip": "10.0.0.8",
    "src_port": 53000,
    "dst_ip": "8.8.8.8",
    "dst_port": 53,
})

assert not match_rule_header(
    forward_rule,
    {**forward_event, "transport_protocol": "UDP"},
)
assert not match_rule_header(
    forward_rule,
    {**forward_event, "src_ip": "10.0.1.5"},
)
assert not match_rule_header(
    forward_rule,
    {**forward_event, "src_port": 999},
)
assert not match_rule_header(forward_rule, {"transport_protocol": "TCP"})

print("PASS: Header Matcher xử lý protocol, IP, port và direction đúng")
