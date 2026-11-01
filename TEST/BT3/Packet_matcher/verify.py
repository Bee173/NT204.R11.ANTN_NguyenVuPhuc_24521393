import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.packet_matcher import match_rule_packet
    from src.core_engine.rule_loader import RuleCandidate
    from src.core_engine.rule_validator import parse_and_validate_rule
except ModuleNotFoundError as error:
    print(f"FAIL: Packet Matcher chưa được triển khai: {error}")
    raise SystemExit(1) from error


def make_rule(options=""):
    return parse_and_validate_rule(RuleCandidate(
        raw=(
            "alert tcp any any -> any 80 "
            f'(msg:"Packet match"; {options} sid:100900; rev:1;)'
        ),
        source="packet.rules",
        line_number=1,
    ))


event = {
    "transport_protocol": "TCP",
    "payload_length": 4,
    "transport": {"tcp_flags": "AP"},
}

assert match_rule_packet(make_rule(), event)
assert match_rule_packet(make_rule("flags:PA; dsize:4;"), event)
assert match_rule_packet(
    make_rule("flags:PA;"),
    {**event, "transport": {"tcp_flags": "pa"}},
)
assert not match_rule_packet(
    make_rule("flags:PA;"),
    {**event, "transport": {"tcp_flags": "SPA"}},
)
assert not match_rule_packet(
    make_rule("flags:PA;"),
    {**event, "transport_protocol": "UDP"},
)
assert not match_rule_packet(make_rule("dsize:5;"), event)
assert not match_rule_packet(
    make_rule("dsize:4;"),
    {**event, "payload_length": True},
)
assert not match_rule_packet(make_rule("flags:PA;"), {"transport": {}})
assert not match_rule_packet(make_rule(), None)

print("PASS: Packet Matcher xử lý TCP flags và dsize đúng")
