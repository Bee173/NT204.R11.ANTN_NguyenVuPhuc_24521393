import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.flow_matcher import match_rule_flow
    from src.core_engine.rule_loader import RuleCandidate
    from src.core_engine.rule_validator import parse_and_validate_rule
except ModuleNotFoundError as error:
    print(f"FAIL: Flow Matcher chưa được triển khai: {error}")
    raise SystemExit(1) from error


def make_rule(flow=None):
    option = f" flow:{flow};" if flow else ""
    return parse_and_validate_rule(RuleCandidate(
        raw=(
            "alert tcp any any -> any 80 "
            f'(msg:"Flow match";{option} sid:100700; rev:1;)'
        ),
        source="flow.rules",
        line_number=1,
    ))


assert match_rule_flow(make_rule(), None)

to_server = make_rule("to_server,established")
assert match_rule_flow(to_server, {
    "direction": "to_server",
    "state": "ESTABLISHED",
})
assert not match_rule_flow(to_server, {
    "direction": "to_client",
    "state": "ESTABLISHED",
})
assert not match_rule_flow(to_server, {
    "direction": "to_server",
    "state": "HANDSHAKE",
})

not_established = make_rule("to_client,not_established")
assert match_rule_flow(not_established, {
    "direction": "TO_CLIENT",
    "state": "handshake",
})
assert not match_rule_flow(not_established, {
    "direction": "to_client",
    "state": "ESTABLISHED",
})
assert not match_rule_flow(not_established, {
    "direction": "to_client",
    "state": "BROKEN",
})

assert not match_rule_flow(to_server, None)
assert not match_rule_flow(to_server, {"direction": "to_server"})

print("PASS: Flow Matcher xử lý direction và connection state đúng")
