import sys
from dataclasses import replace
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.rule_loader import RuleCandidate
    from src.core_engine.rule_repository import RuleRepository
    from src.core_engine.rule_validator import parse_and_validate_rule
except ModuleNotFoundError as error:
    print(f"FAIL: Rule Repository chưa được triển khai: {error}")
    raise SystemExit(1) from error


def make_rule(raw, line_number):
    return parse_and_validate_rule(RuleCandidate(
        raw=raw,
        source="repository.rules",
        line_number=line_number,
    ))


rules = [
    make_rule(
        "alert tcp 10.0.0.0/24 any -> 192.168.1.10 80 "
        '(msg:"Specific HTTP"; sid:100601; rev:1;)',
        1,
    ),
    make_rule(
        "alert tcp any any -> any any "
        '(msg:"Any TCP"; sid:100602; rev:1;)',
        2,
    ),
    make_rule(
        "alert udp any any -> any 53 "
        '(msg:"DNS"; sid:100603; rev:1;)',
        3,
    ),
    replace(make_rule(
        "alert tcp any any -> any any "
        '(msg:"Disabled"; sid:100604; rev:1;)',
        4,
    ), enabled=False),
    make_rule(
        "alert tcp any any -> any 80 "
        '(msg:"Unsupported"; pcre:"/x/"; sid:100605; rev:1;)',
        5,
    ),
]

repository = RuleRepository(rules)
assert repository.rule_count == 3


def candidate_sids(event):
    return [
        int(rule.first_option_value("sid"))
        for rule in repository.candidate_rules(event)
    ]


assert candidate_sids({
    "transport_protocol": "TCP",
    "src_ip": "10.0.0.5",
    "src_port": 45000,
    "dst_ip": "192.168.1.10",
    "dst_port": 80,
}) == [100601, 100602]

assert candidate_sids({
    "transport_protocol": "TCP",
    "src_ip": "172.16.0.5",
    "src_port": 40000,
    "dst_ip": "192.168.2.20",
    "dst_port": 443,
}) == [100602]

assert candidate_sids({
    "transport_protocol": "UDP",
    "src_ip": "10.0.0.5",
    "src_port": 53000,
    "dst_ip": "8.8.8.8",
    "dst_port": 53,
}) == [100603]

assert repository.candidate_rules({"transport_protocol": "UNKNOWN"}) == ()

print("PASS: Rule Repository lập chỉ mục và chọn candidate đúng")
