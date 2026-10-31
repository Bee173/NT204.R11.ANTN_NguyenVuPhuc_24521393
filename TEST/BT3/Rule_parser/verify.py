import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.rule_loader import RuleCandidate
    from src.core_engine.rule_model import RuleStatus
    from src.core_engine.rule_parser import parse_rule
except ModuleNotFoundError as error:
    print(f"FAIL: Rule Parser chưa được triển khai: {error}")
    raise SystemExit(1) from error


candidate = RuleCandidate(
    raw=(
        "alert tcp any any -> 192.168.1.0/24 80:8080 "
        '(msg:"Semicolon; inside"; content:"a;b"; nocase; '
        "sid:100010; rev:2;)"
    ),
    source="local.rules",
    line_number=12,
)

rule = parse_rule(candidate)

assert rule.status == RuleStatus.VALID
assert rule.source == "local.rules"
assert rule.line_number == 12
assert rule.header.to_dict() == {
    "action": "alert",
    "protocol": "tcp",
    "src_ip": "any",
    "src_port": "any",
    "direction": "->",
    "dst_ip": "192.168.1.0/24",
    "dst_port": "80:8080",
}
assert [(option.keyword, option.value) for option in rule.options] == [
    ("msg", "Semicolon; inside"),
    ("content", "a;b"),
    ("nocase", None),
    ("sid", "100010"),
    ("rev", "2"),
]

print("PASS: Snort Rule Parser tách đúng header và quoted options")
