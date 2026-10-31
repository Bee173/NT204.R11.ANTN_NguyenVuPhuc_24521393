import json
import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.rule_model import (
        RuleHeader,
        RuleOption,
        RuleStatus,
        SnortRule,
    )
except ModuleNotFoundError as error:
    print(f"FAIL: Rule Model chưa được triển khai: {error}")
    raise SystemExit(1) from error


header = RuleHeader(
    action="alert",
    protocol="tcp",
    src_ip="any",
    src_port="any",
    direction="->",
    dst_ip="192.168.1.0/24",
    dst_port="80:8080",
)

rule = SnortRule(
    raw=(
        'alert tcp any any -> 192.168.1.0/24 80:8080 '
        '(msg:"Traversal"; content:"../"; content:"etc/passwd"; '
        'sid:100001; rev:1;)'
    ),
    source="local.rules",
    line_number=7,
    status=RuleStatus.VALID,
    header=header,
    options=(
        RuleOption("msg", "Traversal"),
        RuleOption("content", "../"),
        RuleOption("content", "etc/passwd"),
        RuleOption("sid", "100001"),
        RuleOption("rev", "1"),
    ),
)

assert rule.option_values("content") == ("../", "etc/passwd"), (
    "Các option content lặp lại phải giữ nguyên thứ tự"
)
assert rule.first_option_value("sid") == "100001"
assert rule.first_option_value("missing") is None

serialized = rule.to_dict()
assert serialized["status"] == "valid"
assert serialized["header"]["dst_port"] == "80:8080"
assert serialized["options"][1] == {
    "keyword": "content",
    "value": "../",
}
json.dumps(serialized)

invalid_rule = SnortRule(
    raw="alert tcp any",
    source="broken.rules",
    line_number=3,
    status=RuleStatus.INVALID,
    reasons=("missing destination",),
)

assert invalid_rule.header is None
assert invalid_rule.to_dict()["reasons"] == ["missing destination"]

print("PASS: Snort Rule Model giữ đúng contract nội bộ")
