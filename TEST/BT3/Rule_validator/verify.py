import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.rule_loader import RuleCandidate
    from src.core_engine.rule_model import RuleStatus
    from src.core_engine.rule_validator import parse_and_validate_rule
except ModuleNotFoundError as error:
    print(f"FAIL: Rule Validator chưa được triển khai: {error}")
    raise SystemExit(1) from error


def candidate(raw, line_number):
    return RuleCandidate(
        raw=raw,
        source="validator.rules",
        line_number=line_number,
    )


valid_rule = parse_and_validate_rule(candidate(
    "alert tcp 10.0.0.0/24 1024:65535 -> 192.168.1.10 80 "
    '(msg:"HTTP request"; content:"GET"; nocase; offset:0; depth:3; '
    "flow:to_server,established; flags:PA; dsize:3; "
    "classtype:web-application-attack; priority:1; sid:100100; rev:1;)",
    1,
))
assert valid_rule.status == RuleStatus.VALID
assert valid_rule.reasons == ()

for protocol, flags, expected_reason in (
    ("tcp", "Z", "flags: invalid TCP flags Z"),
    ("udp", "PA", "flags: requires TCP protocol"),
):
    invalid_flags = parse_and_validate_rule(candidate(
        f"alert {protocol} any any -> any any "
        f'(msg:"Invalid flags"; flags:{flags}; sid:100106; rev:1;)',
        7,
    ))
    assert invalid_flags.status == RuleStatus.INVALID
    assert expected_reason in invalid_flags.reasons

invalid_syntax = parse_and_validate_rule(candidate(
    "alert tcp any any -> any 80",
    2,
))
assert invalid_syntax.status == RuleStatus.INVALID
assert invalid_syntax.header is None
assert any("syntax" in reason for reason in invalid_syntax.reasons)

unsupported_keyword = parse_and_validate_rule(candidate(
    "alert tcp any any -> any 80 "
    '(msg:"Unsupported"; pcre:"/admin/"; sid:100101; rev:1;)',
    3,
))
assert unsupported_keyword.status == RuleStatus.UNSUPPORTED
assert any("pcre" in reason for reason in unsupported_keyword.reasons)

invalid_values = parse_and_validate_rule(candidate(
    "alert tcp 999.1.1.1 70000 -> any 80 "
    '(msg:"Bad values"; sid:abc; rev:0;)',
    4,
))
assert invalid_values.status == RuleStatus.INVALID
for field in ("src_ip", "src_port", "sid", "rev"):
    assert any(field in reason for reason in invalid_values.reasons), (
        f"Thiếu lý do invalid cho {field}"
    )

unsupported_protocol = parse_and_validate_rule(candidate(
    "alert icmp any any -> any any "
    '(msg:"ICMP"; sid:100102; rev:1;)',
    5,
))
assert unsupported_protocol.status == RuleStatus.UNSUPPORTED
assert any("protocol" in reason for reason in unsupported_protocol.reasons)

non_decimal_numbers = parse_and_validate_rule(candidate(
    "alert tcp any 1_000 -> any 80 "
    '(msg:"Non-decimal"; sid:1_00; rev:+1;)',
    6,
))
assert non_decimal_numbers.status == RuleStatus.INVALID
for field in ("src_port", "sid", "rev"):
    assert any(field in reason for reason in non_decimal_numbers.reasons), (
        f"Validator phải từ chối cú pháp số không thuần decimal cho {field}"
    )

print("PASS: Snort Rule Validator phân loại và ghi lý do đúng")
