import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.content_matcher import match_rule_content
    from src.core_engine.rule_loader import RuleCandidate
    from src.core_engine.rule_validator import parse_and_validate_rule
except ModuleNotFoundError as error:
    print(f"FAIL: Content Matcher chưa được triển khai: {error}")
    raise SystemExit(1) from error


def make_rule(options, sid=100800):
    return parse_and_validate_rule(RuleCandidate(
        raw=(
            "alert tcp any any -> any 80 "
            f'(msg:"Content match"; {options} sid:{sid}; rev:1;)'
        ),
        source="content.rules",
        line_number=1,
    ))


plain = make_rule('content:"LOGIN";')
assert match_rule_content(plain, b"xxLOGINyy") == ({
    "content": "LOGIN",
    "start": 2,
    "end": 7,
},)
assert match_rule_content(plain, b"xxloginyy") is None

nocase = make_rule('content:"LOGIN"; nocase;')
assert match_rule_content(nocase, "xxloginyy") == ({
    "content": "LOGIN",
    "start": 2,
    "end": 7,
},)

bounded = make_rule('content:"evil"; offset:2; depth:4;')
assert match_rule_content(bounded, b"xxevil") is not None
assert match_rule_content(
    make_rule('content:"evil"; offset:4; depth:4;'),
    b"xxevil",
) is None

relative = make_rule(
    'content:"USER"; content:"PASS"; distance:4; within:8;'
)
assert match_rule_content(relative, b"USER xx PASS data") == (
    {"content": "USER", "start": 0, "end": 4},
    {"content": "PASS", "start": 8, "end": 12},
)
assert match_rule_content(
    make_rule(
        'content:"USER"; content:"PASS"; distance:5; within:8;'
    ),
    b"USER xx PASS data",
) is None
assert match_rule_content(
    make_rule(
        'content:"USER"; content:"PASS"; distance:4; within:7;'
    ),
    b"USER xx PASS data",
) is None

backtracking = make_rule(
    'content:"A"; content:"B"; distance:1; within:3;'
)
assert match_rule_content(backtracking, b"AxxxxA_B") == (
    {"content": "A", "start": 5, "end": 6},
    {"content": "B", "start": 7, "end": 8},
)

assert match_rule_content(make_rule(""), b"anything") == ()
assert match_rule_content(plain, None) is None

print("PASS: Content Matcher xử lý content và positional modifiers đúng")
