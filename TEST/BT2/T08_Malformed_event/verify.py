import json
import sys
from copy import deepcopy
from pathlib import Path

folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))

from src.preprocessor import preprocess_event

base = {
    "timestamp": 123.5,
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": 12345,
    "dst_port": 80,
    "transport_protocol": "TCP",
    "application_protocol": "HTTP",
}

cases = []

def add_case(name, changes, status, action, config=None):
    event = deepcopy(base)
    event.update(changes)
    cases.append({
        "name": name,
        "input": event,
        "config": config,
        "expected_status": status,
        "expected_action": action,
    })

add_case("invalid_ip", {"src_ip": "999.1.1.1"}, "invalid", "skip")
add_case("port_too_large", {"dst_port": 70000}, "invalid", "skip")
add_case("negative_port", {"src_port": -1}, "invalid", "skip")
add_case("fractional_port", {"src_port": 12.5}, "invalid", "skip")
add_case("invalid_timestamp", {"timestamp": "abc"}, "invalid", "skip")
add_case("infinite_timestamp", {"timestamp": "inf"}, "invalid", "skip")
add_case("missing_required_ip", {"dst_ip": None}, "invalid", "skip")

unsupported = {
    "transport_protocol": "UNKNOWN",
    "src_port": None,
    "dst_port": None,
}
add_case("unsupported_skip", unsupported, "partial", "skip")
add_case(
    "unsupported_continue",
    unsupported,
    "partial",
    "continue",
    {"skip_unsupported": False},
)
add_case(
    "invalid_continue",
    {"dst_port": 70000},
    "invalid",
    "continue",
    {"skip_invalid": False},
)
add_case(
    "malformed_application",
    {"application": ["wrong_type"]},
    "partial",
    "continue",
)

# Event không phải dictionary.
cases.append({
    "name": "non_dictionary",
    "input": None,
    "config": None,
    "expected_status": "invalid",
    "expected_action": "skip",
})

# Packet/event tốt phía sau phải tiếp tục xử lý bình thường.
add_case("valid_after_errors", {}, "valid", "continue")

(folder / "input.jsonl").write_text(
    "".join(
        json.dumps(case, ensure_ascii=False) + "\n"
        for case in cases
    ),
    encoding="utf-8",
)

results = []

for case in cases:
    result = preprocess_event(
        deepcopy(case["input"]),
        config=case["config"],
    )

    assert result["preprocess_status"] == case["expected_status"], (
        f'{case["name"]}: sai preprocess_status'
    )
    assert result["processing_action"] == case["expected_action"], (
        f'{case["name"]}: sai processing_action'
    )

    if case["expected_status"] != "valid":
        assert result["reason"], f'{case["name"]}: thiếu reason'
    else:
        assert result["reason"] == []

    results.append({"name": case["name"], "event": result})
    print(f'PASS: {case["name"]}')

(folder / "result.jsonl").write_text(
    "".join(
        json.dumps(result, ensure_ascii=False) + "\n"
        for result in results
    ),
    encoding="utf-8",
)

print(f"PASS T08: {len(cases)} cases")
