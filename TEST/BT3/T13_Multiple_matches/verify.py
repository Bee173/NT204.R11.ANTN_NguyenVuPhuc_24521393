import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_path = folder / "result.jsonl"

if not result_path.exists():
    print("FAIL T13: chưa có result.jsonl")
    raise SystemExit(1)

with result_path.open(encoding="utf-8") as file:
    results = [json.loads(line) for line in file if line.strip()]

assert results == [
    {
        "event_id": "two_rules_match",
        "detection_sids": [101301, 101302],
    },
    {
        "event_id": "one_rule_matches",
        "detection_sids": [101302],
    },
]

print("PASS T13: một event sinh đầy đủ kết quả từ nhiều rule cùng match")
