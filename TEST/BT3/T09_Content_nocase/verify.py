import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_path = folder / "result.jsonl"

if not result_path.exists():
    print("FAIL T09: chưa có result.jsonl")
    raise SystemExit(1)

with result_path.open(encoding="utf-8") as file:
    results = [json.loads(line) for line in file if line.strip()]

assert results == [
    {
        "event_id": "uppercase_login",
        "detection_sids": [100901, 100902],
    },
    {
        "event_id": "lowercase_login",
        "detection_sids": [100902],
    },
    {
        "event_id": "unrelated_content",
        "detection_sids": [],
    },
]

print("PASS T09: content phân biệt hoa thường và nocase hoạt động đúng")
