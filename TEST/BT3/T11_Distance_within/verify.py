import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_path = folder / "result.jsonl"

if not result_path.exists():
    print("FAIL T11: chưa có result.jsonl")
    raise SystemExit(1)

with result_path.open(encoding="utf-8") as file:
    results = [json.loads(line) for line in file if line.strip()]

assert results == [
    {
        "event_id": "relative_content_match",
        "detection_sids": [101101],
    },
    {
        "event_id": "second_content_too_close",
        "detection_sids": [],
    },
    {
        "event_id": "second_content_outside_within",
        "detection_sids": [],
    },
]

print("PASS T11: distance và within relative matching hoạt động đúng")
