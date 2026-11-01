import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_path = folder / "result.jsonl"

if not result_path.exists():
    print("FAIL T10: chưa có result.jsonl")
    raise SystemExit(1)

with result_path.open(encoding="utf-8") as file:
    results = [json.loads(line) for line in file if line.strip()]

assert results == [
    {
        "event_id": "content_in_range",
        "detection_sids": [101001],
    },
    {
        "event_id": "content_before_offset",
        "detection_sids": [],
    },
    {
        "event_id": "content_beyond_depth",
        "detection_sids": [],
    },
]

print("PASS T10: offset và depth chỉ match content trong vùng chỉ định")
