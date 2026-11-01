import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_path = folder / "result.jsonl"

if not result_path.exists():
    print("FAIL T12: chưa có result.jsonl")
    raise SystemExit(1)

with result_path.open(encoding="utf-8") as file:
    results = [json.loads(line) for line in file if line.strip()]

assert results == [
    {
        "event_id": "flags_and_dsize_match",
        "detection_sids": [101201],
    },
    {
        "event_id": "flags_mismatch",
        "detection_sids": [],
    },
    {
        "event_id": "dsize_mismatch",
        "detection_sids": [],
    },
]

print("PASS T12: flags và dsize match đúng theo event")
