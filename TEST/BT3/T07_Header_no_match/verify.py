import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_path = folder / "result.jsonl"

if not result_path.exists():
    print("FAIL T07: chưa có result.jsonl")
    raise SystemExit(1)

with result_path.open(encoding="utf-8") as file:
    results = [json.loads(line) for line in file if line.strip()]

assert results == [{
    "event_id": "header_miss",
    "candidate_rules": 0,
    "matches": 0,
    "detection_sids": [],
}]

print("PASS T07: header không match bị loại trước content matching")
