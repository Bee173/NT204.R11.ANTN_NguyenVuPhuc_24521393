import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_file = folder / "result.jsonl"

if not result_file.exists():
    print("FAIL T06: result.jsonl chưa được tạo")
    raise SystemExit(1)

with result_file.open(encoding="utf-8") as file:
    results = [json.loads(line) for line in file if line.strip()]

assert results == [
    {"event_id": "specific_tcp", "candidate_sids": [100601, 100602]},
    {"event_id": "other_tcp", "candidate_sids": [100602]},
    {"event_id": "dns_udp", "candidate_sids": [100603]},
]

print("PASS T06: Indexer trả đúng candidate cho IP, TCP, UDP và any")
