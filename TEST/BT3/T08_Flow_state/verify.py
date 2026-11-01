import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_path = folder / "result.jsonl"

if not result_path.exists():
    print("FAIL T08: chưa có result.jsonl")
    raise SystemExit(1)

with result_path.open(encoding="utf-8") as file:
    results = [json.loads(line) for line in file if line.strip()]

assert results == [
    {
        "event_id": "to_server_established",
        "detection_sids": [100801],
    },
    {
        "event_id": "to_client_established",
        "detection_sids": [],
    },
    {
        "event_id": "to_server_handshake",
        "detection_sids": [],
    },
]

print("PASS T08: flow to_server và established được match đúng")
