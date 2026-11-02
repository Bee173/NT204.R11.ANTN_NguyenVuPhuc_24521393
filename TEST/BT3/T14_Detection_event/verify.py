import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_path = folder / "result.jsonl"

if not result_path.exists():
    print("FAIL T14: chưa có result.jsonl")
    raise SystemExit(1)

with result_path.open(encoding="utf-8") as file:
    results = [json.loads(line) for line in file if line.strip()]

assert results == [{
    "timestamp": 1700000018.25,
    "sid": 101401,
    "rev": 2,
    "msg": "Directory traversal",
    "priority": 1,
    "classtype": "web-application-attack",
    "src_ip": "10.0.0.5",
    "src_port": 52133,
    "dst_ip": "192.168.1.20",
    "dst_port": 80,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "flow_id": "F1401",
    "matched_information": {
        "flow": "to_server,established",
        "content": [{"content": "../", "start": 0, "end": 3}],
        "matched_field": "body",
    },
}]

print("PASS T14: Detection Event có đủ rule, flow, 5-tuple và match info")
