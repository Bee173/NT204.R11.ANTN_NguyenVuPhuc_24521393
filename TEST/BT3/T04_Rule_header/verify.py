import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_file = folder / "result.jsonl"

if not result_file.exists():
    print("FAIL T04: result.jsonl chưa được tạo")
    raise SystemExit(1)

with result_file.open(encoding="utf-8") as file:
    rules = [json.loads(line) for line in file if line.strip()]

assert [rule["status"] for rule in rules] == ["valid", "valid"]
assert [rule["header"] for rule in rules] == [
    {
        "action": "alert",
        "protocol": "tcp",
        "src_ip": "any",
        "src_port": "any",
        "direction": "->",
        "dst_ip": "192.168.1.10",
        "dst_port": "80",
    },
    {
        "action": "alert",
        "protocol": "tcp",
        "src_ip": "10.0.0.0/24",
        "src_port": "1024:65535",
        "direction": "->",
        "dst_ip": "any",
        "dst_port": "8000:8080",
    },
]

print("PASS T04: header any/IPv4/CIDR và port/range được parse đúng")
