import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_file = folder / "result.jsonl"

if not result_file.exists():
    print("FAIL T01: result.jsonl chưa được tạo")
    raise SystemExit(1)

with result_file.open(encoding="utf-8") as file:
    candidates = [json.loads(line) for line in file if line.strip()]

assert candidates == [
    {
        "raw": (
            "alert tcp any any -> any 80 "
            '(msg:"HTTP request"; sid:100001; rev:1;)'
        ),
        "source": "input.rules",
        "line_number": 3,
    },
    {
        "raw": (
            "alert udp any any <> any 53 "
            '(msg:"DNS traffic"; sid:100002; rev:1;)'
        ),
        "source": "input.rules",
        "line_number": 6,
    },
], "Loader phải chỉ chuyển các dòng rule sang bước parser"

print("PASS T01: comment và dòng trống không được đưa sang parser")
