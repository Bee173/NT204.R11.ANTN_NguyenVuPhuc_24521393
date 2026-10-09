import json
from pathlib import Path

folder = Path(__file__).resolve().parent

with (folder / "result.jsonl").open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

assert len(events) == 1, "Phải có đúng 1 event"

event = events[0]
application = event["application"]

assert event["application_protocol"] == "HTTP"
assert application["path"] == "/search?q=%27%20OR%201%3D1", (
    "URI gốc bị thay đổi"
)
assert application["decoded_path"] == "/search?q=' OR 1=1", (
    "URI giải mã không đúng"
)
assert event["decode_status"] == "success"
assert event["decode_errors"] == []

print("PASS T01: decoded URI đúng, raw URI giữ nguyên")