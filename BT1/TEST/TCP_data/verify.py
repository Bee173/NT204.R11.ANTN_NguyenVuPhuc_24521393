import json
from pathlib import Path

result = Path(__file__).parent / "result.jsonl"

with result.open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

passed = (
    len(events) == 1
    and events[0]["transport_protocol"] == "TCP"
    and events[0]["payload_length"] == 9
    and not events[0]["parse_errors"]
)

if passed:
    print("PASS: TCP data was parsed correctly")
    print("Payload length: 9 bytes")
else:
    print("FAIL: TCP data result is incorrect")
    raise SystemExit(1)