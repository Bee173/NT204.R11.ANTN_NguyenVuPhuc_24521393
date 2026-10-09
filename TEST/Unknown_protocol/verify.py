import json
from pathlib import Path

result = Path(__file__).parent / "result.jsonl"

with result.open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

event = events[0] if len(events) == 1 else {}

passed = (
    len(events) == 1
    and event.get("network_protocol") == "IPv4"
    and event.get("transport_protocol") == "UNKNOWN"
    and event.get("application_protocol") == "UNKNOWN"
    and event.get("src_ip") == "10.0.0.1"
    and event.get("dst_ip") == "10.0.0.2"
    and not event.get("parse_errors")
)

if passed:
    print("PASS: Unknown protocol was handled correctly")
    print("The program did not crash")
else:
    print("FAIL: Unknown protocol result is incorrect")
    raise SystemExit(1)