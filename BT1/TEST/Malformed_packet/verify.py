import json
from pathlib import Path

result = Path(__file__).parent / "result.jsonl"

if not result.exists():
    print("FAIL: result.jsonl does not exist")
    raise SystemExit(1)

with result.open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

event = events[0] if len(events) == 1 else {}

passed = (
    len(events) == 1
    and event.get("transport_protocol") == "UNKNOWN"
    and event.get("application_protocol") == "UNKNOWN"
    and isinstance(event.get("parse_errors"), list)
)

if passed:
    print("PASS: Malformed packet was handled correctly")
    print("The program did not crash")
    print(f"Parse errors: {event['parse_errors']}")
else:
    print("FAIL: Malformed packet result is incorrect")
    raise SystemExit(1)