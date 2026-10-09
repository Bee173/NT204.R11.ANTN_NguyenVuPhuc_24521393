import json
from pathlib import Path

result = Path(__file__).parent / "result.jsonl"

with result.open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

event = events[0] if len(events) == 1 else {}
application = event.get("application", {})

passed = (
    len(events) == 1
    and event.get("transport_protocol") == "TCP"
    and event.get("src_port") == 25
    and event.get("application_protocol") == "SMTP"
    and application.get("type") == "RESPONSE"
    and application.get("status_code") == 250
    and application.get("message") == "OK"
    and not event.get("parse_errors")
)

if passed:
    print("PASS: SMTP response was parsed correctly")
    print("Status: 250 OK")
else:
    print("FAIL: SMTP response result is incorrect")
    raise SystemExit(1)