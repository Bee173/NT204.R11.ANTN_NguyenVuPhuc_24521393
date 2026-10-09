import json
from pathlib import Path

result = Path(__file__).parent / "result.jsonl"

with result.open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

event = events[0] if len(events) == 1 else {}
application = event.get("application", {})
headers = application.get("headers", {})

passed = (
    len(events) == 1
    and event.get("transport_protocol") == "TCP"
    and event.get("application_protocol") == "HTTP"
    and application.get("type") == "RESPONSE"
    and application.get("version") == "HTTP/1.1"
    and application.get("status_code") == 200
    and application.get("reason") == "OK"
    and headers.get("Content-Type") == "text/plain"
    and headers.get("Content-Length") == "5"
    and headers.get("Server") == "IDPS-Test"
    and application.get("body") == "Hello"
    and not event.get("parse_errors")
)

if passed:
    print("PASS: HTTP response was parsed correctly")
    print("Status: 200 OK")
else:
    print("FAIL: HTTP response result is incorrect")
    raise SystemExit(1)