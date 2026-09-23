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
    and application.get("type") == "REQUEST"
    and application.get("method") == "POST"
    and application.get("path") == "/login"
    and application.get("version") == "HTTP/1.1"
    and headers.get("Host") == "example.com"
    and headers.get("Content-Length") == "20"
    and application.get("body") == "username=test&pass=1"
    and not event.get("parse_errors")
)

if passed:
    print("PASS: HTTP POST was parsed correctly")
    print(f"Body: {application['body']}")
else:
    print("FAIL: HTTP POST result is incorrect")
    raise SystemExit(1)