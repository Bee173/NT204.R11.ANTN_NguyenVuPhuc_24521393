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
    and event.get("dst_port") == 9000
    and event.get("application_protocol") == "HTTP"
    and application.get("type") == "REQUEST"
    and application.get("method") == "GET"
    and application.get("path") == "/index.html"
    and application.get("version") == "HTTP/1.1"
    and application.get("headers", {}).get("Host") == "example.com"
    and not event.get("parse_errors")
)

if passed:
    print("PASS: HTTP GET was parsed correctly")
    print("HTTP was detected on non-standard port 9000")
else:
    print("FAIL: HTTP GET result is incorrect")
    raise SystemExit(1)