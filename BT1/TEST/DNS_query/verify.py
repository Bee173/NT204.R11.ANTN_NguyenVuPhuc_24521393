import json
from pathlib import Path

result = Path(__file__).parent / "result.jsonl"

with result.open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

event = events[0] if len(events) == 1 else {}
application = event.get("application", {})

passed = (
    len(events) == 1
    and event.get("transport_protocol") == "UDP"
    and event.get("dst_port") == 53
    and event.get("application_protocol") == "DNS"
    and application.get("type") == "QUERY"
    and application.get("transaction_id") == 0x1234
    and application.get("query") == "example.com"
    and application.get("query_type") == "A"
    and not event.get("parse_errors")
)

if passed:
    print("PASS: DNS query was parsed correctly")
    print("Query: example.com")
    print("Query type: A")
else:
    print("FAIL: DNS query result is incorrect")
    raise SystemExit(1)