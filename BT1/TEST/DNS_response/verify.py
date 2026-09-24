import json
from pathlib import Path

result = Path(__file__).parent / "result.jsonl"

with result.open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

event = events[0] if len(events) == 1 else {}
application = event.get("application", {})
answers = application.get("answers", [])
answer = answers[0] if answers else {}

passed = (
    len(events) == 1
    and event.get("transport_protocol") == "UDP"
    and event.get("src_port") == 53
    and event.get("application_protocol") == "DNS"
    and application.get("type") == "RESPONSE"
    and application.get("transaction_id") == 0x1234
    and application.get("query") == "example.com"
    and application.get("query_type") == "A"
    and len(answers) >= 1
    and answer.get("name") == "example.com"
    and answer.get("type") == "A"
    and answer.get("ttl") == 300
    and answer.get("data") == "93.184.216.34"
    and not event.get("parse_errors")
)

if passed:
    print("PASS: DNS response was parsed correctly")
    print("Answer: example.com -> 93.184.216.34")
else:
    print("FAIL: DNS response result is incorrect")
    raise SystemExit(1)