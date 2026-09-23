import json
from pathlib import Path

result = Path(__file__).parent / "result.jsonl"

with result.open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

passed = (
    len(events) == 1
    and events[0]["network_protocol"] == "IPv4"
    and events[0]["transport_protocol"] == "UDP"
    and events[0]["src_port"] == 40000
    and events[0]["dst_port"] == 5000
    and events[0]["payload_length"] == 9
    and not events[0]["parse_errors"]
)

if passed:
    print("PASS: UDP packet was parsed correctly")
    print("Payload length: 9 bytes")
else:
    print("FAIL: UDP result is incorrect")
    raise SystemExit(1)