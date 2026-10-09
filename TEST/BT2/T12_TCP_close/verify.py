import json
from pathlib import Path

folder = Path(__file__).resolve().parent

with (folder / "result.jsonl").open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

assert len(events) == 11
assert all(event["track_status"] == "tracked" for event in events)

fin_events = events[:7]
rst_events = events[7:]

assert len({event["flow_id"] for event in fin_events}) == 1
assert len({event["flow_id"] for event in rst_events}) == 1
assert fin_events[0]["flow_id"] != rst_events[0]["flow_id"]

assert [event["flow"]["state"] for event in fin_events] == [
    "HANDSHAKE",
    "HANDSHAKE",
    "ESTABLISHED",
    "CLOSING",
    "CLOSING",
    "CLOSING",
    "CLOSED",
]

fin_flow = fin_events[-1]["flow"]
assert fin_flow["FIN_count"] == 2
assert fin_flow["RST_count"] == 0
assert fin_flow["SYN_count"] == 2
assert fin_flow["ACK_count"] == 6
assert fin_flow["packet_count"] == 7
assert fin_flow["forward_packet_count"] == 4
assert fin_flow["backward_packet_count"] == 3
assert fin_flow["duration"] == 6.0

assert rst_events[2]["flow"]["state"] == "ESTABLISHED"

rst_flow = rst_events[-1]["flow"]
assert rst_flow["state"] == "RESET"
assert rst_flow["RST_count"] == 1
assert rst_flow["FIN_count"] == 0
assert rst_flow["packet_count"] == 4

print("PASS T12: FIN hai chiều → CLOSED; RST → RESET")
