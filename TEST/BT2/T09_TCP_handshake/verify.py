import json
from pathlib import Path

folder = Path(__file__).resolve().parent

with (folder / "result.jsonl").open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

assert len(events) == 3
assert all(event["track_status"] == "tracked" for event in events)
assert len({event["flow_id"] for event in events}) == 1

assert [event["direction"] for event in events] == [
    "forward", "backward", "forward",
]
assert [event["flow"]["state"] for event in events] == [
    "HANDSHAKE", "HANDSHAKE", "ESTABLISHED",
]

flow = events[-1]["flow"]

assert flow["packet_count"] == 3
assert flow["forward_packet_count"] == 2
assert flow["backward_packet_count"] == 1

assert flow["byte_count"] == sum(
    event["packet_length"] for event in events
)
assert flow["forward_byte_count"] == (
    events[0]["packet_length"] + events[2]["packet_length"]
)
assert flow["backward_byte_count"] == events[1]["packet_length"]

assert flow["SYN_count"] == 2
assert flow["ACK_count"] == 2
assert flow["FIN_count"] == 0
assert flow["RST_count"] == 0
assert flow["duration"] == 2.0

print("PASS T09: một flow hai chiều, ESTABLISHED, counters đúng")
