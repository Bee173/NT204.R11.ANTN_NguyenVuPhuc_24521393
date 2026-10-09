import json
from pathlib import Path
from scapy.all import PcapReader

folder = Path(__file__).resolve().parent

with (folder / "result.jsonl").open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

with PcapReader(str(folder / "concurrent_flows.pcap")) as reader:
    sizes = [len(packet) for packet in reader]

assert len(events) == 8
assert all(event["track_status"] == "tracked" for event in events)

forward_ids = [event["flow_id"] for event in events[:4]]
assert len(set(forward_ids)) == 4, "Các flow khác nhau bị gộp nhầm"

for index in range(4):
    forward = events[index]
    backward = events[index + 4]
    flow = backward["flow"]

    assert forward["flow_id"] == backward["flow_id"]
    assert forward["direction"] == "forward"
    assert backward["direction"] == "backward"

    assert forward["flow"]["packet_count"] == 1
    assert flow["packet_count"] == 2
    assert flow["forward_packet_count"] == 1
    assert flow["backward_packet_count"] == 1

    assert flow["byte_count"] == sizes[index] + sizes[index + 4]
    assert flow["forward_byte_count"] == sizes[index]
    assert flow["backward_byte_count"] == sizes[index + 4]
    assert flow["duration"] == 4.0

# Cùng IP và port nhưng khác transport protocol.
assert events[0]["flow_id"] != events[2]["flow_id"]

# Cùng IP nhưng khác source port.
assert events[0]["flow_id"] != events[1]["flow_id"]

# Cùng port và protocol nhưng khác destination IP.
assert events[0]["flow_id"] != events[3]["flow_id"]

print("PASS T11: 4 flow xen kẽ được tách đúng, hai chiều ghép đúng")
