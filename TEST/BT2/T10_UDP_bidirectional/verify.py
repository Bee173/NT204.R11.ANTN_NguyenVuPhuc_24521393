import json
from pathlib import Path
from scapy.all import PcapReader

folder = Path(__file__).resolve().parent

with (folder / "result.jsonl").open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

with PcapReader(str(folder / "udp_dns.pcap")) as reader:
    sizes = [len(packet) for packet in reader]

assert len(events) == 2
query, response = events

for event in events:
    assert event["track_status"] == "tracked"
    assert event["transport_protocol"] == "UDP"
    assert event["application_protocol"] == "DNS"

assert query["application"]["type"] == "QUERY"
assert response["application"]["type"] == "RESPONSE"
assert query["flow_id"] == response["flow_id"]
assert query["direction"] == "forward"
assert response["direction"] == "backward"

flow = response["flow"]

assert flow["protocol"] == "UDP"
assert flow["application_protocol"] == "DNS"
assert flow["state"] == "ACTIVE"

assert flow["endpoint_a"] == {"ip": "10.0.0.1", "port": 12345}
assert flow["endpoint_b"] == {"ip": "10.0.0.2", "port": 53}

assert flow["packet_count"] == 2
assert flow["forward_packet_count"] == 1
assert flow["backward_packet_count"] == 1

assert flow["byte_count"] == sum(sizes)
assert flow["forward_byte_count"] == sizes[0]
assert flow["backward_byte_count"] == sizes[1]

assert flow["start_time"] == 1000
assert flow["last_seen"] == 1001
assert flow["duration"] == 1.0

for counter in ("SYN_count", "ACK_count", "FIN_count", "RST_count"):
    assert flow[counter] == 0

# Snapshot của query không bị response sửa lại.
assert query["flow"]["packet_count"] == 1

print("PASS T10: DNS UDP hai chiều cùng flow, direction và thống kê đúng")
