import json
from pathlib import Path
from scapy.all import PcapReader, IP, TCP

folder = Path(__file__).resolve().parent

def read_jsonl(name):
    with (folder / name).open(encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]

events = read_jsonl("result.jsonl")
flows = read_jsonl("flows.jsonl")

with PcapReader(str(folder / "statistics.pcap")) as reader:
    packets = list(reader)

assert len(events) == len(packets) == 8
assert len(flows) == 1
assert all(event["track_status"] == "tracked" for event in events)

flow = flows[0]

forward = [
    packet for packet in packets
    if packet[IP].src == "10.0.0.1"
]
backward = [
    packet for packet in packets
    if packet[IP].src == "10.0.0.2"
]

assert flow["packet_count"] == 8
assert flow["forward_packet_count"] == len(forward) == 5
assert flow["backward_packet_count"] == len(backward) == 3

assert flow["byte_count"] == sum(len(packet) for packet in packets)
assert flow["forward_byte_count"] == sum(len(packet) for packet in forward)
assert flow["backward_byte_count"] == sum(len(packet) for packet in backward)

assert flow["byte_count"] == (
    flow["forward_byte_count"] + flow["backward_byte_count"]
)

for flag, counter in (
    ("S", "SYN_count"),
    ("A", "ACK_count"),
    ("F", "FIN_count"),
    ("R", "RST_count"),
):
    expected = sum(flag in str(packet[TCP].flags) for packet in packets)
    assert flow[counter] == expected, f"Sai {counter}"

assert flow["SYN_count"] == 2
assert flow["ACK_count"] == 7
assert flow["FIN_count"] == 2
assert flow["RST_count"] == 0

assert flow["start_time"] == 1000
assert flow["last_seen"] == 1007
assert flow["duration"] == 7.0
assert flow["state"] == "CLOSED"
assert flow["export_reason"] == "connection_closed"

assert all(event["flow_id"] == flow["flow_id"] for event in events)
assert [event["flow"]["packet_count"] for event in events] == list(range(1, 9))

assert events[3]["payload_length"] == 5
assert events[4]["payload_length"] == 6
assert flow["byte_count"] > 11, "Phải tính cả header và packet không payload"

print("PASS T14: packet/byte/flags/duration và snapshot đúng")
