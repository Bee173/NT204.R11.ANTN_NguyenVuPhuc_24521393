import json
import sys
from pathlib import Path

folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))

from src.flow_tracker import FlowTracker
from src.preprocessor import preprocess_event


def make_event(protocol, timestamp):
    return preprocess_event({
        "timestamp": timestamp,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 12000,
        "dst_port": 9000,
        "transport_protocol": protocol,
        "application_protocol": "UNKNOWN",
        "packet_length": 60,
        "payload_length": 0,
        "transport": {
            "tcp_flags": "S" if protocol == "TCP" else None,
            "sequence_number": 100,
            "acknowledgment_number": 0,
        },
    })


tracker = FlowTracker(tcp_timeout=10, udp_timeout=5)

tcp = tracker.track_event(make_event("TCP", 1000))
udp = tracker.track_event(make_event("UDP", 1000))
assert len(tracker.active_flows) == 2

# Đúng bằng timeout: UDP chưa hết hạn.
tracker.expire_flows(1005)
assert len(tracker.active_flows) == 2
assert tracker.drain_finished() == []

# UDP hết hạn, TCP vẫn còn.
tracker.expire_flows(1006)
udp_exports = tracker.drain_finished()

assert len(tracker.active_flows) == 1
assert len(udp_exports) == 1
assert udp_exports[0]["flow_id"] == udp["flow_id"]
assert udp_exports[0]["state"] == "EXPIRED"
assert udp_exports[0]["export_reason"] == "idle_timeout"
assert udp_exports[0]["packet_count"] == 1
assert udp_exports[0]["byte_count"] == 60
assert udp_exports[0]["duration"] == 0

# TCP hết hạn.
tracker.expire_flows(1011)
tcp_exports = tracker.drain_finished()

assert tracker.active_flows == {}
assert len(tcp_exports) == 1
assert tcp_exports[0]["flow_id"] == tcp["flow_id"]

# Dùng lại 5-tuple: tạo phiên mới với flow_id khác.
new_udp = tracker.track_event(make_event("UDP", 1012))
assert new_udp["flow_id"] != udp["flow_id"]
assert new_udp["flow"]["packet_count"] == 1

# Khi kết thúc capture: xuất và giải phóng flow còn lại.
tracker.flush()
final_exports = tracker.drain_finished()

assert tracker.active_flows == {}
assert len(final_exports) == 1
assert final_exports[0]["export_reason"] == "capture_end"
assert tracker.drain_finished() == []

results = udp_exports + tcp_exports + final_exports
(folder / "result.jsonl").write_text(
    "".join(json.dumps(flow) + "\n" for flow in results),
    encoding="utf-8",
)

print("PASS T13: TCP/UDP timeout, giải phóng bảng, ID phiên mới, flush")
