import hashlib
import json
from copy import deepcopy


class FlowTracker:
    def __init__(self):
        self.active_flows = {}

    def track_event(self, event):
        event["flow_id"] = None
        event["direction"] = None
        event["track_status"] = "skipped"

        if event.get("processing_action") == "skip":
            return event

        protocol = event.get("transport_protocol")
        if protocol not in {"TCP", "UDP"}:
            return event

        required = (
            "src_ip", "dst_ip", "src_port",
            "dst_port", "timestamp", "packet_length",
        )
        if any(event.get(field) is None for field in required):
            event["track_reason"] = "missing flow fields"
            return event

        source = (event["src_ip"], event["src_port"])
        destination = (event["dst_ip"], event["dst_port"])

        endpoint_a, endpoint_b = sorted([source, destination])
        key = (protocol, endpoint_a, endpoint_b)
        direction = "forward" if source == endpoint_a else "backward"
        timestamp = event["timestamp"]

        if key not in self.active_flows:
            key_text = json.dumps(key, separators=(",", ":"))
            flow_id = hashlib.sha256(key_text.encode()).hexdigest()[:24]

            self.active_flows[key] = {
                "flow_id": flow_id,
                "protocol": protocol,
                "application_protocol": "UNKNOWN",
                "endpoint_a": {
                    "ip": endpoint_a[0], "port": endpoint_a[1],
                },
                "endpoint_b": {
                    "ip": endpoint_b[0], "port": endpoint_b[1],
                },
                "start_time": timestamp,
                "last_seen": timestamp,
                "duration": 0.0,
                "packet_count": 0,
                "byte_count": 0,
                "forward_packet_count": 0,
                "backward_packet_count": 0,
                "forward_byte_count": 0,
                "backward_byte_count": 0,
                "SYN_count": 0,
                "ACK_count": 0,
                "FIN_count": 0,
                "RST_count": 0,
                "state": "NEW" if protocol == "TCP" else "ACTIVE",
                "_syn_source": None,
                "_synack_seen": False,
            }

        flow = self.active_flows[key]
        size = event["packet_length"]

        flow["start_time"] = min(flow["start_time"], timestamp)
        flow["last_seen"] = max(flow["last_seen"], timestamp)
        flow["duration"] = flow["last_seen"] - flow["start_time"]

        flow["packet_count"] += 1
        flow["byte_count"] += size
        flow[f"{direction}_packet_count"] += 1
        flow[f"{direction}_byte_count"] += size

        application_protocol = event.get("application_protocol", "UNKNOWN")
        if application_protocol != "UNKNOWN":
            flow["application_protocol"] = application_protocol

        if protocol == "TCP":
            flags = (event.get("transport") or {}).get("tcp_flags") or ""

            for flag, counter in (
                ("S", "SYN_count"),
                ("A", "ACK_count"),
                ("F", "FIN_count"),
                ("R", "RST_count"),
            ):
                if flag in flags:
                    flow[counter] += 1

            # Ghi nhận bên khởi tạo kết nối.
            if "S" in flags and "A" not in flags:
                if flow["state"] == "NEW":
                    flow["_syn_source"] = source
                    flow["state"] = "HANDSHAKE"

            # SYN/ACK phải đến từ bên đối diện.
            elif "S" in flags and "A" in flags:
                if (
                    flow["state"] == "HANDSHAKE"
                    and source != flow["_syn_source"]
                ):
                    flow["_synack_seen"] = True

            # ACK cuối phải đến từ bên khởi tạo.
            elif "A" in flags and "F" not in flags and "R" not in flags:
                if (
                    flow["state"] == "HANDSHAKE"
                    and flow["_synack_seen"]
                    and source == flow["_syn_source"]
                ):
                    flow["state"] = "ESTABLISHED"

        event["flow_id"] = flow["flow_id"]
        event["direction"] = direction
        event["track_status"] = "tracked"

        # Snapshot riêng để packet sau không sửa kết quả packet trước.
        event["flow"] = deepcopy({
            name: value
            for name, value in flow.items()
            if not name.startswith("_")
        })
        return event
