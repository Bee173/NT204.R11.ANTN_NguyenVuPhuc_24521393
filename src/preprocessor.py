import math
from ipaddress import ip_address


def preprocess_event(event, config=None):
    config = config or {}
    skip_invalid = config.get("skip_invalid", True)
    skip_unsupported = config.get("skip_unsupported", True)

    if not isinstance(event, dict):
        return {
            "preprocess_status": "invalid",
            "processing_action": "skip",
            "reason": ["event must be a dictionary"],
        }

    invalid = []
    partial = []

    # Chuẩn hóa tên protocol.
    for field in ("transport_protocol", "application_protocol"):
        value = event.get(field)
        if value is None:
            event[field] = "UNKNOWN"
        elif isinstance(value, str):
            event[field] = value.strip().upper() or "UNKNOWN"
        else:
            event[field] = "UNKNOWN"
            invalid.append(f"{field}: invalid type")

    # Kiểm tra và chuẩn hóa IP.
    for field in ("src_ip", "dst_ip"):
        value = event.get(field)
        try:
            if not isinstance(value, str):
                raise ValueError("missing or invalid IP")
            event[field] = str(ip_address(value.strip()))
        except ValueError:
            event[field] = None
            invalid.append(f"{field}: missing or invalid IP")

    # Timestamp: Unix seconds, hữu hạn và không âm.
    try:
        value = event.get("timestamp")
        if isinstance(value, bool) or value is None:
            raise ValueError()
        timestamp = float(value)
        if not math.isfinite(timestamp) or timestamp < 0:
            raise ValueError()
        event["timestamp"] = timestamp
    except (ValueError, TypeError, OverflowError):
        event["timestamp"] = None
        invalid.append("timestamp: missing or invalid")

    protocol = event["transport_protocol"]
    supported = protocol in {"TCP", "UDP"}

    if not supported:
        partial.append("transport_protocol: unsupported")

    # TCP/UDP cần port hợp lệ.
    for field in ("src_port", "dst_port"):
        value = event.get(field)
        if not supported and value is None:
            event[field] = None
            continue

        try:
            if isinstance(value, bool):
                raise ValueError()
            if isinstance(value, str):
                port = int(value.strip())
            elif isinstance(value, int):
                port = value
            else:
                raise ValueError()
            if not 0 <= port <= 65535:
                raise ValueError()
            event[field] = port
        except (ValueError, TypeError):
            event[field] = None
            invalid.append(f"{field}: missing or invalid port")

    # Validate byte lengths before flow statistics.
    for field in ("packet_length", "payload_length"):
        value = event.get(field)

        if value is None:
            event[field] = 0 if field == "payload_length" else None
        elif isinstance(value, bool) or not isinstance(value, int) or value < 0:
            event[field] = None
            invalid.append(f"{field}: invalid byte length")

    packet_length = event.get("packet_length")
    payload_length = event.get("payload_length")
    if isinstance(packet_length, int) and isinstance(payload_length, int):
        if payload_length > packet_length:
            invalid.append("payload_length exceeds packet_length")

    # Các object và danh sách luôn có kiểu nhất quán.
    for field in ("network", "transport", "application"):
        value = event.get(field)
        if value is None:
            event[field] = {}
        elif not isinstance(value, dict):
            event[field] = {}
            partial.append(f"{field}: invalid object type")

    for field in ("parse_errors", "decode_errors"):
        value = event.get(field)
        if value is None:
            event[field] = []
        elif not isinstance(value, list):
            event[field] = []
            partial.append(f"{field}: invalid list type")

    # Đồng bộ field cấp ngoài và field trong parser.
    event["network"]["src_ip"] = event["src_ip"]
    event["network"]["dst_ip"] = event["dst_ip"]
    event["transport"]["protocol"] = protocol
    event["transport"]["src_port"] = event["src_port"]
    event["transport"]["dst_port"] = event["dst_port"]

    application = event["application"]
    app_protocol = event["application_protocol"]

    if app_protocol == "HTTP":
        headers = application.get("headers")
        if headers is None:
            headers = {}
        elif not isinstance(headers, dict):
            headers = {}
            partial.append("HTTP headers: invalid object type")

        application.setdefault("raw_headers", dict(headers))
        normalized_headers = {}

        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                partial.append("HTTP header: invalid name or value")
                continue
            key = name.strip().lower()
            if key in normalized_headers:
                partial.append(f"HTTP header: duplicate normalized name {key}")
            normalized_headers[key] = value.strip()

        application["headers"] = normalized_headers

        # Không sửa path: path có thể phân biệt hoa/thường.
        application.setdefault("path", None)
        application.setdefault("body", None)

        host = normalized_headers.get("host")
        application["normalized_host"] = (
            host.lower() if host is not None else None
        )

    elif app_protocol == "DNS":
        query = application.get("query")
        if isinstance(query, str):
            application.setdefault("raw_query", query)
            application["query"] = query.strip().rstrip(".").lower()
        else:
            application["query"] = None
            if query is not None:
                partial.append("DNS query: invalid type")

        if application.get("answers") is None:
            application["answers"] = []
        elif not isinstance(application["answers"], list):
            application["answers"] = []
            partial.append("DNS answers: invalid list type")

    if event["parse_errors"] or event["decode_errors"]:
        partial.append("upstream processing errors")

    status = "invalid" if invalid else "partial" if partial else "valid"
    should_skip = (
        (bool(invalid) and skip_invalid)
        or (not supported and skip_unsupported)
    )

    event["preprocess_status"] = status
    event["processing_action"] = "skip" if should_skip else "continue"
    event["reason"] = invalid + partial
    return event
