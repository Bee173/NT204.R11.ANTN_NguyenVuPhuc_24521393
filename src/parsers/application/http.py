from scapy.packet import Raw


def get_http_payload(packet):
    if Raw not in packet:
        return ""

    try:
        return bytes(packet[Raw].load).decode("utf-8", errors="replace",)
    except Exception:
        return ""


def parse_headers(lines):
    headers = {}

    for line in lines:
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()

    return headers


def parse_http(packet):
    result = {
        "type": "UNKNOWN",
        "method": None,
        "path": None,
        "version": None,
        "status_code": None,
        "reason": None,
        "headers": {},
        "body": None,
    }

    payload = get_http_payload(packet)

    if not payload:
        return result

    header_text, separator, body = payload.partition(
        "\r\n\r\n"
    )

    lines = header_text.split("\r\n")

    if not lines:
        return result

    start_line = lines[0]
    parts = start_line.split()

    # HTTP response
    # Example: HTTP/1.1 200 OK
    if start_line.upper().startswith("HTTP/"):
        result["type"] = "RESPONSE"

        if len(parts) >= 1:
            result["version"] = parts[0]

        if len(parts) >= 2:
            try:
                result["status_code"] = int(parts[1])
            except ValueError:
                pass

        if len(parts) >= 3:
            result["reason"] = " ".join(parts[2:])

    # HTTP request
    # Example: GET /index.html HTTP/1.1
    else:
        result["type"] = "REQUEST"

        if len(parts) >= 1:
            result["method"] = parts[0]

        if len(parts) >= 2:
            result["path"] = parts[1]

        if len(parts) >= 3:
            result["version"] = parts[2]

    result["headers"] = parse_headers(lines[1:])

    if separator:
        result["body"] = body

    return result