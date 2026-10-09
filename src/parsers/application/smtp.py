from scapy.packet import Raw


SMTP_COMMANDS = (
    "HELO",
    "EHLO",
    "MAIL FROM",
    "RCPT TO",
    "DATA",
    "QUIT",
    "RSET",
    "NOOP",
)


def get_smtp_payload(packet):
    """
    Get SMTP payload and decode it safely.
    """
    if Raw not in packet:
        return ""

    try:
        return bytes(packet[Raw].load).decode(
            "utf-8",
            errors="replace",
        )
    except Exception:
        return ""


def parse_smtp_response(line):
    """
    Parse SMTP response.

    Example:
        250 OK
    """
    result = {
        "type": "RESPONSE",
        "command": None,
        "argument": None,
        "status_code": None,
        "message": None,
    }

    if len(line) < 3:
        return result

    try:
        result["status_code"] = int(
            line[:3]
        )
    except ValueError:
        return result

    if len(line) > 4:
        result["message"] = line[4:].strip()

    return result


def parse_smtp_command(line):
    """
    Parse common SMTP commands.
    """
    result = {
        "type": "UNKNOWN",
        "command": None,
        "argument": None,
        "status_code": None,
        "message": None,
    }

    upper_line = line.upper()

    # MAIL FROM and RCPT TO need special handling
    # because they contain a colon.
    if upper_line.startswith("MAIL FROM:"):
        result["type"] = "COMMAND"
        result["command"] = "MAIL FROM"

        result["argument"] = line[
            len("MAIL FROM:"):
        ].strip()

        return result

    if upper_line.startswith("RCPT TO:"):
        result["type"] = "COMMAND"
        result["command"] = "RCPT TO"

        result["argument"] = line[
            len("RCPT TO:"):
        ].strip()

        return result

    parts = line.split(
        None,
        1,
    )

    if not parts:
        return result

    command = parts[0].upper()

    if command not in SMTP_COMMANDS:
        return result

    result["type"] = "COMMAND"
    result["command"] = command

    if len(parts) == 2:
        result["argument"] = parts[1].strip()

    return result


def parse_smtp(packet):
    """
    Parse SMTP command or response.
    """
    result = {
        "type": "UNKNOWN",
        "command": None,
        "argument": None,
        "status_code": None,
        "message": None,
    }

    payload = get_smtp_payload(packet)

    if not payload:
        return result

    lines = payload.splitlines()

    if not lines:
        return result

    first_line = lines[0].strip()

    if not first_line:
        return result

    # SMTP response begins with a 3-digit status code.
    if (
        len(first_line) >= 3
        and first_line[:3].isdigit()
    ):
        return parse_smtp_response(
            first_line
        )

    return parse_smtp_command(
        first_line
    )