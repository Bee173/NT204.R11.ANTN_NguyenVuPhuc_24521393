from scapy.layers.dns import DNS


DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}


def decode_dns_value(value):
    """
    Convert DNS bytes to readable text.
    """
    if isinstance(value, bytes):
        return value.decode(
            "utf-8",
            errors="replace",
        ).rstrip(".")

    return str(value)


def get_dns_type(record_type):
    """
    Convert DNS record type number to readable name.
    """
    try:
        record_type = int(record_type)
    except (TypeError, ValueError):
        return str(record_type)

    return DNS_TYPES.get(
        record_type,
        str(record_type),
    )


def get_dns_record(field, index):
    """
    Safely get a DNS record from a Scapy DNS field.

    Different Scapy versions may represent DNS records
    differently, so this helper handles both indexed
    and chained representations.
    """
    if field is None:
        return None

    try:
        return field[index]
    except Exception:
        pass

    if index == 0:
        return field

    current = field

    for _ in range(index):
        try:
            current = current.payload
        except Exception:
            return None

        if current is None:
            return None

        if current.__class__.__name__ == "NoPayload":
            return None

    return current


def parse_dns(packet):
    """
    Parse DNS query or response.
    """
    result = {
        "type": "UNKNOWN",
        "transaction_id": None,
        "query": None,
        "query_type": None,
        "answers": [],
    }

    if DNS not in packet:
        return result

    dns = packet[DNS]

    # Transaction ID
    try:
        result["transaction_id"] = int(dns.id)
    except Exception:
        pass

    # qr = 0: query
    # qr = 1: response
    try:
        if int(dns.qr) == 1:
            result["type"] = "RESPONSE"
        else:
            result["type"] = "QUERY"
    except Exception:
        pass

    # Parse query
    try:
        question = get_dns_record(dns.qd, 0)

        if question is not None:
            result["query"] = decode_dns_value(
                question.qname
            )

            result["query_type"] = get_dns_type(
                question.qtype
            )

    except Exception:
        pass

    # Parse answers
    try:
        answer_count = int(dns.ancount or 0)
    except Exception:
        answer_count = 0

    for index in range(answer_count):
        answer = get_dns_record(
            dns.an,
            index,
        )

        if answer is None:
            continue

        try:
            parsed_answer = {
                "name": decode_dns_value(
                    answer.rrname
                ),
                "type": get_dns_type(
                    answer.type
                ),
                "ttl": int(answer.ttl),
                "data": decode_dns_value(
                    answer.rdata
                ),
            }

            result["answers"].append(
                parsed_answer
            )

        except Exception:
            continue

    return result