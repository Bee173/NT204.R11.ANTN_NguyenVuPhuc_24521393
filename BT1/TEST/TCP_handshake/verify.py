import json
from pathlib import Path

RESULT_FILE = Path(__file__).parent / "result.jsonl"
EXPECTED_STATES = ["SYN", "SYN/ACK", "ACK"]


def load_events():
    with RESULT_FILE.open("r", encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def main():
    if not RESULT_FILE.exists():
        print("FAIL: result.jsonl does not exist")
        raise SystemExit(1)

    events = load_events()

    if len(events) != 3:
        print(f"FAIL: Expected 3 events, received {len(events)}")
        raise SystemExit(1)

    actual_states = [
        event["transport"]["tcp_state"] for event in events
    ]

    if actual_states != EXPECTED_STATES:
        print(f"FAIL: Expected {EXPECTED_STATES}")
        print(f"Actual: {actual_states}")
        raise SystemExit(1)

    for index, event in enumerate(events, start=1):
        if event["network_protocol"] != "IPv4":
            print(f"FAIL: Packet {index} is not IPv4")
            raise SystemExit(1)

        if event["transport_protocol"] != "TCP":
            print(f"FAIL: Packet {index} is not TCP")
            raise SystemExit(1)

        if event["parse_errors"]:
            print(f"FAIL: Packet {index}: {event['parse_errors']}")
            raise SystemExit(1)

    print("PASS: TCP handshake was parsed correctly")
    print(f"TCP states: {actual_states}")


if __name__ == "__main__":
    main()