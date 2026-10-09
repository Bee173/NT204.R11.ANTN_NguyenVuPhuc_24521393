import json
import sys
from pathlib import Path

folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))

from src.preprocessor import preprocess_event

inputs = [
    {
        "timestamp": "123.5",
        "src_ip": " 10.0.0.1 ",
        "dst_ip": "10.0.0.2",
        "src_port": "12345",
        "dst_port": "80",
        "transport_protocol": " tcp ",
        "application_protocol": " http ",
        "application": {
            "path": "/Admin/Login",
            "headers": {
                " HOST ": " Example.COM ",
                "Content-Type": " text/plain ",
            },
        },
    },
    {
        "timestamp": 124,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 12345,
        "dst_port": 53,
        "transport_protocol": "udp",
        "application_protocol": "dns",
        "application": {"query": " Example.COM. "},
    },
]

(folder / "input.jsonl").write_text(
    "".join(json.dumps(event) + "\n" for event in inputs),
    encoding="utf-8",
)

results = [preprocess_event(event) for event in inputs]
http, dns = results

assert http["transport_protocol"] == "TCP"
assert http["application_protocol"] == "HTTP"
assert http["src_ip"] == "10.0.0.1"
assert http["src_port"] == 12345
assert http["timestamp"] == 123.5
assert http["application"]["headers"]["host"] == "Example.COM"
assert http["application"]["normalized_host"] == "example.com"
assert http["application"]["path"] == "/Admin/Login"
assert http["transport"]["protocol"] == "TCP"

assert dns["application"]["query"] == "example.com"
assert dns["application"]["raw_query"] == " Example.COM. "

for event in results:
    assert event["preprocess_status"] == "valid"
    assert event["processing_action"] == "continue"
    assert event["reason"] == []

(folder / "result.jsonl").write_text(
    "".join(json.dumps(event, ensure_ascii=False) + "\n"
            for event in results),
    encoding="utf-8",
)

print("PASS T06: protocol, IP, port, timestamp, header và domain")
