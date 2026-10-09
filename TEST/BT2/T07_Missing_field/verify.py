import json
import sys
from copy import deepcopy
from pathlib import Path

folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))

from src.preprocessor import preprocess_event

base = {
    "timestamp": 123.5,
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": 12345,
    "dst_port": 80,
    "transport_protocol": "TCP",
    "application_protocol": "HTTP",
}

# HTTP thiếu application, headers, path, body và errors.
http_missing = deepcopy(base)

# Các object/list được truyền dưới dạng null.
http_null = deepcopy(base)
http_null.update({
    "network": None,
    "transport": None,
    "application": None,
    "parse_errors": None,
    "decode_errors": None,
})

# DNS thiếu query và answers.
dns_missing = deepcopy(base)
dns_missing.update({
    "transport_protocol": "UDP",
    "application_protocol": "DNS",
    "dst_port": 53,
})

inputs = [http_missing, http_null, dns_missing]

(folder / "input.jsonl").write_text(
    "".join(json.dumps(event) + "\n" for event in inputs),
    encoding="utf-8",
)

results = [
    preprocess_event(deepcopy(event))
    for event in inputs
]

for event in results:
    assert event["preprocess_status"] == "valid"
    assert event["processing_action"] == "continue"
    assert event["reason"] == []

    assert isinstance(event["network"], dict)
    assert isinstance(event["transport"], dict)
    assert isinstance(event["application"], dict)
    assert event["parse_errors"] == []
    assert event["decode_errors"] == []

for event in results[:2]:
    application = event["application"]
    assert application["headers"] == {}
    assert application["path"] is None
    assert application["body"] is None
    assert application["normalized_host"] is None

dns = results[2]["application"]
assert dns["query"] is None
assert dns["answers"] == []

(folder / "result.jsonl").write_text(
    "".join(
        json.dumps(event, ensure_ascii=False) + "\n"
        for event in results
    ),
    encoding="utf-8",
)

print("PASS T07: thiếu field không bắt buộc vẫn xử lý an toàn")
print("- HTTP: headers={}, path/body/normalized_host=null")
print("- DNS: query=null, answers=[]")
print("- parse_errors/decode_errors=[]")
