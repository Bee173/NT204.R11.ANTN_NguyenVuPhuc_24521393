import base64
import json
from pathlib import Path

folder = Path(__file__).resolve().parent

with (folder / "result.jsonl").open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

assert len(events) == 2, "Phải có 2 events"

for event, encoding in zip(events, ["base64", "quoted-printable"]):
    application = event["application"]

    assert event["application_protocol"] == "SMTP"
    assert application["mime_encoding"] == encoding
    assert application["mime_charset"] == "utf-8"
    assert application["decoded_body"] == "Xin chào Phúc"
    assert event["decode_status"] == "success"
    assert event["decode_errors"] == []

    raw = base64.b64decode(
        application["raw_payload_b64"], validate=True
    )
    assert (
        f"Content-Transfer-Encoding: {encoding}".encode("ascii")
        in raw
    ), "Payload gốc không được giữ đúng"

print("PASS T04: SMTP Base64 và Quoted-Printable")
