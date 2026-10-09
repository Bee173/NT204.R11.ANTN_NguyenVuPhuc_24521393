import base64
import json
from pathlib import Path

folder = Path(__file__).resolve().parent

with (folder / "result.jsonl").open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

assert len(events) == 2, "Chương trình phải ghi cả hai packet"

bad, good = events

assert bad["application"]["character_decode_status"] == "partial"
assert bad["decode_status"] in {"partial", "error"}
assert bad["decode_errors"], "Phải ghi nhận lỗi decode"

raw = base64.b64decode(
    bad["application"]["raw_payload_b64"], validate=True
)
assert raw.endswith(b"hello\xff\xfe"), "Phải giữ nguyên bytes gốc"

assert good["packet_id"] == 2
assert good["application"]["character_decode_status"] == "success"
assert good["application"]["decoded_body"] == "hello"
assert good["decode_status"] == "success"
assert good["decode_errors"] == []

print("PASS T05: ghi nhận UTF-8 lỗi, giữ raw bytes, xử lý tiếp packet tốt")
