import json
from pathlib import Path

folder = Path(__file__).resolve().parent

with (folder / "result.jsonl").open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

assert len(events) == 1, "Phải có đúng 1 event"

event = events[0]
application = event["application"]

assert event["application_protocol"] == "HTTP"
assert application["body"] == (
    "&lt;script&gt;hello&lt;/script&gt; &amp; &#39;test&#39;"
), "Body gốc bị thay đổi"

assert application["decoded_body"] == (
    "<script>hello</script> & 'test'"
), "HTML entity giải mã không đúng"

assert event["decode_status"] == "success"
assert event["decode_errors"] == []

print("PASS T03: HTML entity giải mã đúng, body gốc giữ nguyên")
