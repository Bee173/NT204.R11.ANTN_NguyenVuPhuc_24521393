import json
from pathlib import Path

folder = Path(__file__).resolve().parent

with (folder / "result.jsonl").open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

assert len(events) == 1, "Phải có đúng 1 event"

event = events[0]
application = event["application"]

assert event["application_protocol"] == "HTTP"
assert application["method"] == "POST"

assert application["body"] == (
    "name=Nguyen+Vu+Phuc"
    "&message=%27+OR+1%3D1"
    "&tag=a&tag=b&empty="
), "Body gốc bị thay đổi"

# JSON chuyển các tuple thành list.
assert application["decoded_form"] == [
    ["name", "Nguyen Vu Phuc"],
    ["message", "' OR 1=1"],
    ["tag", "a"],
    ["tag", "b"],
    ["empty", ""],
], "Form giải mã không đúng"

assert event["decode_status"] == "success"
assert event["decode_errors"] == []

print("PASS: HTTP form decoding")
print("- Dấu + chuyển thành khoảng trắng")
print("- Percent-encoding giải mã đúng")
print("- Giữ field trùng tên và giá trị rỗng")
print("- Body gốc giữ nguyên")