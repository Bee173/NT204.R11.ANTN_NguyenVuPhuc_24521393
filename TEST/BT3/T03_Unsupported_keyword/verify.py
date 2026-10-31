import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_file = folder / "result.jsonl"

if not result_file.exists():
    print("FAIL T03: result.jsonl chưa được tạo")
    raise SystemExit(1)

with result_file.open(encoding="utf-8") as file:
    rules = [json.loads(line) for line in file if line.strip()]

assert len(rules) == 2, "Phải xử lý cả rule unsupported và rule kế tiếp"

unsupported_rule, valid_rule = rules
assert unsupported_rule["status"] == "unsupported"
assert any("pcre" in reason for reason in unsupported_rule["reasons"])
assert valid_rule["status"] == "valid", (
    "Validator phải tiếp tục sau keyword unsupported"
)

print("PASS T03: keyword ngoài phạm vi được đánh unsupported")
