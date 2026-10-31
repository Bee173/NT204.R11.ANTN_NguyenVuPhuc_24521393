import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_file = folder / "result.jsonl"

if not result_file.exists():
    print("FAIL T02: result.jsonl chưa được tạo")
    raise SystemExit(1)

with result_file.open(encoding="utf-8") as file:
    rules = [json.loads(line) for line in file if line.strip()]

assert len(rules) == 2, "Phải xử lý cả rule lỗi và rule hợp lệ phía sau"

invalid_rule, valid_rule = rules
assert invalid_rule["status"] == "invalid"
assert invalid_rule["reasons"], "Rule invalid phải có lý do"
assert any("syntax" in reason for reason in invalid_rule["reasons"])

assert valid_rule["status"] == "valid", (
    "Validator phải tiếp tục xử lý rule sau khi gặp syntax lỗi"
)

print("PASS T02: rule sai syntax được đánh invalid và engine tiếp tục")
