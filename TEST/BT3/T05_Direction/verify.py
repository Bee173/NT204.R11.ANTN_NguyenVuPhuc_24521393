import json
from pathlib import Path


folder = Path(__file__).resolve().parent
result_file = folder / "result.jsonl"

if not result_file.exists():
    print("FAIL T05: result.jsonl chưa được tạo")
    raise SystemExit(1)

with result_file.open(encoding="utf-8") as file:
    results = [json.loads(line) for line in file if line.strip()]

assert results == [
    {"event_id": "forward", "matched_sids": [100501, 100502]},
    {"event_id": "reverse", "matched_sids": [100502]},
], "Rule -> chỉ match thuận; rule <> phải match cả hai chiều"

print("PASS T05: direction -> và <> match đúng")
