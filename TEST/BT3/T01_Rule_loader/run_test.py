import json
import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))

from src.core_engine.rule_loader import load_rule_files


result = load_rule_files([folder / "input.rules"])

if result.issues:
    for issue in result.issues:
        print(f"FAIL T01: {issue.source}: {issue.reason}")
    raise SystemExit(1)

output_file = folder / "result.jsonl"
with output_file.open("w", encoding="utf-8") as file:
    for candidate in result.candidates:
        record = {
            "raw": candidate.raw,
            "source": Path(candidate.source).name,
            "line_number": candidate.line_number,
        }
        file.write(json.dumps(record, ensure_ascii=False))
        file.write("\n")

print(f"Created: {output_file}")
