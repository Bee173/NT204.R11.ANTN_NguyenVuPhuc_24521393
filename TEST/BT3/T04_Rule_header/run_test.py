import json
import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))

from src.core_engine.rule_loader import load_rule_files
from src.core_engine.rule_validator import parse_and_validate_rule


load_result = load_rule_files([folder / "input.rules"])
if load_result.issues:
    raise SystemExit(load_result.issues[0].reason)

with (folder / "result.jsonl").open("w", encoding="utf-8") as file:
    for candidate in load_result.candidates:
        record = parse_and_validate_rule(candidate).to_dict()
        record["source"] = Path(record["source"]).name
        file.write(json.dumps(record, ensure_ascii=False) + "\n")

print(f"Created: {folder / 'result.jsonl'}")
