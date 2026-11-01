import json
import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))

from src.core_engine.rule_loader import load_rule_files
from src.core_engine.rule_repository import RuleRepository
from src.core_engine.rule_validator import parse_and_validate_rule


load_result = load_rule_files([folder / "input.rules"])
repository = RuleRepository(
    parse_and_validate_rule(candidate)
    for candidate in load_result.candidates
)

with (folder / "events.jsonl").open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

with (folder / "result.jsonl").open("w", encoding="utf-8") as file:
    for event in events:
        candidate_sids = [
            int(rule.first_option_value("sid"))
            for rule in repository.candidate_rules(event)
        ]
        result = {
            "event_id": event["event_id"],
            "candidate_sids": candidate_sids,
        }
        file.write(json.dumps(result) + "\n")

print(f"Created: {folder / 'result.jsonl'}")
