import json
import sys
from pathlib import Path


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))

from src.core_engine.core_engine import CoreEngine


engine = CoreEngine.from_rule_files([folder / "input.rules"])

with (folder / "events.jsonl").open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

with (folder / "result.jsonl").open("w", encoding="utf-8") as file:
    for event in events:
        detections = engine.process_event(event)
        result = {
            "event_id": event["event_id"],
            "detection_sids": [item["sid"] for item in detections],
        }
        file.write(json.dumps(result) + "\n")

print(f"Created: {folder / 'result.jsonl'}")
