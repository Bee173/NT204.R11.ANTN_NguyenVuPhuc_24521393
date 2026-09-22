import json
from pathlib import Path


def prepare_output(file_path):
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")


def log_event(event, file_path):
    path = Path(file_path)

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, ensure_ascii=False))
        file.write("\n")