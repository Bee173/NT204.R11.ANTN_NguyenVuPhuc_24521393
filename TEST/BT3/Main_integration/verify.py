import json
import subprocess
import sys
import tempfile
from pathlib import Path


folder = Path(__file__).resolve().parent
root = folder.parents[2]
pcap = root / "TEST/BT2/T01_HTTP_URL_decode/http_url_decode.pcap"
sys.path.insert(0, str(root))

from main import evaluate_event  # noqa: E402


class RejectCalls:
    def process_event(self, event):
        raise AssertionError("skipped event reached Core Engine")


assert evaluate_event(None, {"processing_action": "continue"}) == ()
assert evaluate_event(RejectCalls(), {"processing_action": "skip"}) == ()

with tempfile.TemporaryDirectory() as temporary_directory:
    output = Path(temporary_directory)
    events_path = output / "events.jsonl"
    flows_path = output / "flows.jsonl"
    detections_path = output / "detections.jsonl"

    completed = subprocess.run(
        [
            sys.executable,
            str(root / "main.py"),
            "--pcap", str(pcap),
            "--output", str(events_path),
            "--flow-output", str(flows_path),
            "--rules", str(folder / "input.rules"),
            "--detection-output", str(detections_path),
        ],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr

    with events_path.open(encoding="utf-8") as file:
        events = [json.loads(line) for line in file if line.strip()]
    with detections_path.open(encoding="utf-8") as file:
        detections = [json.loads(line) for line in file if line.strip()]

assert len(events) == 1
assert events[0]["flow_context"]["direction"] == "to_server"
assert events[0]["flow_context"]["state"] == "NEW"
assert [detection["sid"] for detection in detections] == [101501, 101502]
assert detections[0]["msg"] == "SQL injection query"
assert detections[0]["flow_id"] == events[0]["flow_id"]
assert detections[0]["matched_information"] == {
    "flow": "to_server,not_established",
    "content": [{
        "content": "' OR 1=1",
        "start": 10,
        "end": 18,
    }],
    "matched_field": "decoded_path",
}
assert "[ALERT] sid=101501" in completed.stdout
assert "[ALERT] sid=101502" in completed.stdout

print("PASS: main.py integrates Flow Tracker with Core Engine alerts")
