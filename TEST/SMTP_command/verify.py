import json
from pathlib import Path

result = Path(__file__).parent / "result.jsonl"

with result.open(encoding="utf-8") as file:
    events = [json.loads(line) for line in file if line.strip()]

expected = [
    ("EHLO", "client.example.com"),
    ("MAIL FROM", "<sender@example.com>"),
    ("RCPT TO", "<receiver@example.com>"),
]

passed = len(events) == 3

if passed:
    for event, (command, argument) in zip(events, expected):
        application = event.get("application", {})

        if (
            event.get("application_protocol") != "SMTP"
            or application.get("type") != "COMMAND"
            or application.get("command") != command
            or application.get("argument") != argument
            or event.get("parse_errors")
        ):
            passed = False
            break

if passed:
    print("PASS: SMTP commands were parsed correctly")
    print("Commands: EHLO, MAIL FROM, RCPT TO")
else:
    print("FAIL: SMTP command result is incorrect")
    raise SystemExit(1)