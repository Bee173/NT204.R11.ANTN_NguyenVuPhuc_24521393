import base64
import binascii
from dataclasses import replace

from src.core_engine.detection_event import generate_detection_event
from src.core_engine.evaluation_engine import RuleEvaluationEngine
from src.core_engine.rule_loader import load_rule_files
from src.core_engine.rule_model import RuleStatus
from src.core_engine.rule_repository import RuleRepository
from src.core_engine.rule_validator import parse_and_validate_rule


APPLICATION_FIELDS = (
    "decoded_path", "decoded_body", "body", "path", "query",
)


def _application_data(event):
    if not isinstance(event, dict):
        return None
    application = event.get("application")
    if not isinstance(application, dict):
        return None

    parts = []
    raw_payload = application.get("raw_payload_b64")
    if isinstance(raw_payload, str):
        try:
            parts.append(base64.b64decode(raw_payload, validate=True))
        except (ValueError, binascii.Error):
            pass

    parts.extend(
        value.encode("utf-8")
        for field in APPLICATION_FIELDS
        if isinstance((value := application.get(field)), str)
    )
    return b"\n".join(parts) if parts else None


class CoreEngine:
    def __init__(self, rules, load_issues=()):
        self.rules = tuple(rules)
        self.load_issues = tuple(load_issues)
        self.rejected_rules = tuple(
            rule for rule in self.rules
            if rule.status != RuleStatus.VALID or not rule.enabled
        )
        self._evaluator = RuleEvaluationEngine(RuleRepository(self.rules))

    @classmethod
    def from_rule_files(
        cls,
        file_paths,
        disabled_files=None,
        disabled_sids=None,
    ):
        loaded = load_rule_files(file_paths, disabled_files)
        disabled = {str(sid).strip() for sid in (disabled_sids or ())}
        parsed_rules = tuple(
            parse_and_validate_rule(candidate)
            for candidate in loaded.candidates
        )
        rules = tuple(
            replace(rule, enabled=False)
            if rule.first_option_value("sid") in disabled else rule
            for rule in parsed_rules
        )
        return cls(rules, loaded.issues)

    @property
    def rule_count(self):
        return self._evaluator.repository.rule_count

    @property
    def statistics(self):
        return self._evaluator.statistics

    def process_event(self, event, flow_context=None, application_data=None):
        data = (
            _application_data(event)
            if application_data is None else application_data
        )
        matches = self._evaluator.evaluate(event, flow_context, data)
        return tuple(
            generate_detection_event(event, match)
            for match in matches
        )
