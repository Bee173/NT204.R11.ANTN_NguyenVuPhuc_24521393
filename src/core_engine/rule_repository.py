from src.core_engine.header_matcher import match_rule_header
from src.core_engine.rule_model import RuleStatus, SnortRule


class RuleRepository:
    def __init__(self, rules=()):
        self._rules_by_protocol = {"tcp": [], "udp": []}
        self._rule_count = 0
        for rule in rules:
            self.add(rule)

    @property
    def rule_count(self):
        return self._rule_count

    def add(self, rule):
        if (
            not isinstance(rule, SnortRule)
            or rule.status != RuleStatus.VALID
            or not rule.enabled
            or rule.header is None
        ):
            return False

        bucket = self._rules_by_protocol.get(rule.header.protocol)
        if bucket is None:
            return False

        bucket.append(rule)
        self._rule_count += 1
        return True

    def candidate_rules(self, event):
        if not isinstance(event, dict):
            return ()
        protocol = event.get("transport_protocol")
        if not isinstance(protocol, str):
            return ()

        bucket = self._rules_by_protocol.get(protocol.strip().lower(), ())
        return tuple(
            rule for rule in bucket
            if match_rule_header(rule, event)
        )
