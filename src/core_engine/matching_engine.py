from dataclasses import dataclass, field

from src.core_engine.content_matcher import match_rule_content
from src.core_engine.flow_matcher import match_rule_flow
from src.core_engine.header_matcher import match_rule_header
from src.core_engine.packet_matcher import match_rule_packet
from src.core_engine.rule_model import RuleStatus, SnortRule


@dataclass(frozen=True)
class RuleMatchResult:
    matched: bool
    reason: str
    sid: int | None = None
    rev: int | None = None
    msg: str | None = None
    priority: int | None = None
    classtype: str | None = None
    matched_information: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "matched": self.matched,
            "reason": self.reason,
            "sid": self.sid,
            "rev": self.rev,
            "msg": self.msg,
            "priority": self.priority,
            "classtype": self.classtype,
            "matched_information": self.matched_information,
        }


def _no_match(reason):
    return RuleMatchResult(matched=False, reason=reason)


def match_rule(rule: SnortRule, event, flow_context=None, application_data=None):
    if rule.status != RuleStatus.VALID:
        return _no_match("rule")
    if not match_rule_header(rule, event):
        return _no_match("header")
    if not match_rule_flow(rule, flow_context):
        return _no_match("flow")
    if not match_rule_packet(rule, event):
        return _no_match("packet")

    content = match_rule_content(rule, application_data)
    if content is None:
        return _no_match("content")

    information = {}
    for keyword in ("flow", "flags"):
        value = rule.first_option_value(keyword)
        if value is not None:
            information[keyword] = value
    dsize = rule.first_option_value("dsize")
    if dsize is not None:
        information["dsize"] = int(dsize)
    if content:
        information["content"] = list(content)

    priority = rule.first_option_value("priority")
    return RuleMatchResult(
        matched=True,
        reason="matched",
        sid=int(rule.first_option_value("sid")),
        rev=int(rule.first_option_value("rev")),
        msg=rule.first_option_value("msg"),
        priority=int(priority) if priority is not None else None,
        classtype=rule.first_option_value("classtype"),
        matched_information=information,
    )
