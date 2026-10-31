from dataclasses import asdict, dataclass
from enum import Enum


class RuleStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class RuleHeader:
    action: str
    protocol: str
    src_ip: str
    src_port: str
    direction: str
    dst_ip: str
    dst_port: str

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class RuleOption:
    keyword: str
    value: str | None = None

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class SnortRule:
    raw: str
    source: str
    line_number: int
    status: RuleStatus
    header: RuleHeader | None = None
    options: tuple[RuleOption, ...] = ()
    reasons: tuple[str, ...] = ()
    enabled: bool = True

    def option_values(self, keyword):
        return tuple(
            option.value
            for option in self.options
            if option.keyword == keyword
        )

    def first_option_value(self, keyword):
        values = self.option_values(keyword)
        return values[0] if values else None

    def to_dict(self):
        return {
            "raw": self.raw,
            "source": self.source,
            "line_number": self.line_number,
            "status": self.status.value,
            "header": self.header.to_dict() if self.header else None,
            "options": [option.to_dict() for option in self.options],
            "reasons": list(self.reasons),
            "enabled": self.enabled,
        }
