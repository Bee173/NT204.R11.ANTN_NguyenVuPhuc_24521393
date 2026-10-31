from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RuleCandidate:
    raw: str
    source: str
    line_number: int


@dataclass(frozen=True)
class RuleLoadIssue:
    source: str
    reason: str


@dataclass(frozen=True)
class RuleLoadResult:
    candidates: tuple[RuleCandidate, ...]
    issues: tuple[RuleLoadIssue, ...]


def load_rule_files(file_paths, disabled_files=None):
    disabled = {
        str(Path(file_path).resolve())
        for file_path in (disabled_files or [])
    }
    candidates = []
    issues = []

    for file_path in file_paths:
        path = Path(file_path)
        source = str(path)

        if str(path.resolve()) in disabled:
            continue

        try:
            with path.open(encoding="utf-8") as rule_file:
                for line_number, line in enumerate(rule_file, start=1):
                    raw = line.strip()
                    if not raw or raw.startswith("#"):
                        continue
                    candidates.append(
                        RuleCandidate(
                            raw=raw,
                            source=source,
                            line_number=line_number,
                        )
                    )
        except (OSError, UnicodeError) as error:
            issues.append(
                RuleLoadIssue(
                    source=source,
                    reason=f"{type(error).__name__}: {error}",
                )
            )

    return RuleLoadResult(
        candidates=tuple(candidates),
        issues=tuple(issues),
    )
