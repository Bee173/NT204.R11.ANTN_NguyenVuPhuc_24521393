from src.core_engine.rule_model import RuleStatus, SnortRule


MODIFIERS = {"nocase", "offset", "depth", "distance", "within"}


def _content_groups(rule):
    groups = []
    for option in rule.options:
        if option.keyword == "content":
            groups.append({"content": option.value})
        elif option.keyword in MODIFIERS and groups:
            groups[-1][option.keyword] = option.value
    return groups


def _find_matches(payload, groups, index=0, previous_end=None):
    if index == len(groups):
        return ()

    group = groups[index]
    relative = previous_end is not None and (
        "distance" in group or "within" in group
    )
    if relative:
        start = previous_end + int(group.get("distance") or 0)
        stop = (
            previous_end + int(group["within"])
            if "within" in group else len(payload)
        )
    else:
        start = int(group.get("offset") or 0)
        stop = start + int(group["depth"]) if "depth" in group else len(payload)

    needle = group["content"].encode("utf-8")
    haystack = payload
    if "nocase" in group:
        needle = needle.lower()
        haystack = haystack.lower()

    stop = min(stop, len(payload))
    position = haystack.find(needle, start, stop)
    while position >= 0:
        end = position + len(needle)
        remaining = _find_matches(payload, groups, index + 1, end)
        if remaining is not None:
            match = {
                "content": group["content"],
                "start": position,
                "end": end,
            }
            return (match, *remaining)
        position = haystack.find(needle, position + 1, stop)
    return None


def match_rule_content(rule: SnortRule, data):
    if rule.status != RuleStatus.VALID:
        return None

    groups = _content_groups(rule)
    if not groups:
        return ()
    if isinstance(data, str):
        payload = data.encode("utf-8")
    elif isinstance(data, bytes):
        payload = data
    else:
        return None

    return _find_matches(payload, groups)
