from src.core_engine.matching_engine import match_rule


class RuleEvaluationEngine:
    def __init__(self, repository):
        self.repository = repository
        self._statistics = {
            "events_evaluated": 0,
            "candidate_rules": 0,
            "matches": 0,
        }

    @property
    def statistics(self):
        return dict(self._statistics)

    def evaluate(self, event, flow_context=None, application_data=None):
        self._statistics["events_evaluated"] += 1
        candidates = self.repository.candidate_rules(event)
        self._statistics["candidate_rules"] += len(candidates)

        results = tuple(
            result
            for rule in candidates
            if (
                result := match_rule(
                    rule,
                    event,
                    flow_context,
                    application_data,
                )
            ).matched
        )
        self._statistics["matches"] += len(results)
        return results
