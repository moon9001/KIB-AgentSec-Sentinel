from __future__ import annotations

from typing import Any

from .models import RuleHit


def score_hits(hits: list[RuleHit], scoring_config: dict[str, Any], signals: dict[str, Any] | None = None) -> tuple[float, int, str]:
    signals = signals or {}
    max_score = float(scoring_config.get("max_score", 100))
    score = min(max_score, sum(max(0.0, float(hit.weight)) for hit in hits))

    levels = scoring_config.get("risk_levels", {})
    score_threshold = float(scoring_config.get("score_threshold", scoring_config.get("label_threshold", 60)))
    strong_chain_threshold = float(scoring_config.get("strong_chain_threshold", levels.get("high", 55)))
    weak_cap = float(scoring_config.get("weak_signal_score_cap", max(0, score_threshold - 1)))
    require_chain = bool(scoring_config.get("require_chain_for_label1", True))
    terminal_rule_ids = set(scoring_config.get("terminal_rule_ids", ["R005"]))

    terminal_hits = [hit for hit in hits if hit.severity == "terminal" and hit.rule_id in terminal_rule_ids]
    guarded_chain_rules = set(str(rule_id) for rule_id in signals.get("strong_chain_rules") or [])
    guarded_chain_hits = [hit for hit in hits if hit.rule_id in guarded_chain_rules and hit.severity in {"chain", "terminal"}]
    max_chain_weight = max((float(hit.weight) for hit in guarded_chain_hits), default=0.0)

    has_terminal = bool(terminal_hits)
    has_explicit_malicious_action = bool(signals.get("explicit_malicious_action"))
    has_guarded_chain = bool(guarded_chain_hits)
    qualifying_chain = has_guarded_chain and max_chain_weight >= strong_chain_threshold

    if has_terminal:
        score = max(score, score_threshold)
    elif has_explicit_malicious_action:
        score = max(score, score_threshold)
    elif qualifying_chain:
        score = max(score, score_threshold)
    elif require_chain:
        score = min(score, weak_cap)

    score = min(max_score, score)
    label = 0
    if has_terminal or has_explicit_malicious_action or qualifying_chain:
        label = 1
    return round(score, 2), label, risk_level(score, scoring_config)


def risk_level(score: float, scoring_config: dict[str, Any]) -> str:
    levels = scoring_config.get("risk_levels", {})
    if score >= float(levels.get("critical", 75)):
        return "critical"
    if score >= float(levels.get("high", 55)):
        return "high"
    if score >= float(levels.get("medium", 35)):
        return "medium"
    if score >= float(levels.get("low", 15)):
        return "low"
    return "none"
