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
    min_strong_categories = int(scoring_config.get("min_strong_categories_for_label1", 2))

    has_terminal = bool(signals.get("terminal_rule")) or any(hit.severity == "terminal" for hit in hits)
    has_strong_chain = bool(signals.get("strong_chain")) or any(hit.severity == "chain" for hit in hits)
    strong_category_count = int(signals.get("strong_category_count") or 0)

    if has_terminal:
        score = max(score, strong_chain_threshold)
    elif require_chain and not has_strong_chain:
        score = min(score, weak_cap)
    elif has_strong_chain and strong_category_count >= min_strong_categories:
        score = max(score, strong_chain_threshold)

    score = min(max_score, score)
    label = 0
    if has_terminal:
        label = 1
    elif has_strong_chain and strong_category_count >= min_strong_categories and score >= score_threshold:
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
