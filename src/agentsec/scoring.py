from __future__ import annotations

from typing import Any

from .models import RuleHit


def score_hits(hits: list[RuleHit], scoring_config: dict[str, Any]) -> tuple[float, int, str]:
    max_score = float(scoring_config.get("max_score", 100))
    score = min(max_score, sum(max(0.0, float(hit.weight)) for hit in hits))
    levels = scoring_config.get("risk_levels", {})
    critical_floor = float(levels.get("critical", 75))
    if any(hit.severity == "critical" for hit in hits):
        score = max(score, min(max_score, critical_floor))

    label_threshold = float(scoring_config.get("label_threshold", 45))
    label = 1 if score >= label_threshold else 0
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

