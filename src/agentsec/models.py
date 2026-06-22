from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Event:
    md5: str
    source: str
    event_type: str
    text: str
    timestamp: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Evidence:
    source: str
    rule_id: str
    message: str
    excerpt: str
    fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuleHit:
    rule_id: str
    name: str
    category: str
    severity: str
    weight: float
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SampleFeatures:
    md5: str
    event_counts: dict[str, int] = field(default_factory=dict)
    audit_stats: dict[str, int] = field(default_factory=dict)
    pcap: dict[str, Any] = field(default_factory=dict)
    signals: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionResult:
    md5: str
    label: int
    score: float
    risk_level: str
    matched_rules: list[RuleHit] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    behavior_chains: list[dict[str, Any]] = field(default_factory=list)
    feature_summary: dict[str, Any] = field(default_factory=dict)
    llm_analysis: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

