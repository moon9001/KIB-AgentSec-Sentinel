from __future__ import annotations

from agentsec.config import DEFAULT_RULES
from agentsec.models import Event
from agentsec.rules import RuleEngine
from agentsec.scoring import score_hits


SCORING = {
    "score_threshold": 60,
    "strong_chain_threshold": 55,
    "weak_signal_score_cap": 34,
    "require_chain_for_label1": True,
    "min_strong_categories_for_label1": 2,
    "max_score": 100,
    "risk_levels": {"low": 10, "medium": 35, "high": 60, "critical": 80},
}


def test_benign_llm_post_does_not_create_exfil_chain() -> None:
    engine = RuleEngine(DEFAULT_RULES)
    events = [
        Event(
            md5="synthetic",
            source="audit",
            event_type="execve",
            text='type=EXECVE a0="cat" a1="/etc/passwd"',
            fields={"a0": "cat", "a1": "/etc/passwd"},
        )
    ]
    pcap = {
        "http_post_count": 4,
        "http_hosts": [["llm-proxy.local:18443", 4]],
        "http_paths": [["/v1/chat/completions", 4]],
        "user_agents": [["OpenAI JS 6.26.0", 4]],
        "dst_ports": [18443],
    }
    hits, signals = engine.evaluate(events, pcap)
    score, label, _risk = score_hits(hits, SCORING, signals)
    assert signals["sensitive_access"] is True
    assert signals["network_post"] is False
    assert signals["strong_chain"] is False
    assert label == 0
    assert score < SCORING["score_threshold"]


def test_upload_post_can_create_sensitive_network_chain() -> None:
    engine = RuleEngine(DEFAULT_RULES)
    events = [
        Event(
            md5="synthetic",
            source="audit",
            event_type="execve",
            text='type=EXECVE a0="cat" a1="/etc/passwd"',
            fields={"a0": "cat", "a1": "/etc/passwd"},
        )
    ]
    pcap = {
        "http_post_count": 1,
        "http_hosts": [["example.invalid", 1]],
        "http_paths": [["/upload", 1]],
        "user_agents": [["python-requests/2.31", 1]],
        "dst_ports": [8080],
    }
    hits, signals = engine.evaluate(events, pcap)
    score, label, _risk = score_hits(hits, SCORING, signals)
    assert signals["network_post"] is True
    assert "R107" in {hit.rule_id for hit in hits}
    assert label == 1
    assert score >= SCORING["score_threshold"]

