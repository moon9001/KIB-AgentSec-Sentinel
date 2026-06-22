from __future__ import annotations

from typing import Any

from .models import RuleHit, SampleFeatures


def build_behavior_chains(md5: str, hits: list[RuleHit], features: SampleFeatures) -> list[dict[str, Any]]:
    signals = features.signals or {}
    hit_by_category: dict[str, list[str]] = {}
    for hit in hits:
        hit_by_category.setdefault(hit.category, []).append(hit.rule_id)

    chains: list[dict[str, Any]] = []
    if signals.get("sensitive_access") and signals.get("compression") and (
        signals.get("network_transfer") or signals.get("network_post")
    ):
        chains.append(
            {
                "chain_id": f"{md5}:sensitive-archive-network",
                "title": "Sensitive access -> archive -> network transfer",
                "risk": "critical",
                "steps": ["sensitive_access", "archive_or_compression", "network_transfer"],
                "supporting_rules": sorted(set(hit_by_category.get("file", []) + hit_by_category.get("archive", []) + hit_by_category.get("network", []) + hit_by_category.get("combo", []))),
            }
        )

    if signals.get("credential_access") and (
        signals.get("network_transfer") or signals.get("compression") or signals.get("network_post") or signals.get("copy_or_download")
    ):
        chains.append(
            {
                "chain_id": f"{md5}:credential-exposure",
                "title": "Credential access with transfer or packaging evidence",
                "risk": "critical",
                "steps": ["credential_access", "package_or_transfer"],
                "supporting_rules": sorted(set(hit_by_category.get("credential", []) + hit_by_category.get("combo", []))),
            }
        )

    if signals.get("trace_cleanup") and (signals.get("sensitive_access") or signals.get("credential_access")):
        chains.append(
            {
                "chain_id": f"{md5}:trace-cleanup",
                "title": "Trace cleanup or session deletion behavior",
                "risk": "high",
                "steps": ["trace_cleanup", "contextual_sensitive_or_network_activity"],
                "supporting_rules": sorted(set(hit_by_category.get("cleanup", []) + hit_by_category.get("combo", []))),
            }
        )

    if signals.get("privilege") and signals.get("sensitive_access"):
        chains.append(
            {
                "chain_id": f"{md5}:privilege-followup",
                "title": "Privilege or permission change with follow-up activity",
                "risk": "high",
                "steps": ["privilege_or_permission_change", "file_or_network_activity"],
                "supporting_rules": sorted(set(hit_by_category.get("privilege", []) + hit_by_category.get("combo", []))),
            }
        )

    if signals.get("destructive"):
        chains.append(
            {
                "chain_id": f"{md5}:destructive-command",
                "title": "Destructive command behavior",
                "risk": "critical",
                "steps": ["destructive_command"],
                "supporting_rules": sorted(set(hit_by_category.get("destructive", []))),
            }
        )

    if signals.get("shell_or_cmd") and signals.get("sensitive_access") and (
        signals.get("network_transfer") or signals.get("network_post")
    ):
        chains.append(
            {
                "chain_id": f"{md5}:shell-sensitive-network",
                "title": "Shell command with sensitive path and network transfer",
                "risk": "high",
                "steps": ["shell_or_cmd", "sensitive_access", "network_transfer"],
                "supporting_rules": sorted(set(hit_by_category.get("agent", []) + hit_by_category.get("file", []) + hit_by_category.get("network", []) + hit_by_category.get("combo", []))),
            }
        )

    if not chains and hits:
        chains.append(
            {
                "chain_id": f"{md5}:single-signal",
                "title": "Single or weak suspicious signal",
                "risk": "low",
                "steps": sorted(key for key, value in signals.items() if value is True),
                "supporting_rules": [hit.rule_id for hit in hits],
            }
        )
    return chains
