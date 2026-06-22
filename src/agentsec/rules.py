from __future__ import annotations

import re
from typing import Any, Callable

from .models import Event, Evidence, RuleHit
from .utils import contains_any, redact_text


class RuleEngine:
    def __init__(self, rules_config: dict[str, Any], output_config: dict[str, Any] | None = None) -> None:
        self.rules_config = rules_config
        self.keywords = rules_config.get("keywords", {})
        self.weights = rules_config.get("weights", {})
        output_config = output_config or {}
        self.excerpt_chars = int(output_config.get("evidence_excerpt_max_chars", output_config.get("evidence_excerpt_chars", 240)))

    def evaluate(self, events: list[Event], pcap_features: dict[str, Any]) -> tuple[list[RuleHit], dict[str, Any]]:
        hits: list[RuleHit] = []

        sensitive_events = self._matching_events(events, self._is_sensitive_access)
        credential_events = self._matching_events(events, self._is_credential_access)
        compression_events = self._matching_events(events, self._is_archive_action)
        network_events = self._matching_events(events, self._is_network_exfil_event)
        destructive_events = self._matching_events(events, self._is_destructive_action)
        privilege_events = self._matching_events(events, self._is_privilege_action)
        cleanup_events = self._matching_events(events, self._has_keywords("trace_cleanup_commands"))
        agent_tool_events = self._matching_events(events, self._is_agent_tool_abuse)
        suspicious_network = self._is_suspicious_network(pcap_features)
        network_post = int(pcap_features.get("http_post_count") or 0) > 0
        shell_events = self._matching_events(events, self._is_shell_or_cmd_event)
        copy_events = self._matching_events(events, self._is_copy_action)

        self._add_if(hits, "R001", "Sensitive file or directory access", "file", "low", "sensitive_file_access", sensitive_events)
        self._add_if(hits, "R002", "Credential material access", "credential", "medium", "credential_access", credential_events)
        self._add_if(hits, "R003", "Archive or compression command", "archive", "low", "compression_archive", compression_events)
        self._add_if(hits, "R004", "Network upload or exfiltration command", "network", "medium", "network_exfil", network_events)
        self._add_if(hits, "R005", "Destructive command marker", "destructive", "terminal", "destructive_command", destructive_events)
        self._add_if(hits, "R006", "Privilege escalation or permission change", "privilege", "medium", "privilege_escalation", privilege_events)
        self._add_if(hits, "R007", "Trace cleanup or session deletion", "cleanup", "medium", "trace_cleanup", cleanup_events)
        self._add_if(hits, "R008", "Agent shell/tool action with risky context", "agent", "medium", "agent_tool_abuse", agent_tool_events)

        if suspicious_network:
            hits.append(
                self._feature_hit(
                    "R009",
                    "Suspicious network behavior in PCAP",
                    "network",
                    "low",
                    "suspicious_network",
                    pcap_features,
                )
            )

        if sensitive_events and compression_events and (network_events or network_post):
            hits.append(
                self._combo_hit(
                    "R101",
                    "Sensitive access followed by archive and network transfer",
                    "combo",
                    "chain",
                    "combo_sensitive_archive_network",
                    [sensitive_events[0], compression_events[0], (network_events or [None])[0]],
                    pcap_features if network_post else None,
                )
            )
        if sensitive_events and network_events:
            hits.append(
                self._combo_hit(
                    "R106",
                    "Sensitive access with explicit upload or transfer command",
                    "combo",
                    "chain",
                    "combo_sensitive_upload",
                    [sensitive_events[0], network_events[0]],
                )
            )
        if sensitive_events and network_post:
            hits.append(
                self._combo_hit(
                    "R107",
                    "Sensitive access with HTTP POST network evidence",
                    "combo",
                    "chain",
                    "combo_sensitive_network_post",
                    [sensitive_events[0]],
                    pcap_features,
                )
            )
        if cleanup_events and (sensitive_events or credential_events):
            hits.append(
                self._combo_hit(
                    "R102",
                    "Trace cleanup combined with sensitive behavior",
                    "combo",
                    "chain",
                    "combo_cleanup_plus_sensitive",
                    [cleanup_events[0], (credential_events or sensitive_events)[0]],
                )
            )
        if privilege_events and sensitive_events:
            hits.append(
                self._combo_hit(
                    "R103",
                    "Privilege change with sensitive access",
                    "combo",
                    "chain",
                    "combo_privilege_followup",
                    [privilege_events[0], sensitive_events[0]],
                )
            )
        if credential_events and (copy_events or compression_events or network_events or network_post):
            hits.append(
                self._combo_hit(
                    "R104",
                    "Credential access with packaging or transfer evidence",
                    "combo",
                    "terminal",
                    "combo_credential_exfil",
                    [credential_events[0], (copy_events or compression_events or network_events or [None])[0]],
                    pcap_features if network_post else None,
                )
            )
        if shell_events and sensitive_events and (network_events or network_post):
            hits.append(
                self._combo_hit(
                    "R108",
                    "Shell command with sensitive path and network transfer",
                    "combo",
                    "chain",
                    "combo_shell_sensitive_network",
                    [shell_events[0], sensitive_events[0], (network_events or [None])[0]],
                    pcap_features if network_post else None,
                )
            )
        if agent_tool_events and (network_events or network_post) and (sensitive_events or credential_events):
            hits.append(
                self._combo_hit(
                    "R105",
                    "Agent tool behavior correlated with audit or network evidence",
                    "combo",
                    "chain",
                    "correlated_agent_audit_network",
                    [agent_tool_events[0], (sensitive_events or credential_events)[0], (network_events or [None])[0]],
                    pcap_features if network_post else None,
                )
            )

        strong_chain_rules = {hit.rule_id for hit in hits if hit.severity in {"chain", "terminal"}}
        strong_categories = sorted(
            {
                category
                for category, active in {
                    "sensitive": bool(sensitive_events),
                    "credential": bool(credential_events),
                    "archive": bool(compression_events),
                    "network": bool(network_events or network_post),
                    "privilege": bool(privilege_events),
                    "cleanup": bool(cleanup_events),
                    "destructive": bool(destructive_events),
                    "agent": bool(agent_tool_events or shell_events),
                }.items()
                if active
            }
        )

        signals = {
            "sensitive_access": bool(sensitive_events),
            "credential_access": bool(credential_events),
            "compression": bool(compression_events),
            "network_transfer": bool(network_events),
            "network_post": bool(network_post),
            "destructive": bool(destructive_events),
            "privilege": bool(privilege_events),
            "trace_cleanup": bool(cleanup_events),
            "agent_tool_abuse": bool(agent_tool_events),
            "shell_or_cmd": bool(shell_events),
            "copy_or_download": bool(copy_events),
            "suspicious_pcap": bool(suspicious_network),
            "strong_chain": bool(strong_chain_rules),
            "terminal_rule": bool(any(hit.severity == "terminal" for hit in hits)),
            "strong_chain_rules": sorted(strong_chain_rules),
            "strong_categories": strong_categories,
            "strong_category_count": len(strong_categories),
            "hit_count": len(hits),
        }
        return hits, signals

    def _matching_events(self, events: list[Event], predicate: Callable[[Event], bool]) -> list[Event]:
        return [event for event in events if predicate(event)]

    def _has_keywords(self, key: str) -> Callable[[Event], bool]:
        needles = self.keywords.get(key, [])
        return lambda event: contains_any(event.text, needles)

    def _command_text(self, event: Event) -> str:
        fields = event.fields or {}
        values = [
            event.event_type,
            fields.get("tool"),
            fields.get("action"),
            fields.get("cmd"),
            fields.get("name"),
            fields.get("function_call"),
            fields.get("params"),
            fields.get("args"),
            fields.get("comm"),
            fields.get("exe"),
            fields.get("proctitle"),
            fields.get("a0"),
            fields.get("a1"),
            fields.get("a2"),
            fields.get("a3"),
        ]
        return " ".join(str(value) for value in values if value not in (None, "")).lower()

    def _is_sensitive_access(self, event: Event) -> bool:
        text = event.text.lower()
        sensitive = contains_any(text, self.keywords.get("sensitive_paths", []))
        credential = contains_any(text, self.keywords.get("credential_keywords", []))
        read_marker = contains_any(text, self.keywords.get("read_markers", []))
        path_marker = "/" in text or "\\" in text or event.source == "audit"
        command_context = self._command_text(event)
        benign_session_type = event.source == "session" and event.event_type in {
            "session",
            "message",
            "model_change",
            "thinking_level_change",
            "custom",
        }
        if benign_session_type and not contains_any(command_context, self.keywords.get("read_markers", [])):
            return False
        return (sensitive and (read_marker or path_marker)) or (credential and read_marker)

    def _is_credential_access(self, event: Event) -> bool:
        text = event.text.lower()
        credential = contains_any(text, self.keywords.get("credential_keywords", []))
        strong_path = any(marker in text for marker in ["id_rsa", "/etc/shadow", "authorized_keys", "private key"])
        read_marker = contains_any(text, self.keywords.get("read_markers", []))
        return strong_path or (credential and read_marker)

    def _is_archive_action(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if event.source == "audit" and event.event_type not in {"execve", "proctitle", "syscall"}:
            return False
        return contains_any(command_text, self.keywords.get("compression_tools", []))

    def _is_network_exfil_event(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if event.source == "audit" and event.event_type not in {"execve", "proctitle", "syscall"}:
            return False
        return contains_any(command_text, self.keywords.get("upload_tools", []))

    def _is_destructive_action(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if event.source == "audit" and event.event_type not in {"execve", "proctitle", "syscall"}:
            return False
        if event.source == "session" and event.event_type in {"message", "session", "model_change", "thinking_level_change", "custom"}:
            return False
        return contains_any(command_text, self.keywords.get("destructive_commands", []))

    def _is_copy_action(self, event: Event) -> bool:
        command_text = self._command_text(event)
        return contains_any(command_text, ["copy", "cp", "download", "write_file"])

    def _is_shell_or_cmd_event(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if event.source == "session":
            return contains_any(command_text, self.keywords.get("shell_tools", []))
        if event.source == "audit" and event.event_type in {"execve", "proctitle", "syscall"}:
            return contains_any(command_text, ["bash", "sh", "zsh", "python", "perl"])
        return False

    def _is_agent_tool_abuse(self, event: Event) -> bool:
        if event.source != "session":
            return False
        fields = event.fields or {}
        tool_text = " ".join(
            str(value)
            for value in [
                event.event_type,
                fields.get("tool"),
                fields.get("action"),
                fields.get("cmd"),
                fields.get("name"),
                fields.get("function_call"),
                fields.get("params"),
                fields.get("args"),
            ]
            if value not in (None, "")
        ).lower()
        text = f"{tool_text} {event.text.lower()}"
        tool_marker = contains_any(tool_text, self.keywords.get("suspicious_agent_tools", []))
        shell_marker = contains_any(tool_text, self.keywords.get("shell_tools", []))
        risky_action = (
            contains_any(text, self.keywords.get("sensitive_paths", []))
            or contains_any(text, self.keywords.get("upload_tools", []))
            or contains_any(text, self.keywords.get("privilege_tools", []))
            or contains_any(text, self.keywords.get("trace_cleanup_commands", []))
            or contains_any(text, self.keywords.get("destructive_commands", []))
        )
        return tool_marker and shell_marker and risky_action

    def _is_privilege_action(self, event: Event) -> bool:
        text = event.text.lower()
        strong_phrases = ["chmod 777", "setuid", "useradd"]
        if any(phrase in text for phrase in strong_phrases):
            return True
        command_text = " ".join(
            str(value)
            for value in [
                event.event_type,
                event.fields.get("comm"),
                event.fields.get("exe"),
                event.fields.get("proctitle"),
                event.fields.get("cmd"),
                event.fields.get("a0"),
                event.fields.get("a1"),
                event.fields.get("a2"),
                event.fields.get("a3"),
                event.fields.get("tool"),
                event.fields.get("action"),
            ]
            if value not in (None, "")
        ).lower()
        return any(
            re.search(rf"(?<![a-z0-9_./-]){re.escape(command)}(?![a-z0-9_./-])", command_text)
            for command in ["sudo", "su", "chown", "passwd"]
        )

    def _is_suspicious_network(self, features: dict[str, Any]) -> bool:
        if not features:
            return False
        http_post = int(features.get("http_post_count") or 0) > 0
        ports = set(int(port) for port in features.get("dst_ports") or [])
        suspicious_ports = set(int(port) for port in self.rules_config.get("pcap", {}).get("suspicious_nonstandard_ports", []))
        if not suspicious_ports:
            suspicious_ports = {4444, 5555, 6667, 8081, 9001, 1337}
        suspicious_domain = False
        hosts = [host for host, _count in features.get("http_hosts") or []]
        for host in hosts:
            if contains_any(str(host), self.keywords.get("suspicious_domains", [])):
                suspicious_domain = True
                break
        return http_post or bool(ports & suspicious_ports) or suspicious_domain

    def _add_if(
        self,
        hits: list[RuleHit],
        rule_id: str,
        name: str,
        category: str,
        severity: str,
        weight_key: str,
        events: list[Event],
    ) -> None:
        if not events:
            return
        evidence = [self._event_evidence(rule_id, event, name) for event in events[:5]]
        hits.append(
            RuleHit(
                rule_id=rule_id,
                name=name,
                category=category,
                severity=severity,
                weight=float(self.weights.get(weight_key, 0)),
                evidence=evidence,
            )
        )

    def _feature_hit(
        self,
        rule_id: str,
        name: str,
        category: str,
        severity: str,
        weight_key: str,
        features: dict[str, Any],
    ) -> RuleHit:
        fields = {
            "external_ip_count": features.get("external_ip_count", 0),
            "http_post_count": features.get("http_post_count", 0),
            "top_dst_ports": features.get("top_dst_ports", []),
            "http_hosts": features.get("http_hosts", []),
        }
        return RuleHit(
            rule_id=rule_id,
            name=name,
            category=category,
            severity=severity,
            weight=float(self.weights.get(weight_key, 0)),
            evidence=[
                Evidence(
                    source="pcap",
                    rule_id=rule_id,
                    message=name,
                    excerpt=redact_text(fields, self.excerpt_chars),
                    fields=fields,
                )
            ],
        )

    def _combo_hit(
        self,
        rule_id: str,
        name: str,
        category: str,
        severity: str,
        weight_key: str,
        events: list[Event | None],
        pcap_features: dict[str, Any] | None = None,
    ) -> RuleHit:
        evidence = [self._event_evidence(rule_id, event, name) for event in events if event is not None]
        if pcap_features:
            evidence.append(
                Evidence(
                    source="pcap",
                    rule_id=rule_id,
                    message="PCAP correlation",
                    excerpt=redact_text(
                        {
                            "external_ip_count": pcap_features.get("external_ip_count", 0),
                            "http_post_count": pcap_features.get("http_post_count", 0),
                            "top_dst_ports": pcap_features.get("top_dst_ports", []),
                        },
                        self.excerpt_chars,
                    ),
                    fields={},
                )
            )
        return RuleHit(
            rule_id=rule_id,
            name=name,
            category=category,
            severity=severity,
            weight=float(self.weights.get(weight_key, 0)),
            evidence=evidence,
        )

    def _event_evidence(self, rule_id: str, event: Event, message: str) -> Evidence:
        return Evidence(
            source=event.source,
            rule_id=rule_id,
            message=message,
            excerpt=redact_text(event.text, self.excerpt_chars),
            fields={
                "event_type": event.event_type,
                "timestamp": event.timestamp,
                "line": event.fields.get("line"),
            },
        )
