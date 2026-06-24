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
        self.behavior = rules_config.get("profile_behavior", {})
        output_config = output_config or {}
        self.excerpt_chars = int(output_config.get("evidence_excerpt_max_chars", output_config.get("evidence_excerpt_chars", 240)))

    def evaluate(self, events: list[Event], pcap_features: dict[str, Any]) -> tuple[list[RuleHit], dict[str, Any]]:
        hits: list[RuleHit] = []

        sensitive_events = self._matching_events(events, self._is_sensitive_access)
        strong_sensitive_events = self._matching_events(events, self._is_high_confidence_sensitive_access)
        credential_events = self._matching_events(events, self._is_credential_access)
        strong_credential_events = self._matching_events(events, self._is_high_confidence_credential_access)
        credential_shell_events = self._matching_events(events, self._is_credential_shell_access)
        compression_events = self._matching_events(events, self._is_archive_action)
        network_events = self._matching_events(events, self._is_network_exfil_event)
        destructive_events = self._matching_events(events, self._is_destructive_action)
        privilege_events = self._matching_events(events, self._is_privilege_action)
        cleanup_events = self._matching_events(events, self._has_keywords("trace_cleanup_commands"))
        agent_tool_events = self._matching_events(events, self._is_agent_tool_abuse)
        network_post = self._is_network_post_exfil(pcap_features)
        suspicious_network = self._is_suspicious_network(pcap_features, network_post)
        sysmon_network_events = self._matching_events(events, self._is_sysmon_network_observed)
        network_observed = self._is_network_observed(pcap_features) or bool(sysmon_network_events)
        shell_events = self._matching_events(events, self._is_shell_or_cmd_event)
        copy_events = self._matching_events(events, self._is_copy_action)
        suspicious_command_events = self._matching_events(events, self._is_suspicious_command)
        suspicious_powershell_events = self._matching_events(events, self._is_suspicious_powershell)
        persistence_events = self._matching_events(events, self._is_persistence_action)
        lateral_events = self._matching_events(events, self._is_lateral_movement)
        command_context_events = self._matching_events(events, self._is_command_access_context)

        self._add_if(hits, "R001", "Sensitive file or directory access", "file", "low", "sensitive_file_access", sensitive_events)
        self._add_if(hits, "R002", "Credential material access", "credential", "medium", "credential_access", credential_events)
        self._add_if(hits, "R003", "Archive or compression command", "archive", "low", "compression_archive", compression_events)
        self._add_if(hits, "R004", "Network upload or exfiltration command", "network", "medium", "network_exfil", network_events)
        self._add_if(hits, "R005", "Destructive command marker", "destructive", "terminal", "destructive_command", destructive_events)
        self._add_if(hits, "R006", "Privilege escalation or permission change", "privilege", "medium", "privilege_escalation", privilege_events)
        self._add_if(hits, "R007", "Trace cleanup or session deletion", "cleanup", "medium", "trace_cleanup", cleanup_events)
        self._add_if(hits, "R008", "Agent shell/tool action with risky context", "agent", "medium", "agent_tool_abuse", agent_tool_events)
        self._add_if(hits, "R011", "Suspicious command interpreter or living-off-the-land tool", "command", "low", "suspicious_command", suspicious_command_events)
        self._add_if(hits, "R012", "Suspicious PowerShell command", "powershell", "medium", "suspicious_powershell", suspicious_powershell_events)
        self._add_if(hits, "R013", "Persistence mechanism marker", "persistence", "medium", "persistence", persistence_events)
        self._add_if(hits, "R014", "Lateral movement marker", "lateral", "medium", "lateral_movement", lateral_events)

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

        strict_credential = bool(self.behavior.get("credential_exfil_requires_command", True))
        strict_sensitive = bool(self.behavior.get("sensitive_chain_requires_command", True))
        credential_exfil_events = (credential_shell_events or strong_credential_events) if strict_credential else (credential_events or credential_shell_events or strong_credential_events)
        sensitive_chain_events = (strong_sensitive_events or credential_exfil_events) if strict_sensitive else (sensitive_events or credential_exfil_events)

        if sensitive_chain_events and compression_events and (network_events or network_post):
            hits.append(
                self._combo_hit(
                    "R101",
                    "Sensitive access followed by archive and network transfer",
                    "combo",
                    "chain",
                    "combo_sensitive_archive_network",
                    [sensitive_chain_events[0], compression_events[0], (network_events or [None])[0]],
                    pcap_features if network_post else None,
                )
            )
        if sensitive_chain_events and network_events:
            hits.append(
                self._combo_hit(
                    "R106",
                    "Sensitive access with explicit upload or transfer command",
                    "combo",
                    "chain",
                    "combo_sensitive_upload",
                    [sensitive_chain_events[0], network_events[0]],
                )
            )
        if sensitive_chain_events and network_post:
            hits.append(
                self._combo_hit(
                    "R107",
                    "Sensitive access with HTTP POST network evidence",
                    "combo",
                    "chain",
                    "combo_sensitive_network_post",
                    [sensitive_chain_events[0]],
                    pcap_features,
                )
            )
        cleanup_chain_events = [event for event in cleanup_events if self._is_command_access_context(event)]
        if cleanup_chain_events and (credential_exfil_events or (strong_sensitive_events and (network_events or network_post or privilege_events))):
            hits.append(
                self._combo_hit(
                    "R102",
                    "Trace cleanup combined with sensitive behavior",
                    "combo",
                    "chain",
                    "combo_cleanup_plus_sensitive",
                    [cleanup_chain_events[0], (credential_exfil_events or strong_sensitive_events)[0]],
                )
            )
        if credential_shell_events or (
            not bool(self.behavior.get("credential_shell_requires_same_event", True)) and credential_events and shell_events
        ):
            hits.append(
                self._combo_hit(
                    "R109",
                    "Credential access through shell or command execution",
                    "combo",
                    "chain",
                    "combo_credential_shell",
                    [credential_shell_events[0] if credential_shell_events else credential_events[0], shell_events[0] if shell_events and not credential_shell_events else None],
                )
            )
        if privilege_events and strong_sensitive_events:
            hits.append(
                self._combo_hit(
                    "R103",
                    "Privilege change with sensitive access",
                    "combo",
                    "chain",
                    "combo_privilege_followup",
                    [privilege_events[0], strong_sensitive_events[0]],
                )
            )
        if privilege_events and shell_events and (network_observed or network_events or network_post):
            hits.append(
                self._combo_hit(
                    "R110",
                    "Privilege command with shell and network context",
                    "combo",
                    "chain",
                    "combo_privilege_shell_network_context",
                    [privilege_events[0], shell_events[0]],
                    pcap_features,
                )
            )
        if suspicious_powershell_events and (network_events or network_post):
            hits.append(
                self._combo_hit(
                    "R111",
                    "Suspicious PowerShell with network transfer",
                    "combo",
                    "chain",
                    "combo_powershell_network",
                    [suspicious_powershell_events[0], (network_events or [None])[0]],
                    pcap_features if network_post else None,
                )
            )
        persistence_followup_events = credential_exfil_events or strong_sensitive_events or network_events or privilege_events
        persistence_chain_events = persistence_events if (
            (shell_events or agent_tool_events or suspicious_powershell_events)
            and (persistence_followup_events or network_post)
        ) else []
        if persistence_chain_events and suspicious_command_events:
            hits.append(
                self._combo_hit(
                    "R112",
                    "Persistence mechanism created by suspicious command",
                    "combo",
                    "chain",
                    "combo_persistence_command",
                    [persistence_chain_events[0], suspicious_command_events[0]],
                )
            )
        if lateral_events and credential_exfil_events:
            hits.append(
                self._combo_hit(
                    "R113",
                    "Lateral movement combined with credential access",
                    "combo",
                    "chain",
                    "combo_lateral_credential",
                    [lateral_events[0], credential_exfil_events[0]],
                )
            )
        if credential_exfil_events and (copy_events or compression_events or network_events or network_post):
            hits.append(
                self._combo_hit(
                    "R104",
                    "Credential access with packaging or transfer evidence",
                    "combo",
                    "chain",
                    "combo_credential_exfil",
                    [credential_exfil_events[0], (copy_events or compression_events or network_events or [None])[0]],
                    pcap_features if network_post else None,
                )
            )
        credential_file_path = bool(
            strong_credential_events
            or credential_shell_events
            or [event for event in credential_events if self._has_real_credential_artifact(f"{self._command_text(event)} {event.text.lower()}")]
        )
        strong_file_context = bool(strong_sensitive_events or strong_credential_events or credential_shell_events or credential_file_path)

        if credential_file_path and command_context_events and compression_events and network_post:
            hits.append(
                self._combo_hit(
                    "R116",
                    "Credential access with archive and HTTP POST evidence",
                    "combo",
                    "chain",
                    "combo_credential_archive_post",
                    [credential_events[0], compression_events[0]],
                    pcap_features,
                )
            )
        if credential_file_path and command_context_events and (compression_events or copy_events) and network_observed and not (network_events or network_post):
            hits.append(
                self._combo_hit(
                    "R115",
                    "Credential access with packaging and network context",
                    "combo",
                    "chain",
                    "combo_credential_package_network_observed",
                    [credential_events[0], (compression_events or copy_events)[0]],
                    pcap_features if self._is_network_observed(pcap_features) else None,
                )
            )
        if shell_events and sensitive_chain_events and (network_events or network_post):
            hits.append(
                self._combo_hit(
                    "R108",
                    "Shell command with sensitive path and network transfer",
                    "combo",
                    "chain",
                    "combo_shell_sensitive_network",
                    [shell_events[0], sensitive_chain_events[0], (network_events or [None])[0]],
                    pcap_features if network_post else None,
                )
            )
        if sensitive_events and command_context_events and shell_events and suspicious_command_events and network_observed and not (network_events or network_post):
            hits.append(
                self._combo_hit(
                    "R114",
                    "Sensitive access with shell command and network context",
                    "combo",
                    "chain",
                    "combo_sensitive_shell_network_observed",
                    [sensitive_events[0], shell_events[0], suspicious_command_events[0]],
                    pcap_features if self._is_network_observed(pcap_features) else None,
                )
            )
        if agent_tool_events and (network_events or network_post) and (sensitive_chain_events or credential_exfil_events):
            hits.append(
                self._combo_hit(
                    "R105",
                    "Agent tool behavior correlated with audit or network evidence",
                    "combo",
                    "chain",
                    "correlated_agent_audit_network",
                    [agent_tool_events[0], (sensitive_chain_events or credential_exfil_events)[0], (network_events or [None])[0]],
                    pcap_features if network_post else None,
                )
            )

        chain_candidate_rules = {hit.rule_id for hit in hits if hit.severity in {"chain", "terminal"}}
        explicitly_malicious_rules = {"R005"} if destructive_events else set()
        strong_chain_rules = set(explicitly_malicious_rules)
        if real_exfil := bool(network_events or network_post):
            strong_chain_rules.update(chain_candidate_rules & {"R101", "R106", "R107", "R108", "R105", "R111"})
        if credential_file_path and command_context_events and (network_events or network_post or compression_events or copy_events):
            strong_chain_rules.update(chain_candidate_rules & {"R104", "R116"})
        if credential_shell_events and (network_events or network_post or compression_events or copy_events):
            strong_chain_rules.update(chain_candidate_rules & {"R109"})
        if privilege_events and (strong_file_context or real_exfil or persistence_chain_events):
            strong_chain_rules.update(chain_candidate_rules & {"R103", "R110"})
        if persistence_chain_events and suspicious_command_events:
            strong_chain_rules.update(chain_candidate_rules & {"R112"})
        if lateral_events and credential_exfil_events:
            strong_chain_rules.update(chain_candidate_rules & {"R113"})

        max_chain_weight = max((float(hit.weight) for hit in hits if hit.rule_id in strong_chain_rules), default=0.0)
        rule_ids = {hit.rule_id for hit in hits}
        weak_credential_chain = bool(rule_ids & {"R115", "R116"} and not (strong_chain_rules & {"R115", "R116"}))
        weak_sensitive_chain = bool(rule_ids & {"R114"})
        observed_network_chain = bool(rule_ids & {"R114", "R115"})
        strong_categories = sorted(
            {
                category
                for category, active in {
                    "sensitive": bool(strong_sensitive_events or (weak_sensitive_chain and strong_chain_rules)),
                    "credential": bool(strong_credential_events or credential_shell_events or (weak_credential_chain and strong_chain_rules)),
                    "archive": bool(compression_events),
                    "network": bool(network_events or network_post or (observed_network_chain and strong_chain_rules) or (network_observed and self.behavior.get("include_network_observed_as_strong_category", False))),
                    "privilege": bool(privilege_events),
                    "cleanup": bool(cleanup_chain_events),
                    "destructive": bool(destructive_events),
                    "agent": bool(agent_tool_events or shell_events or credential_shell_events),
                    "powershell": bool(suspicious_powershell_events),
                    "persistence": bool(persistence_chain_events),
                    "lateral": bool(lateral_events),
                }.items()
                if active
            }
        )

        signals = {
            "sensitive_access": bool(sensitive_events),
            "credential_access": bool(credential_events),
            "strong_sensitive_access": bool(strong_sensitive_events),
            "strong_credential_access": bool(strong_credential_events),
            "compression": bool(compression_events),
            "network_transfer": bool(network_events),
            "network_post": bool(network_post),
            "network_observed": bool(network_observed),
            "sysmon_network_observed": bool(sysmon_network_events),
            "destructive": bool(destructive_events),
            "privilege": bool(privilege_events),
            "trace_cleanup": bool(cleanup_events),
            "agent_tool_abuse": bool(agent_tool_events),
            "shell_or_cmd": bool(shell_events or credential_shell_events),
            "credential_shell_access": bool(credential_shell_events),
            "copy_or_download": bool(copy_events),
            "suspicious_command": bool(suspicious_command_events),
            "suspicious_powershell": bool(suspicious_powershell_events),
            "persistence": bool(persistence_events),
            "lateral_movement": bool(lateral_events),
            "suspicious_pcap": bool(suspicious_network),
            "strong_chain": bool(strong_chain_rules),
            "chain_candidates": sorted(chain_candidate_rules),
            "explicit_malicious_action": bool(destructive_events),
            "real_command_context": bool(command_context_events),
            "real_exfil": real_exfil,
            "credential_file_path": credential_file_path,
            "terminal_rule": bool(any(hit.severity == "terminal" for hit in hits)),
            "strong_chain_rules": sorted(strong_chain_rules),
            "max_chain_weight": max_chain_weight,
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
            fields.get("image"),
            fields.get("command_line"),
            fields.get("parent_image"),
            fields.get("parent_command_line"),
            fields.get("target_filename"),
            fields.get("current_directory"),
            fields.get("query_name"),
            fields.get("destination_ip"),
            fields.get("destination_port"),
        ]
        return " ".join(str(value) for value in values if value not in (None, "")).lower()

    def _is_plain_session_text(self, event: Event) -> bool:
        if event.source != "session":
            return False
        if event.event_type in {"session", "message", "model_change", "thinking", "thinking_level_change", "custom"}:
            return True
        fields = event.fields or {}
        command_fields = ["tool", "action", "cmd", "function_call", "params", "args"]
        return not any(fields.get(key) not in (None, "") for key in command_fields)

    def _is_llm_api_discussion_text(self, text: str) -> bool:
        benign_markers = [
            "openai",
            "completions",
            "openai-completions",
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/responses",
            "api key",
        ]
        return contains_any(text, benign_markers)

    def _has_real_credential_artifact(self, text: str) -> bool:
        lower = text.lower()
        if any(marker in lower for marker in ["/etc/shadow", "id_rsa", "authorized_keys", "private key"]):
            return True
        if any(marker.lower() in lower for marker in self.keywords.get("windows_credential_artifacts", [])):
            return True
        if self._has_sensitive_keyword_path(lower):
            return True
        if re.search(r"\b(env|printenv)\b", lower) and re.search(r"\b(token|secret|credential|password|api[_-]?key|access[_-]?key)\b", lower):
            return True
        return False

    def _has_sensitive_artifact(self, text: str) -> bool:
        lower = text.lower()
        if any(marker in lower for marker in ["/etc/passwd", "/etc/shadow", "/.ssh", ".ssh/", "id_rsa", "authorized_keys"]):
            return True
        if self._has_sensitive_keyword_path(lower):
            return True
        return False

    def _has_sensitive_keyword_path(self, text: str) -> bool:
        keyword = r"(?:tokens?|secrets?|credentials?|passwords?|shadow|api[_-]?keys?|access[_-]?keys?)"
        return re.search(rf"(?:^|[/\\._-]){keyword}(?:$|[/\\._-])", text) is not None

    def _is_command_access_context(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if event.source == "audit" and event.event_type in {"execve", "proctitle", "syscall"}:
            return bool(command_text)
        if event.source == "session":
            return contains_any(command_text, ["cmd_run", "shell", "bash", "sh", "cat", "grep", "cp", "tar"])
        if event.source == "sysmon":
            return event.event_type in {"1", "process_create", "process creation", "sysmon"} or bool(
                event.fields.get("command_line") or event.fields.get("image")
            )
        return False

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

    def _is_high_confidence_sensitive_access(self, event: Event) -> bool:
        if self._is_plain_session_text(event):
            return False
        command_text = self._command_text(event)
        combined = f"{command_text} {event.text.lower()}"
        if self._is_llm_api_discussion_text(combined) and not self._has_real_credential_artifact(combined):
            return False
        if not self._has_sensitive_artifact(combined):
            return False
        action = contains_any(
            command_text,
            self.keywords.get("read_markers", [])
            + self.keywords.get("compression_tools", [])
            + self.keywords.get("upload_tools", [])
            + ["grep", "awk", "sed", "findstr", "get-content", "type"],
        )
        if event.source in {"audit", "session", "sysmon"} and self._is_command_access_context(event) and action:
            return True
        return False

    def _is_credential_access(self, event: Event) -> bool:
        text = event.text.lower()
        if self._is_plain_session_text(event):
            return False
        if self._is_llm_api_discussion_text(text) and not self._has_real_credential_artifact(text):
            return False
        credential = contains_any(text, self.keywords.get("credential_keywords", []))
        strong_path = self._has_real_credential_artifact(text)
        read_marker = contains_any(text, self.keywords.get("read_markers", []))
        return strong_path or (credential and read_marker)

    def _is_high_confidence_credential_access(self, event: Event) -> bool:
        if self._is_plain_session_text(event):
            return False
        command_text = self._command_text(event)
        combined = f"{command_text} {event.text.lower()}"
        if self._is_llm_api_discussion_text(combined) and not self._has_real_credential_artifact(combined):
            return False
        if not self._has_real_credential_artifact(combined):
            return False
        if not self._is_command_access_context(event):
            return False
        return contains_any(
            command_text,
            self.keywords.get("read_markers", [])
            + self.keywords.get("compression_tools", [])
            + ["grep", "awk", "sed", "findstr", "get-content", "type", "env", "printenv", "mimikatz", "procdump"],
        )

    def _is_credential_shell_access(self, event: Event) -> bool:
        if self._is_plain_session_text(event):
            return False
        command_text = self._command_text(event)
        combined = f"{command_text} {event.text.lower()}"
        if self._is_llm_api_discussion_text(combined) and not self._has_real_credential_artifact(combined):
            return False
        if not self._is_command_access_context(event):
            return False
        access_action = contains_any(
            command_text,
            [
                "cat",
                "grep",
                "cp",
                "copy",
                "tar",
                "zip",
                "read_file",
                "download",
                "env",
                "printenv",
                "awk",
                "sed",
                "type",
                "findstr",
                "get-content",
                "reg save",
                "procdump",
                "mimikatz",
                "certutil",
            ],
        )
        if not access_action:
            return False
        return self._has_real_credential_artifact(combined)

    def _is_archive_action(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if event.source == "audit" and event.event_type not in {"execve", "proctitle", "syscall"}:
            return False
        return contains_any(command_text, self.keywords.get("compression_tools", []))

    def _is_network_exfil_event(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if event.source == "audit" and event.event_type not in {"execve", "proctitle", "syscall"}:
            return False
        if self._is_plain_session_text(event):
            return False
        if self._is_llm_api_discussion_text(command_text) and not contains_any(
            command_text,
            ["--upload-file", "--form", " -f ", " -d ", "--data", "--data-binary", "--post-file", "--post-data", "file=@", "/upload"],
        ):
            return False
        direct_transfer = contains_any(command_text, ["scp", "sftp", "rsync", "ftp ", "upload"])
        curl_upload = contains_any(
            command_text,
            ["--upload-file", "--form", " -f ", " -d ", "--data", "--data-binary", "file=@", "/upload", "method=post"],
        )
        wget_upload = contains_any(command_text, ["--post-file", "--post-data"])
        if event.source == "sysmon" and event.event_type in {"3", "network", "network_connection"}:
            return contains_any(command_text, ["powershell", "pwsh", "certutil", "bitsadmin"]) and not self._is_llm_api_discussion_text(command_text)
        return direct_transfer or curl_upload or wget_upload

    def _is_sysmon_network_observed(self, event: Event) -> bool:
        if event.source != "sysmon":
            return False
        if event.event_type not in {"3", "network", "network_connection"}:
            return False
        fields = event.fields or {}
        return bool(fields.get("destination_ip") or fields.get("destination_port") or fields.get("query_name"))

    def _is_destructive_action(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if event.source == "audit" and event.event_type not in {"execve", "proctitle", "syscall"}:
            return False
        if event.source == "session" and event.event_type in {"message", "session", "model_change", "thinking_level_change", "custom"}:
            return False
        agent_asset_path = contains_any(
            command_text,
            [
                ".openclaw/skills",
                "agent skills",
                "/skills/",
                "\\skills\\",
                "plugins/",
                "\\plugins\\",
                "tools/",
                "\\tools\\",
            ],
        )
        recursive_delete = (
            contains_any(command_text, ["rm -rf", "rm -fr", "rm -r -f", "rmdir /s /q", "del /f /s /q"])
            or ("remove-item" in command_text and "-recurse" in command_text and "-force" in command_text)
        )
        if agent_asset_path and recursive_delete:
            return True
        return contains_any(command_text, self.keywords.get("destructive_commands", []))

    def _is_copy_action(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if event.source == "audit" and event.event_type not in {"execve", "proctitle", "syscall"}:
            return False
        if self._is_plain_session_text(event):
            return False
        return contains_any(command_text, ["copy", "cp", "download", "write_file", "xcopy", "robocopy", "reg save"])

    def _is_shell_or_cmd_event(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if event.source == "session":
            return contains_any(command_text, self.keywords.get("shell_tools", []))
        if event.source == "audit" and event.event_type in {"execve", "proctitle", "syscall"}:
            return contains_any(command_text, ["bash", "sh", "zsh", "python", "perl"])
        if event.source == "sysmon":
            return contains_any(command_text, self.keywords.get("shell_tools", []) + ["cmd.exe", "powershell", "pwsh"])
        return False

    def _is_suspicious_command(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if not command_text:
            return False
        if event.source == "session" and event.event_type in {"message", "session", "model_change", "thinking_level_change", "custom"}:
            return False
        return contains_any(command_text, self.keywords.get("suspicious_commands", []))

    def _is_suspicious_powershell(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if not contains_any(command_text, ["powershell", "pwsh"]):
            return False
        return contains_any(command_text, self.keywords.get("suspicious_powershell_markers", []))

    def _is_persistence_action(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if event.source == "session" and event.event_type in {"message", "session", "model_change", "thinking_level_change", "custom"}:
            return False
        return contains_any(command_text, self.keywords.get("persistence_markers", []))

    def _is_lateral_movement(self, event: Event) -> bool:
        command_text = self._command_text(event)
        if event.source == "session" and event.event_type in {"message", "session", "model_change", "thinking_level_change", "custom"}:
            return False
        return contains_any(command_text, self.keywords.get("lateral_movement_markers", []))

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

    def _counter_items(self, value: Any) -> list[str]:
        items: list[str] = []
        if isinstance(value, dict):
            return [str(key) for key in value]
        if isinstance(value, list):
            for item in value:
                if isinstance(item, (list, tuple)) and item:
                    items.append(str(item[0]))
                elif isinstance(item, dict):
                    first = item.get("value") or item.get("name") or item.get("host") or item.get("path")
                    if first:
                        items.append(str(first))
                elif item not in (None, ""):
                    items.append(str(item))
        return items

    def _is_benign_model_api_pcap(self, features: dict[str, Any]) -> bool:
        http_post = int(features.get("http_post_count") or 0)
        if http_post <= 0:
            return False
        hosts = [item.lower() for item in self._counter_items(features.get("http_hosts"))]
        paths = [item.lower() for item in self._counter_items(features.get("http_paths"))]
        agents = [item.lower() for item in self._counter_items(features.get("user_agents"))]
        keywords = self.keywords
        benign_hosts = keywords.get("benign_llm_hosts", [])
        benign_paths = keywords.get("benign_llm_paths", [])
        benign_agents = keywords.get("benign_llm_user_agents", [])
        host_ok = not hosts or all(contains_any(host, benign_hosts) for host in hosts)
        path_ok = bool(paths) and all(contains_any(path, benign_paths) for path in paths)
        agent_ok = not agents or any(contains_any(agent, benign_agents) for agent in agents)
        return host_ok and path_ok and agent_ok

    def _is_network_post_exfil(self, features: dict[str, Any]) -> bool:
        http_post = int(features.get("http_post_count") or 0)
        if http_post <= 0:
            return False
        if self._is_benign_model_api_pcap(features):
            return False
        paths = self._counter_items(features.get("http_paths"))
        hosts = self._counter_items(features.get("http_hosts"))
        require_details = bool(self.rules_config.get("network", {}).get("require_http_details_for_post", True))
        if require_details and not paths and not hosts:
            return False
        suspicious_domain = any(contains_any(host, self.keywords.get("suspicious_domains", [])) for host in hosts)
        transfer_path = any(contains_any(path, self.keywords.get("upload_tools", [])) for path in paths)
        return suspicious_domain or transfer_path or not require_details

    def _is_suspicious_network(self, features: dict[str, Any], network_post: bool = False) -> bool:
        if not features:
            return False
        ports = set(int(port) for port in features.get("dst_ports") or [])
        suspicious_ports = set(int(port) for port in self.rules_config.get("pcap", {}).get("suspicious_nonstandard_ports", []))
        if not suspicious_ports:
            suspicious_ports = {4444, 5555, 6667, 8081, 9001, 1337}
        suspicious_domain = False
        hosts = self._counter_items(features.get("http_hosts"))
        for host in hosts:
            if contains_any(str(host), self.keywords.get("suspicious_domains", [])):
                suspicious_domain = True
                break
        return network_post or bool(ports & suspicious_ports) or suspicious_domain

    def _is_network_observed(self, features: dict[str, Any]) -> bool:
        if not features:
            return False
        return bool(
            int(features.get("external_ip_count") or 0) > 0
            or int(features.get("http_post_count") or 0) > 0
        )

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
