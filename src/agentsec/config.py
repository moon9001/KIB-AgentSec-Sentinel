from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import deep_merge


DEFAULT_CONFIG: dict[str, Any] = {
    "rules_file": "rules/default_rules.yaml",
    "scoring": {
        "score_threshold": 60,
        "label_threshold": 60,
        "strong_chain_threshold": 55,
        "weak_keyword_weight": 1,
        "weak_signal_score_cap": 34,
        "require_chain_for_label1": True,
        "min_strong_categories_for_label1": 2,
        "llm_min_score": 35,
        "llm_correction_min_confidence": 0.7,
        "default_label_on_error": 0,
        "max_score": 100,
        "risk_levels": {"low": 10, "medium": 35, "high": 60, "critical": 80},
    },
    "llm": {
        "enabled": False,
        "base_url": "http://127.0.0.1:8000/v1",
        "model": "qwen36-27b",
        "timeout_seconds": 8,
        "llm_min_score": 35,
        "min_score": 35,
        "borderline_window": 12,
        "max_evidence": 8,
        "allow_external_api": False,
    },
    "pcap_enabled": True,
    "pcap_max_packets": 50000,
    "evidence_excerpt_max_chars": 240,
    "default_label_on_error": 0,
    "pcap": {
        "enabled": True,
        "max_packets": 50000,
        "suspicious_external_threshold": 1,
        "suspicious_connection_threshold": 200,
        "suspicious_nonstandard_ports": [4444, 5555, 6667, 8081, 9001, 1337],
    },
    "output": {"evidence_excerpt_chars": 240, "evidence_excerpt_max_chars": 240},
}


DEFAULT_RULES: dict[str, Any] = {
    "weights": {
        "sensitive_file_access": 4,
        "credential_access": 8,
        "compression_archive": 4,
        "network_exfil": 6,
        "destructive_command": 80,
        "privilege_escalation": 8,
        "trace_cleanup": 8,
        "agent_tool_abuse": 6,
        "suspicious_network": 3,
        "combo_sensitive_archive_network": 60,
        "combo_sensitive_upload": 56,
        "combo_sensitive_network_post": 56,
        "combo_cleanup_plus_sensitive": 55,
        "combo_privilege_followup": 55,
        "combo_credential_exfil": 75,
        "combo_shell_sensitive_network": 60,
        "combo_credential_shell": 60,
        "combo_privilege_shell_network_context": 55,
        "correlated_agent_audit_network": 55,
    },
    "keywords": {
        "sensitive_paths": ["/etc/passwd", "/etc/shadow", "/.ssh", ".ssh/", "id_rsa", "authorized_keys"],
        "credential_keywords": ["token", "secret", "credential", "passwd", "shadow", "id_rsa", "api_key"],
        "read_markers": ["read_file", "cat", "open", "copy", "cp", "download"],
        "compression_tools": ["tar", "zip", "gzip", "7z", "rar"],
        "upload_tools": ["curl", "wget", "scp", "ftp", "sftp", "rsync", "upload", "post"],
        "privilege_tools": ["sudo", "su", "chmod 777", "chown", "setuid", "useradd", "passwd"],
        "destructive_commands": ["rm -rf", "dd if=", "mkfs", "reboot", "shutdown", "systemctl stop", "kill -9"],
        "trace_cleanup_commands": ["history -c", "truncate", "rm audit.log", "sessions.remove", "clear log"],
        "suspicious_agent_tools": ["openclaw", "gateway", "file_home", "cmd_run", "shell", "network", "upload", "read_file"],
        "shell_tools": ["cmd_run", "shell", "bash", "sh"],
        "suspicious_domains": ["paste", "transfer", "webhook", "ngrok", "requestbin"],
        "benign_llm_hosts": ["llm", "localhost", "127.0.0.1", "openai"],
        "benign_llm_paths": ["/v1/chat/completions", "/v1/completions", "/v1/responses", "/health"],
        "benign_llm_user_agents": ["openai", "python-requests"],
    },
    "network": {"require_http_details_for_post": True},
}


def load_yaml(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    file_path = Path(path)
    if not file_path.exists():
        return {}
    try:
        import yaml
    except ImportError:
        return {}
    with file_path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    return loaded if isinstance(loaded, dict) else {}


def load_config(config_path: str | Path | None) -> tuple[dict[str, Any], dict[str, Any]]:
    config_file = Path(config_path) if config_path else None
    config = deep_merge(DEFAULT_CONFIG, load_yaml(config_file))

    rules_file = Path(str(config.get("rules_file", "rules/default_rules.yaml")))
    if not rules_file.is_absolute():
        base = config_file.parent if config_file else Path.cwd()
        candidate = base / rules_file
        if not candidate.exists():
            candidate = Path.cwd() / rules_file
        rules_file = candidate

    rules = deep_merge(DEFAULT_RULES, load_yaml(rules_file))
    return config, rules
