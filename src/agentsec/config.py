from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import deep_merge

PROJECT_ROOT = Path(__file__).resolve().parents[2]
VALID_PROFILES = {"balanced", "recall", "precision"}


DEFAULT_CONFIG: dict[str, Any] = {
    "profile": "balanced",
    "rules_file": "rules/default_rules.yaml",
    "scoring": {
        "score_threshold": 60,
        "label_threshold": 60,
        "strong_chain_threshold": 55,
        "weak_keyword_weight": 1,
        "weak_signal_score_cap": 34,
        "require_chain_for_label1": True,
        "min_strong_categories_for_label1": 2,
        "terminal_rule_ids": ["R005"],
        "llm_min_score": 35,
        "llm_correction_min_confidence": 0.7,
        "default_label_on_error": 0,
        "max_score": 100,
        "risk_levels": {"low": 10, "medium": 35, "high": 60, "critical": 80},
    },
    "llm": {
        "enabled": False,
        "mode": "borderline",
        "base_url": "http://127.0.0.1:8000/v1",
        "model": "qwen36-27b",
        "timeout": 180,
        "timeout_seconds": 180,
        "llm_min_score": 4,
        "min_score": 4,
        "max_score": 80,
        "max_cases": 0,
        "borderline_window": 12,
        "max_evidence": 8,
        "cache": True,
        "cache_path": "data/work/llm_cache.jsonl",
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
        "combo_powershell_network": 58,
        "combo_persistence_command": 58,
        "combo_lateral_credential": 65,
        "combo_sensitive_shell_network_observed": 55,
        "combo_credential_package_network_observed": 55,
        "combo_credential_archive_post": 56,
        "suspicious_powershell": 8,
        "persistence": 8,
        "lateral_movement": 10,
        "suspicious_command": 4,
    },
    "keywords": {
        "sensitive_paths": ["/etc/passwd", "/etc/shadow", "/.ssh", ".ssh/", "id_rsa", "authorized_keys"],
        "credential_keywords": [
            "token",
            "secret",
            "credential",
            "passwd",
            "shadow",
            "id_rsa",
            "api_key",
            "lsass",
            "ntds.dit",
            "mimikatz",
            "sam",
        ],
        "read_markers": ["read_file", "cat", "open", "copy", "cp", "download", "type", "findstr", "get-content", "reg save", "procdump"],
        "compression_tools": ["tar", "zip", "gzip", "7z", "rar"],
        "upload_tools": ["curl", "wget", "scp", "ftp", "sftp", "rsync", "upload", "post"],
        "privilege_tools": ["sudo", "su", "chmod 777", "chown", "setuid", "useradd", "passwd"],
        "destructive_commands": [
            "rm -rf",
            "rm -fr",
            "rm -r -f",
            "dd if=",
            "mkfs",
            "reboot",
            "shutdown",
            "systemctl stop",
            "kill -9",
            "rmdir /s /q",
            "del /f /s /q",
        ],
        "trace_cleanup_commands": ["history -c", "truncate", "rm audit.log", "sessions.remove", "clear log"],
        "suspicious_agent_tools": ["openclaw", "gateway", "file_home", "cmd_run", "shell", "network", "upload", "read_file"],
        "shell_tools": ["cmd_run", "shell", "bash", "sh"],
        "suspicious_commands": [
            "powershell",
            "pwsh",
            "cmd.exe",
            "cmd ",
            "wscript",
            "cscript",
            "rundll32",
            "regsvr32",
            "mshta",
            "wmic",
            "schtasks",
            "bitsadmin",
            "certutil",
            "curl",
            "wget",
            "scp",
            "ftp",
            "sftp",
            "python",
            "node",
        ],
        "suspicious_powershell_markers": [
            "encodedcommand",
            "-enc",
            "downloadstring",
            "invoke-webrequest",
            "invoke-restmethod",
            "iex",
            "bypass",
            "hidden",
            "noprofile",
        ],
        "persistence_markers": [
            "runonce",
            "\\run",
            "startup",
            "schtasks",
            "sc create",
            "new-service",
            "service create",
        ],
        "lateral_movement_markers": [
            "psexec",
            "wmic process call create",
            "winrm",
            "enter-pssession",
            "invoke-command",
            "mstsc",
            "admin$",
            "c$",
            "ipc$",
            "\\\\",
        ],
        "windows_credential_artifacts": [
            "lsass",
            "ntds.dit",
            "\\windows\\system32\\config\\sam",
            "\\windows\\system32\\config\\system",
            "\\windows\\system32\\config\\security",
            "hklm\\sam",
            "hklm\\system",
            "hklm\\security",
            "mimikatz",
            "procdump",
            "login data",
            "cookies",
            "web data",
        ],
        "suspicious_domains": ["paste", "transfer", "webhook", "ngrok", "requestbin"],
        "benign_llm_hosts": ["llm", "localhost", "127.0.0.1", "openai"],
        "benign_llm_paths": ["/v1/chat/completions", "/v1/completions", "/v1/responses", "/health"],
        "benign_llm_user_agents": ["openai", "python-requests"],
    },
    "network": {"require_http_details_for_post": True},
    "profile_behavior": {
        "credential_shell_requires_same_event": True,
        "credential_exfil_requires_command": True,
        "sensitive_chain_requires_command": True,
        "include_network_observed_as_strong_category": False,
    },
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


def normalize_profile(profile: str | None) -> str:
    value = (profile or "").strip().lower()
    if not value:
        return "balanced"
    if value not in VALID_PROFILES:
        raise ValueError(f"Unknown profile '{profile}'. Expected one of: {', '.join(sorted(VALID_PROFILES))}")
    return value


def profile_config_path(profile: str) -> Path:
    return PROJECT_ROOT / "configs" / f"{profile}.yaml"


def load_config(config_path: str | Path | None, profile: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    config_file = Path(config_path) if config_path else None
    file_config = load_yaml(config_file)
    selected_profile = normalize_profile(profile or str(file_config.get("profile", DEFAULT_CONFIG.get("profile", "balanced"))))
    profile_file = profile_config_path(selected_profile)
    config = deep_merge(DEFAULT_CONFIG, load_yaml(profile_file))
    config = deep_merge(config, file_config)
    if profile:
        config = deep_merge(config, load_yaml(profile_file))
    config["profile"] = selected_profile
    config["profile_config_source"] = str(profile_file) if profile_file.exists() else "defaults"
    config["config_path"] = str(config_file) if config_file else ""

    rules_file = Path(str(config.get("rules_file", "rules/default_rules.yaml")))
    if not rules_file.is_absolute():
        base = config_file.parent if config_file else PROJECT_ROOT
        candidate = base / rules_file
        if not candidate.exists():
            candidate = PROJECT_ROOT / rules_file
        rules_file = candidate

    rules = deep_merge(DEFAULT_RULES, load_yaml(rules_file))
    rules = deep_merge(rules, config.get("rule_overrides", {}))
    rules = deep_merge(rules, config.get("rules", {}))
    return config, rules
