#!/usr/bin/env python3
from __future__ import annotations

import importlib
import json
import socket
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentsec.config import load_config  # noqa: E402


def import_status(module: str) -> dict[str, Any]:
    try:
        importlib.import_module(module)
        return {"module": module, "available": True}
    except Exception as exc:
        return {"module": module, "available": False, "reason": f"{type(exc).__name__}: {exc}"}


def check_profiles() -> dict[str, Any]:
    profiles: dict[str, Any] = {}
    for profile in ["precision", "balanced", "recall"]:
        try:
            config, rules = load_config(ROOT / "configs" / "default.yaml", profile=profile)
            profiles[profile] = {
                "ok": True,
                "score_threshold": config.get("scoring", {}).get("score_threshold"),
                "strong_chain_threshold": config.get("scoring", {}).get("strong_chain_threshold"),
                "rule_weight_count": len(rules.get("weights", {})),
            }
        except Exception as exc:
            profiles[profile] = {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}
    return profiles


def check_local_llm() -> dict[str, Any]:
    config, _rules = load_config(ROOT / "configs" / "default.yaml", profile="balanced")
    llm = config.get("llm", {})
    base_url = str(llm.get("base_url", "http://127.0.0.1:8000/v1"))
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if host not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
        return {"base_url": base_url, "local_only": False, "available": False, "reason": "configured endpoint is not local"}
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return {"base_url": base_url, "local_only": True, "available": True}
    except OSError as exc:
        return {"base_url": base_url, "local_only": True, "available": False, "reason": str(exc)}


def check_gitignore() -> dict[str, Any]:
    path = ROOT / ".gitignore"
    content = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    expected = [
        "data/",
        "models/",
        "logs/",
        "output/",
        "envs/",
        "cache/",
        "*.zip",
        "*.pcap",
        "*.log",
        "*.csv",
        "*.s3cfg",
        "*.key",
        "*.pem",
        "*.tar.gz",
    ]
    missing = [item for item in expected if item not in content]
    return {"path": str(path), "ok": not missing, "missing": missing}


def main() -> int:
    checks = {
        "imports": [
            import_status("agentsec.pipeline"),
            import_status("agentsec.rules"),
            import_status("agentsec.sysmon"),
            import_status("yaml"),
        ],
        "configs": check_profiles(),
        "llm_local_endpoint": check_local_llm(),
        "pcap_parser": {
            "scapy": import_status("scapy"),
            "dpkt": import_status("dpkt"),
        },
        "sysmon_parser": {
            "json_csv_xml": True,
            "python_evtx": import_status("Evtx.Evtx"),
        },
        "gitignore": check_gitignore(),
    }
    failed = []
    if any(not item.get("available") for item in checks["imports"]):
        failed.append("imports")
    if any(not item.get("ok") for item in checks["configs"].values()):
        failed.append("configs")
    if not checks["gitignore"].get("ok"):
        failed.append("gitignore")
    checks["status"] = "ok" if not failed else "warning"
    checks["failed_required_checks"] = failed
    print(json.dumps(checks, ensure_ascii=False, indent=2, default=str))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
