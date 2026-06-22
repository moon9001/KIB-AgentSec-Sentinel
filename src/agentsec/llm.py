from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import urlparse

from .models import DetectionResult


LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


class LLMAnalyzer:
    def __init__(self, llm_config: dict[str, Any]) -> None:
        self.config = llm_config
        provider = os.getenv("AGENTSEC_LLM_PROVIDER", "").lower().strip()
        default_base_url = str(llm_config.get("base_url", "http://127.0.0.1:8000/v1"))
        default_model = str(llm_config.get("model", "qwen36-27b"))
        if provider == "deepseek":
            default_base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
            default_model = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash")
        self.base_url = os.getenv("AGENTSEC_LLM_BASE_URL", default_base_url)
        self.model = os.getenv("AGENTSEC_LLM_MODEL", default_model)
        self.timeout = float(os.getenv("AGENTSEC_LLM_TIMEOUT", str(llm_config.get("timeout_seconds", 8))))
        self.api_key = (
            os.getenv("AGENTSEC_LLM_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("DEEPSEEK_API_KEY")
            or ""
        )
        allow_external_env = os.getenv("AGENTSEC_ALLOW_EXTERNAL_LLM", "").lower() in {"1", "true", "yes"}
        self.allow_external_api = bool(llm_config.get("allow_external_api", False)) or allow_external_env

    def should_call(self, result: DetectionResult) -> bool:
        min_score = float(self.config.get("min_score", 35))
        return result.score >= min_score

    def analyze(self, result: DetectionResult) -> dict[str, Any]:
        if not self._is_allowed_endpoint():
            return self._mock(result, "external LLM endpoint disabled by configuration")
        try:
            import requests
        except ImportError:
            return self._mock(result, "requests is not installed")

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an offline security triage assistant. Return compact JSON only with keys "
                        "is_malicious, risk_level, attack_types, confidence, summary, recommendation. "
                        "Do not ask for raw logs and do not suggest destructive actions."
                    ),
                },
                {"role": "user", "content": self._prompt(result)},
            ],
            "temperature": 0.1,
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            response = requests.post(
                f"{self.base_url.rstrip('/')}/chat/completions",
                headers=headers,
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            body = response.json()
            content = body["choices"][0]["message"]["content"]
            parsed = self._parse_json_content(content)
            parsed["mode"] = "llm"
            parsed["model"] = self.model
            return parsed
        except Exception as exc:
            return self._mock(result, f"llm unavailable or invalid response: {exc}")

    def _is_allowed_endpoint(self) -> bool:
        parsed = urlparse(self.base_url)
        host = parsed.hostname or ""
        return self.allow_external_api or host in LOCAL_HOSTS

    def _prompt(self, result: DetectionResult) -> str:
        max_evidence = int(self.config.get("max_evidence", 8))
        compact = {
            "md5": result.md5,
            "rule_label": result.label,
            "rule_score": result.score,
            "risk_level": result.risk_level,
            "matched_rules": [
                {
                    "rule_id": hit.rule_id,
                    "name": hit.name,
                    "severity": hit.severity,
                    "category": hit.category,
                }
                for hit in result.matched_rules
            ],
            "evidence": [
                {
                    "source": item.source,
                    "rule_id": item.rule_id,
                    "message": item.message,
                    "excerpt": item.excerpt,
                }
                for item in result.evidence[:max_evidence]
            ],
            "feature_summary": result.feature_summary,
            "behavior_chains": result.behavior_chains,
        }
        return json.dumps(compact, ensure_ascii=False, sort_keys=True)

    def _parse_json_content(self, content: str) -> dict[str, Any]:
        text = content.strip()
        fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.S | re.I)
        if fenced:
            text = fenced.group(1).strip()
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            text = text[start : end + 1]
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("LLM response JSON is not an object")
        return parsed

    def _mock(self, result: DetectionResult, reason: str) -> dict[str, Any]:
        attack_types = [hit.category for hit in result.matched_rules if hit.category != "combo"]
        return {
            "mode": "mock",
            "reason": reason,
            "is_malicious": bool(result.label),
            "risk_level": result.risk_level,
            "attack_types": sorted(set(attack_types)),
            "confidence": 0.65 if result.label else 0.35,
            "summary": "Rule-only analysis; LLM was not used.",
            "recommendation": "Review detail.jsonl evidence and validate against the original offline sample if needed.",
        }
