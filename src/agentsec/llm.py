from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import DetectionResult


LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


class LLMAnalyzer:
    def __init__(self, llm_config: dict[str, Any]) -> None:
        self.config = llm_config
        default_base_url = str(llm_config.get("base_url", "http://127.0.0.1:8000/v1"))
        default_model = str(llm_config.get("model", "qwen36-27b"))
        self.base_url = os.getenv("AGENTSEC_LLM_BASE_URL", default_base_url)
        self.model = os.getenv("AGENTSEC_LLM_MODEL", default_model)
        self.timeout = float(os.getenv("AGENTSEC_LLM_TIMEOUT", str(llm_config.get("timeout", llm_config.get("timeout_seconds", 180)))))
        self.api_key = (
            os.getenv("AGENTSEC_LLM_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or ""
        )
        self.final_review_timeout = float(
            os.getenv(
                "AGENTSEC_LLM_FINAL_REVIEW_TIMEOUT",
                str(llm_config.get("final_review_timeout", llm_config.get("llm_final_review_timeout", 300))),
            )
        )
        self.final_review_max_tokens = int(
            os.getenv(
                "AGENTSEC_LLM_FINAL_REVIEW_MAX_TOKENS",
                str(llm_config.get("final_review_max_tokens", llm_config.get("llm_final_review_max_tokens", 96))),
            )
        )
        self.final_review_retries = int(
            os.getenv(
                "AGENTSEC_LLM_FINAL_REVIEW_RETRIES",
                str(llm_config.get("final_review_retries", llm_config.get("llm_final_review_retries", 1))),
            )
        )
        self.final_review_raw_response_chars = int(llm_config.get("final_review_raw_response_chars", 240))
        allow_external_env = os.getenv("AGENTSEC_ALLOW_EXTERNAL_LLM", "").lower() in {"1", "true", "yes"}
        self.allow_external_api = bool(llm_config.get("allow_external_api", False)) or allow_external_env
        self.mode = str(llm_config.get("mode", "borderline")).strip().lower()
        self.max_cases = int(llm_config.get("max_cases", 0) or 0)
        self.calls_made = 0
        self.cache_enabled = bool(llm_config.get("cache", True))
        self.cache_path = Path(str(llm_config.get("cache_path", "data/work/llm_cache.jsonl")))
        self._cache: dict[str, dict[str, Any]] | None = None

    def should_call(self, result: DetectionResult) -> bool:
        return self.skip_reason(result) is None

    def skip_reason(self, result: DetectionResult) -> str | None:
        if self.mode == "off":
            return "LLM mode is off"
        if self.max_cases > 0 and self.calls_made >= self.max_cases:
            return f"LLM max_cases={self.max_cases} reached"
        if self.mode in {"all", "explain-only"}:
            return None
        signals = (result.feature_summary or {}).get("signals", {})
        if signals.get("terminal_rule"):
            return "terminal rule; LLM cannot lower high-confidence detection"
        threshold = float(self.config.get("score_threshold", 60))
        max_chain_weight = float(signals.get("max_chain_weight") or 0)
        if signals.get("strong_chain") and max_chain_weight >= threshold:
            return "strong high-confidence behavior chain"
        min_score = float(self.config.get("llm_min_score", self.config.get("min_score", 35)))
        window = float(self.config.get("borderline_window", 12))
        if result.risk_level == "medium" or (result.score >= min_score and abs(result.score - threshold) <= window):
            return None
        return "not medium or borderline score"

    def analyze(self, result: DetectionResult) -> dict[str, Any]:
        prompt = self._prompt(result)
        cache_key = self._cache_key(prompt)
        cached = self._cache_get(cache_key)
        if cached is not None:
            cached = dict(cached)
            cached["cached"] = True
            return cached
        self.calls_made += 1
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
                        "is_malicious, confidence, risk_level, attack_types, summary, reason, suggested_label. "
                        "Use only the provided feature summary and short evidence excerpts. "
                        "Do not ask for raw logs and do not suggest destructive actions."
                    ),
                },
                {"role": "user", "content": prompt},
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
            self._cache_put(cache_key, parsed)
            return parsed
        except Exception as exc:
            return self._mock(result, f"llm unavailable or invalid response: {exc}")

    def review_final(self, result: DetectionResult) -> dict[str, Any]:
        if self.max_cases > 0 and self.calls_made >= self.max_cases:
            return self._final_review_skip(f"LLM max_cases={self.max_cases} reached")
        prompt = self._final_review_prompt(result)
        cache_key = self._cache_key(f"final-review\n{prompt}")
        cached = self._cache_get(cache_key)
        if cached is not None:
            cached = dict(cached)
            cached["cached"] = True
            cached.setdefault("timeout", False)
            cached.setdefault("retry_count", 0)
            cached.setdefault("raw_response_short", "")
            cached.setdefault("changed", False)
            return cached
        self.calls_made += 1
        if not self._is_allowed_endpoint():
            return self._final_review_skip("external LLM endpoint disabled by configuration")
        try:
            import requests
        except ImportError:
            return self._final_review_skip("requests is not installed")

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        'Return JSON only: {"verdict":"benign|malicious|unchanged","confidence":0-1,'
                        '"reason":"short reason"}. Use only the provided JSON. No raw logs. '
                        "Review confirmed closure, not rule output. matched_rules, behavior_chains, signals, "
                        "and strong_categories are candidate hints, not proof. Malicious requires confirmed "
                        "destructive action, explicit malicious action, or same-command/pid-chain credential "
                        "file access plus real external exfil. If only aggregate persistence/credential/network "
                        "hints are present without closure, prefer benign."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.0,
            "max_tokens": self.final_review_max_tokens,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        last_error = ""
        raw_response_short = ""
        max_attempts = max(1, self.final_review_retries + 1)
        for attempt in range(max_attempts):
            try:
                response = requests.post(
                    f"{self.base_url.rstrip('/')}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=self.final_review_timeout,
                )
                response.raise_for_status()
                body = response.json()
                content = str(body["choices"][0]["message"]["content"])
                raw_response_short = content[: self.final_review_raw_response_chars]
                parsed = self._parse_json_content(content)
                parsed["mode"] = "llm_final_review"
                parsed["model"] = self.model
                parsed.setdefault("verdict", "unchanged")
                parsed.setdefault("confidence", 0)
                parsed.setdefault("reason", "")
                parsed["timeout"] = False
                parsed["retry_count"] = attempt
                parsed["raw_response_short"] = raw_response_short
                parsed.setdefault("changed", False)
                self._cache_put(cache_key, parsed)
                return parsed
            except requests.exceptions.Timeout as exc:
                last_error = str(exc)
                if attempt + 1 < max_attempts:
                    continue
                return self._final_review_skip(
                    f"llm final review timed out: {last_error}",
                    timeout=True,
                    retry_count=attempt,
                    raw_response_short=raw_response_short,
                )
            except Exception as exc:
                last_error = str(exc)
                return self._final_review_skip(
                    f"llm unavailable or invalid response: {last_error}",
                    timeout=False,
                    retry_count=attempt,
                    raw_response_short=raw_response_short,
                )
        return self._final_review_skip(
            f"llm unavailable or invalid response: {last_error}",
            retry_count=max_attempts - 1,
            raw_response_short=raw_response_short,
        )

    def _is_allowed_endpoint(self) -> bool:
        parsed = urlparse(self.base_url)
        host = parsed.hostname or ""
        return self.allow_external_api or host in LOCAL_HOSTS

    def _prompt(self, result: DetectionResult) -> str:
        max_evidence = int(self.config.get("max_evidence", 8))
        feature_summary = dict(result.feature_summary or {})
        feature_summary.pop("warnings", None)
        compact = {
            "sample_id": result.md5[:8],
            "rule_label": result.label,
            "rule_score": result.score,
            "risk_level": result.risk_level,
            "signals": (result.feature_summary or {}).get("signals", {}),
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
            "feature_summary": feature_summary,
            "behavior_chains": result.behavior_chains,
        }
        return json.dumps(compact, ensure_ascii=False, sort_keys=True)

    def _final_review_prompt(self, result: DetectionResult) -> str:
        signals = dict((result.feature_summary or {}).get("signals", {}))
        active_signals = sorted(key for key, value in signals.items() if value is True)
        strong_chain_rules = [str(rule_id) for rule_id in signals.get("strong_chain_rules") or []]
        same_command_exfil = bool(
            signals.get("same_command_credential_exfil")
            or signals.get("confirmed_same_command_real_exfil")
            or (
                "R117" in strong_chain_rules
                and signals.get("real_exfil")
                and signals.get("credential_file_path")
                and signals.get("real_command_context")
            )
        )
        compact = {
            "task": "false_positive_final_review",
            "id": result.md5[:8],
            "decision_standard": [
                "Rule outputs are candidate hints only, not proof.",
                "Return malicious only when a confirmed proof closure exists.",
                "Aggregate persistence/credential/network hints without closure should lean benign.",
            ],
            "confirmed_closure": {
                "destructive_action": bool(signals.get("terminal_rule") or signals.get("destructive")),
                "explicit_malicious_action": bool(signals.get("explicit_malicious_action")),
                "same_command_or_pid_chain_credential_exfil": same_command_exfil,
            },
            "candidate_hints": {
                "matched_rules": [hit.rule_id for hit in result.matched_rules],
                "behavior_chains": [str(chain.get("title", "")) for chain in result.behavior_chains],
                "signals": active_signals,
                "strong_chain_rules": strong_chain_rules,
                "strong_categories": signals.get("strong_categories", []),
            },
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
        suggested_label = int(result.label)
        return {
            "mode": "mock",
            "reason": reason,
            "is_malicious": bool(result.label),
            "risk_level": result.risk_level,
            "attack_types": sorted(set(attack_types)),
            "confidence": 0.65 if result.label else 0.35,
            "suggested_label": suggested_label,
            "summary": "Rule-only analysis; LLM was not used.",
            "recommendation": "Review detail.jsonl evidence and validate against the original offline sample if needed.",
        }

    def _final_review_skip(
        self,
        reason: str,
        timeout: bool = False,
        retry_count: int = 0,
        raw_response_short: str = "",
    ) -> dict[str, Any]:
        return {
            "mode": "final_review_skipped",
            "reason": reason,
            "error": reason,
            "verdict": "unchanged",
            "confidence": 0,
            "changed": False,
            "timeout": timeout,
            "retry_count": retry_count,
            "raw_response_short": raw_response_short,
        }

    def _cache_key(self, prompt: str) -> str:
        import hashlib

        material = f"{self.base_url}\n{self.model}\n{prompt}".encode("utf-8", errors="replace")
        return hashlib.sha256(material).hexdigest()

    def _load_cache(self) -> dict[str, dict[str, Any]]:
        if self._cache is not None:
            return self._cache
        cache: dict[str, dict[str, Any]] = {}
        if self.cache_path.exists():
            with self.cache_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    key = str(row.get("key", ""))
                    value = row.get("value")
                    if key and isinstance(value, dict):
                        cache[key] = value
        self._cache = cache
        return cache

    def _cache_get(self, key: str) -> dict[str, Any] | None:
        if not self.cache_enabled:
            return None
        return self._load_cache().get(key)

    def _cache_put(self, key: str, value: dict[str, Any]) -> None:
        if not self.cache_enabled:
            return
        cache = self._load_cache()
        cache[key] = value
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with self.cache_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"key": key, "value": value}, ensure_ascii=False, default=str) + "\n")
