from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any


SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{12,}"),
    re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|access[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[^'\"\s,;]{6,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]


def redact_text(text: Any, max_chars: int = 280) -> str:
    value = str(text) if text is not None else ""
    value = value.replace("\x00", " ")
    value = re.sub(r"\s+", " ", value).strip()
    for pattern in SECRET_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    if len(value) > max_chars:
        return value[: max_chars - 3] + "..."
    return value


def flatten_value(value: Any, prefix: str = "", limit: int = 250) -> dict[str, str]:
    out: dict[str, str] = {}

    def walk(item: Any, key: str) -> None:
        if len(out) >= limit:
            return
        if isinstance(item, Mapping):
            for child_key, child_value in item.items():
                next_key = f"{key}.{child_key}" if key else str(child_key)
                walk(child_value, next_key)
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for index, child_value in enumerate(item[:limit] if isinstance(item, list) else item):
                next_key = f"{key}.{index}" if key else str(index)
                walk(child_value, next_key)
                if len(out) >= limit:
                    break
        else:
            out[key or "value"] = redact_text(item, 500)

    walk(value, prefix)
    return out


def compact_json(value: Any, max_chars: int = 900) -> str:
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except TypeError:
        text = str(value)
    return redact_text(text, max_chars)


def contains_any(text: str, needles: list[str]) -> bool:
    return any(contains_keyword(text, needle) for needle in needles)


def contains_keyword(text: str, needle: str) -> bool:
    lower = text.lower()
    target = needle.lower()
    if not target:
        return False
    if re.fullmatch(r"[a-z0-9_]+", target) and len(target) <= 4:
        return re.search(rf"(?<![a-z0-9_]){re.escape(target)}(?![a-z0-9_])", lower) is not None
    return target in lower


def first_present(mapping: Mapping[str, Any], keys: list[str], default: str = "") -> str:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def deep_merge(base: dict[str, Any], override: Mapping[str, Any] | None) -> dict[str, Any]:
    merged = dict(base)
    if not override:
        return merged
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = deep_merge(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged
