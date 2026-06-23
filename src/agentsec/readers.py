from __future__ import annotations

import json
import os
import re
import shlex
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Event
from .sysmon import find_sysmon_artifacts, parse_sysmon_file
from .utils import compact_json, first_present, flatten_value, redact_text


SESSION_FIELDS = [
    "type",
    "version",
    "id",
    "timestamp",
    "cwd",
    "cmd",
    "tool",
    "action",
    "args",
    "message",
    "content",
    "role",
    "function_call",
    "name",
    "params",
    "result",
    "error",
]


@dataclass
class ParsedSample:
    md5: str
    root: Path
    events: list[Event] = field(default_factory=list)
    audit_stats: dict[str, int] = field(default_factory=dict)
    artifact_paths: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def discover_sample_zips(input_path: str | Path) -> list[Path]:
    path = Path(input_path)
    if path.is_file():
        if path.suffix.lower() != ".zip":
            raise ValueError(f"Input file is not a zip: {path}")
        return [path]
    if not path.is_dir():
        raise FileNotFoundError(f"Input path does not exist: {path}")
    return sorted(path.rglob("*.zip"), key=lambda item: item.name.lower())


def safe_extract_zip(zip_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_root = dest_dir.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            target = (dest_dir / member.filename).resolve()
            if target != dest_root and os.path.commonpath([str(dest_root), str(target)]) != str(dest_root):
                raise ValueError(f"Unsafe zip member path: {member.filename}")
        archive.extractall(dest_dir)


def find_artifacts(root: Path) -> dict[str, Path]:
    wanted = {
        "session": "session.jsonl",
        "audit": "audit.log",
        "pcap": "network.pcap",
    }
    found: dict[str, Path] = {}
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        lower = file_path.name.lower()
        for key, filename in wanted.items():
            if lower == filename and key not in found:
                found[key] = file_path
    return found


def parse_extracted_sample(md5: str, root: Path) -> ParsedSample:
    parsed = ParsedSample(md5=md5, root=root)
    artifacts = find_artifacts(root)
    parsed.artifact_paths = {key: str(value) for key, value in artifacts.items()}

    if "session" in artifacts:
        events, warnings = parse_session_jsonl(md5, artifacts["session"])
        parsed.events.extend(events)
        parsed.warnings.extend(warnings)
    else:
        parsed.warnings.append("missing session.jsonl")

    if "audit" in artifacts:
        events, stats, warnings = parse_audit_log(md5, artifacts["audit"])
        parsed.events.extend(events)
        parsed.audit_stats = stats
        parsed.warnings.extend(warnings)
    else:
        parsed.warnings.append("missing audit.log")

    if "pcap" not in artifacts:
        parsed.warnings.append("missing network.pcap")

    for sysmon_path in find_sysmon_artifacts(root):
        events, warnings = parse_sysmon_file(md5, sysmon_path)
        parsed.events.extend(events)
        parsed.warnings.extend(warnings)

    return parsed


def parse_session_jsonl(md5: str, path: Path) -> tuple[list[Event], list[str]]:
    events: list[Event] = []
    warnings: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                warnings.append(f"session.jsonl line {line_no}: bad json ({exc.msg})")
                continue
            if not isinstance(record, dict):
                warnings.append(f"session.jsonl line {line_no}: non-object record")
                continue
            fields = {key: record.get(key) for key in SESSION_FIELDS if key in record}
            flat = flatten_value(record)
            fields["line"] = line_no
            fields["flattened_keys"] = sorted(flat.keys())[:80]
            timestamp = first_present(record, ["timestamp", "time", "created_at"], None)  # type: ignore[arg-type]
            event_type = first_present(record, ["type", "tool", "action", "name", "cmd"], "session")
            text = compact_json(record, 1200)
            events.append(
                Event(
                    md5=md5,
                    source="session",
                    event_type=redact_text(event_type, 80) or "session",
                    timestamp=timestamp,
                    text=text,
                    fields=fields,
                )
            )
    return events, warnings


def parse_audit_log(md5: str, path: Path) -> tuple[list[Event], dict[str, int], list[str]]:
    events: list[Event] = []
    warnings: list[str] = []
    counts: Counter[str] = Counter()
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                fields = parse_audit_fields(stripped)
            except ValueError as exc:
                warnings.append(f"audit.log line {line_no}: parse error ({exc})")
                continue
            audit_type = str(fields.get("type", "AUDIT")).upper()
            counts[audit_type.lower() + "_count"] += 1
            fields["line"] = line_no
            text = audit_event_text(fields)
            events.append(
                Event(
                    md5=md5,
                    source="audit",
                    event_type=audit_type.lower(),
                    timestamp=str(fields.get("audit_time") or "") or None,
                    text=text,
                    fields=fields,
                )
            )
    stats = {
        "execve_count": counts.get("execve_count", 0),
        "syscall_count": counts.get("syscall_count", 0),
        "path_count": counts.get("path_count", 0),
        "cwd_count": counts.get("cwd_count", 0),
        "proctitle_count": counts.get("proctitle_count", 0),
    }
    stats.update(dict(counts))
    return events, stats, warnings


def parse_audit_fields(line: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    type_match = re.search(r"\btype=([A-Z0-9_]+)", line)
    if type_match:
        fields["type"] = type_match.group(1)
    msg_match = re.search(r"msg=audit\(([^:)]+):([^)]+)\)", line)
    if msg_match:
        fields["audit_time"] = msg_match.group(1)
        fields["audit_serial"] = msg_match.group(2)

    try:
        parts = shlex.split(line, posix=True)
    except ValueError:
        parts = line.split()

    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        if key == "msg":
            continue
        value = decode_audit_value(key, value.strip())
        fields[key] = value
    return fields


def decode_audit_value(key: str, value: str) -> str:
    value = value.strip('"')
    if key == "proctitle" and re.fullmatch(r"[0-9A-Fa-f]+", value or ""):
        try:
            raw = bytes.fromhex(value)
            return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except ValueError:
            return value
    return value


def audit_event_text(fields: dict[str, Any]) -> str:
    preferred = [
        "type",
        "exe",
        "comm",
        "cwd",
        "proctitle",
        "a0",
        "a1",
        "a2",
        "a3",
        "name",
        "uid",
        "auid",
        "ses",
        "pid",
        "ppid",
        "syscall",
        "success",
        "key",
    ]
    text_parts = [f"{key}={fields[key]}" for key in preferred if key in fields]
    if not text_parts:
        text_parts = [f"{key}={value}" for key, value in fields.items()]
    return redact_text(" ".join(text_parts), 1200)
