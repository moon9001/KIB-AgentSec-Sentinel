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
    "session_id",
    "conversation_id",
    "message_id",
    "turn_id",
    "timestamp",
    "cwd",
    "cmd",
    "tool",
    "action",
    "args",
    "arguments",
    "input",
    "message",
    "content",
    "role",
    "function_call",
    "tool_calls",
    "name",
    "params",
    "result",
    "error",
]

SESSION_ACTION_KEYS = {"tool", "action", "cmd", "command", "function_call", "tool_call", "tool_calls", "name", "arguments", "args", "params", "input"}


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
            events.extend(session_action_events(md5, record, line_no, timestamp))
    return events, warnings


def session_action_events(md5: str, record: dict[str, Any], line_no: int, timestamp: str | None) -> list[Event]:
    events: list[Event] = []
    base_ids = {
        "line": line_no,
        "session_id": first_present(record, ["session_id", "conversation_id", "id"], ""),
        "message_id": first_present(record, ["message_id", "turn_id"], ""),
        "turn_id": first_present(record, ["turn_id", "message_id"], ""),
    }
    group_id = "|".join(str(value) for value in [base_ids["session_id"], base_ids["message_id"], line_no] if value not in (None, ""))

    for index, call in enumerate(iter_session_action_objects(record)):
        flat = flatten_value(call)
        fields: dict[str, Any] = {
            **base_ids,
            "action_index": index,
            "action_group": group_id,
            "flattened_keys": sorted(flat.keys())[:80],
            "flattened_text": " ".join(flat.values())[:1200],
        }
        fields.update(session_action_fields(call))
        event_type = first_present(fields, ["tool", "action", "cmd", "command", "name", "function_call"], "tool_call")
        text = compact_json({"tool_call": call}, 1200)
        events.append(
            Event(
                md5=md5,
                source="session",
                event_type=redact_text(event_type, 80) or "tool_call",
                timestamp=timestamp,
                text=text,
                fields=fields,
            )
        )
    return events


def iter_session_action_objects(record: dict[str, Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []

    def add_action(value: Any) -> None:
        if isinstance(value, dict):
            actions.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    actions.append(item)

    for key in ["tool_calls", "tool_call", "function_call", "actions", "commands"]:
        if key in record:
            add_action(record.get(key))

    if any(key in record for key in ["tool", "action", "cmd", "command"]) and not any(action is record for action in actions):
        actions.append(record)

    nested: list[dict[str, Any]] = []
    for action in actions:
        for key in ["function", "function_call", "tool", "args", "arguments", "params", "input"]:
            value = action.get(key)
            if isinstance(value, dict) and any(candidate in value for candidate in SESSION_ACTION_KEYS):
                nested.append(value)
    actions.extend(nested)

    unique: list[dict[str, Any]] = []
    seen: set[int] = set()
    for action in actions:
        marker = id(action)
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(action)
    return unique


def session_action_fields(action: dict[str, Any]) -> dict[str, Any]:
    flat = flatten_value(action)
    fields: dict[str, Any] = {}
    for key in ["id", "type", "tool", "action", "cmd", "command", "name", "args", "arguments", "params", "input", "function_call"]:
        if key in action:
            fields[key] = action[key]
    if isinstance(action.get("function"), dict):
        function = action["function"]
        fields.setdefault("function_call", function.get("name"))
        fields.setdefault("name", function.get("name"))
        if "arguments" in function:
            fields.setdefault("arguments", function.get("arguments"))
    if isinstance(action.get("function_call"), dict):
        function_call = action["function_call"]
        fields.setdefault("function_call", function_call.get("name"))
        fields.setdefault("name", function_call.get("name"))
        if "arguments" in function_call:
            fields.setdefault("arguments", function_call.get("arguments"))
    if "cmd" not in fields and "command" in fields:
        fields["cmd"] = fields["command"]
    if "params" not in fields:
        params_text = " ".join(value for key, value in flat.items() if any(marker in key.lower() for marker in ["arg", "param", "input", "command", "cmd"]))
        if params_text:
            fields["params"] = params_text
    return fields


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
