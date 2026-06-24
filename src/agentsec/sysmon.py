from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .models import Event
from .utils import compact_json, first_present, flatten_value, redact_text


SYSMON_FILENAMES = {
    "sysmon.log",
    "sysmon.json",
    "sysmon.jsonl",
    "sysmon.csv",
    "sysmon.xml",
    "windows_event.jsonl",
    "winlog.jsonl",
    "eventlog.jsonl",
}

FIELD_ALIASES: dict[str, list[str]] = {
    "event_id": ["EventID", "EventId", "event_id", "eventid", "Id"],
    "utc_time": ["UtcTime", "TimeCreated", "time_created", "timestamp", "TimeGenerated"],
    "computer": ["Computer", "Hostname", "HostName", "host", "hostname"],
    "image": ["Image", "ProcessName", "process_name", "process_path"],
    "command_line": ["CommandLine", "Commandline", "cmdline", "command_line", "cmd"],
    "parent_image": ["ParentImage", "parent_image"],
    "parent_command_line": ["ParentCommandLine", "parent_command_line"],
    "user": ["User", "AccountName", "SubjectUserName", "user"],
    "target_filename": ["TargetFilename", "TargetFileName", "target_filename", "FileName"],
    "source_ip": ["SourceIp", "SourceIP", "source_ip"],
    "destination_ip": ["DestinationIp", "DestinationIP", "dest_ip", "DestinationAddress"],
    "destination_port": ["DestinationPort", "dest_port", "destination_port"],
    "protocol": ["Protocol", "protocol"],
    "query_name": ["QueryName", "query_name"],
    "hashes": ["Hashes", "Hash", "hashes"],
    "integrity_level": ["IntegrityLevel", "integrity_level"],
    "current_directory": ["CurrentDirectory", "current_directory", "cwd"],
    "process_guid": ["ProcessGuid", "ProcessGUID", "process_guid"],
    "process_id": ["ProcessId", "ProcessID", "process_id", "pid"],
    "parent_process_guid": ["ParentProcessGuid", "ParentProcessGUID", "parent_process_guid"],
    "parent_process_id": ["ParentProcessId", "ParentProcessID", "parent_process_id", "ppid"],
}


def find_sysmon_artifacts(root: Path) -> list[Path]:
    found: list[Path] = []
    for file_path in root.rglob("*"):
        if file_path.is_file() and (file_path.name.lower() in SYSMON_FILENAMES or file_path.suffix.lower() == ".evtx"):
            found.append(file_path)
    return sorted(found, key=lambda item: str(item).lower())


def parse_sysmon_file(md5: str, path: Path) -> tuple[list[Event], list[str]]:
    suffix = path.suffix.lower()
    try:
        if suffix == ".jsonl" or path.name.lower().endswith(".log"):
            return _parse_jsonl_or_text(md5, path)
        if suffix == ".json":
            return _parse_json(md5, path)
        if suffix == ".csv":
            return _parse_csv(md5, path)
        if suffix == ".xml":
            return _parse_xml(md5, path)
        if suffix == ".evtx":
            return _parse_evtx(md5, path)
    except Exception as exc:
        return [], [f"{path.name}: sysmon parse failed ({type(exc).__name__}: {exc})"]
    return _parse_jsonl_or_text(md5, path)


def _parse_jsonl_or_text(md5: str, path: Path) -> tuple[list[Event], list[str]]:
    events: list[Event] = []
    warnings: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError:
                events.append(_event_from_record(md5, {"message": text, "line": line_no}, path.name))
                continue
            if isinstance(record, dict):
                record["line"] = line_no
                events.append(_event_from_record(md5, record, path.name))
            else:
                warnings.append(f"{path.name} line {line_no}: non-object json record")
    return events, warnings


def _parse_json(md5: str, path: Path) -> tuple[list[Event], list[str]]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        payload = json.load(handle)
    records: list[Any]
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        for key in ["events", "Events", "records", "Records"]:
            if isinstance(payload.get(key), list):
                records = payload[key]
                break
        else:
            records = [payload]
    else:
        records = []
    return [_event_from_record(md5, record, path.name) for record in records if isinstance(record, dict)], []


def _parse_csv(md5: str, path: Path) -> tuple[list[Event], list[str]]:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        return [_event_from_record(md5, row, path.name) for row in csv.DictReader(handle)], []


def _parse_xml(md5: str, path: Path) -> tuple[list[Event], list[str]]:
    tree = ET.parse(path)
    root = tree.getroot()
    records = [_record_from_xml_event(item) for item in root.iter() if _strip_ns(item.tag).lower() == "event"]
    if not records and root is not None:
        records = [_record_from_xml_event(root)]
    return [_event_from_record(md5, record, path.name) for record in records], []


def _parse_evtx(md5: str, path: Path) -> tuple[list[Event], list[str]]:
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except ImportError:
        return [], [f"{path.name}: python-evtx is not installed; skipped evtx parsing"]

    events: list[Event] = []
    warnings: list[str] = []
    try:
        with Evtx(str(path)) as log:
            for record in log.records():
                try:
                    xml_text = record.xml()
                    root = ET.fromstring(xml_text)
                    events.append(_event_from_record(md5, _record_from_xml_event(root), path.name))
                except Exception as exc:
                    warnings.append(f"{path.name}: evtx record parse failed ({exc})")
    except Exception as exc:
        warnings.append(f"{path.name}: evtx parse failed ({exc})")
    return events, warnings


def _record_from_xml_event(event: ET.Element) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for item in event.iter():
        tag = _strip_ns(item.tag)
        if tag == "EventID" and item.text:
            record["EventID"] = item.text.strip()
        elif tag == "Computer" and item.text:
            record["Computer"] = item.text.strip()
        elif tag == "TimeCreated":
            system_time = item.attrib.get("SystemTime")
            if system_time:
                record["TimeCreated"] = system_time
        elif tag == "Data":
            name = item.attrib.get("Name")
            if name and item.text:
                record[name] = item.text.strip()
    return record


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _event_from_record(md5: str, record: dict[str, Any], source_name: str) -> Event:
    record = _normalize_record(record)
    flat = flatten_value(record)
    fields: dict[str, Any] = {}
    for canonical, aliases in FIELD_ALIASES.items():
        value = _first_flat(flat, aliases)
        if value not in (None, ""):
            fields[canonical] = value
    fields["flattened_keys"] = sorted(flat.keys())[:80]
    if "line" in record:
        fields["line"] = record["line"]

    event_id = first_present(fields, ["event_id"], "sysmon")
    timestamp = first_present(fields, ["utc_time"], None)  # type: ignore[arg-type]
    if len(record) == 1 and "message" in record:
        text = redact_text(record["message"], 1200)
    else:
        text = compact_json(record, 1200)
    return Event(
        md5=md5,
        source="sysmon",
        event_type=str(event_id).lower(),
        timestamp=timestamp,
        text=text,
        fields=fields,
    )


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            name = value.get("Name") or value.get("@Name") or value.get("name")
            data_value = (
                value.get("#text")
                or value.get("text")
                or value.get("Value")
                or value.get("value")
                or value.get("_")
            )
            if name and data_value not in (None, ""):
                normalized[str(name)] = data_value
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(record)
    return normalized


def _first_flat(flat: dict[str, str], aliases: list[str]) -> str | None:
    lower_to_key = {key.lower(): key for key in flat}
    for alias in aliases:
        key = lower_to_key.get(alias.lower())
        if key is not None:
            return flat[key]
    for key, value in flat.items():
        if key.rsplit(".", 1)[-1].lower() in {alias.lower() for alias in aliases}:
            return value
    return None
