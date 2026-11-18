"""Turn Wazuh/Suricata/AMiner/JSON log exports into A1 telemetry databases.

The generated database has the same canonical ``events`` table the agent
already understands.  Original records stay in ``raw_json`` so the adapter's
temporary process/network/file views keep working, while an inferred field
schema is stored in ``ingest_meta`` for transparency.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

EVENT_COLUMNS = (
    "event_id",
    "timestamp",
    "provider",
    "event_code",
    "category",
    "event_type",
    "action",
    "outcome",
    "severity",
    "host_id",
    "user_id",
    "process_entity_id",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "raw_json",
)

_SUPPORTED_SUFFIXES = {".json", ".jsonl", ".ndjson", ".log", ".txt"}
_SCENARIO_SUFFIX_RE = re.compile(r"[-_](?:wazuh|aminer|suricata|eve)$", re.I)
_SURICATA_CATEGORIES = {
    "alert": "intrusion",
    "anomaly": "intrusion",
    "dns": "network",
    "flow": "network",
    "ftp": "network",
    "http": "network",
    "fileinfo": "file",
    "smb": "network",
    "ssh": "network",
    "stats": "metadata",
    "tls": "network",
}


class IngestError(ValueError):
    """Raised when a log file cannot be parsed into telemetry events."""


def scenario_stem(name: str) -> str:
    """Strip provider suffixes ('santos_wazuh.json' -> 'santos') for grouped uploads."""
    stem = Path(name).stem
    return _SCENARIO_SUFFIX_RE.sub("", stem) or stem


def _path_get(record: Any, path: str) -> Any:
    """Read a dotted path, accepting literal dotted keys such as ``event.id``."""
    if not isinstance(record, dict):
        return None
    if path in record:
        return record[path]
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _first(record: Any, paths: Iterable[str], default: Any = None) -> Any:
    for path in paths:
        value = _path_get(record, path)
        if value is not None and value != "":
            return value
    return default


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple, set)):
        return ",".join(_as_text(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, default=str)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _split_host_port(value: Any) -> Tuple[str, Optional[int]]:
    """Split ``host:port`` while leaving bare hosts and IPv6 addresses alone."""
    text = _as_text(value).strip()
    if not text:
        return "", None
    if text.startswith("["):
        end = text.find("]")
        if end > 0:
            host = text[1:end]
            rest = text[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, None
    if text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
    return text, None


def _as_list(value: Any) -> List[str]:
    if isinstance(value, (list, tuple, set)):
        return [_as_text(item) for item in value if _as_text(item)]
    text = _as_text(value)
    return [text] if text else []


def _normalise_timestamp(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, (int, float)):
        seconds = float(value)
        while seconds > 1e12:
            seconds /= 1000.0
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return str(value)

    text = str(value).strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return _normalise_timestamp(float(text))

    candidate = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        parsed = None
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%b %d %H:%M:%S",
            "%Y %b %d %H:%M:%S",
        ):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_records(text: str) -> Optional[List[Dict[str, Any]]]:
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return None

    affected = _path_get(payload, "data.affected_items")
    if isinstance(affected, list):
        return [item for item in affected if isinstance(item, dict)]

    for key in ("events", "alerts", "logs", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return [payload]


def _parse_fast_log(line: str) -> Optional[Dict[str, Any]]:
    pattern = re.compile(
        r"^(?P<date>\d{2}/\d{2}/\d{4})-(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
        r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
        r"(?P<msg>.*?)\s+\[\*\*\]\s+"
        r"\[Classification:\s*(?P<classification>.*?)\]\s+"
        r"\[Priority:\s*(?P<priority>\d+)\]\s+"
        r"\{(?P<proto>[^}]+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)"
    )
    match = pattern.match(line)
    if not match:
        return None

    try:
        stamp = datetime.strptime(
            f"{match.group('date')} {match.group('time')}", "%m/%d/%Y %H:%M:%S.%f"
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        stamp = None

    def split_peer(value: str) -> Tuple[str, int]:
        if value.startswith("[") and "]:" in value:
            host, port = value[1:].split("]:", 1)
            return host, _as_int(port)
        if ":" in value:
            host, port = value.rsplit(":", 1)
            return host, _as_int(port)
        return value, 0

    src_ip, src_port = split_peer(match.group("src"))
    dest_ip, dest_port = split_peer(match.group("dst"))
    return {
        "timestamp": stamp.isoformat().replace("+00:00", "Z") if stamp else "",
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": match.group("proto").strip(),
        "alert": {
            "gid": _as_int(match.group("gid")),
            "signature_id": _as_int(match.group("sid")),
            "rev": _as_int(match.group("rev")),
            "signature": match.group("msg").strip(),
            "category": match.group("classification").strip(),
            "severity": _as_int(match.group("priority")),
        },
        "_raw_text": line,
    }


def _parse_text_line(line: str) -> Dict[str, Any]:
    suricata = _parse_fast_log(line)
    if suricata is not None:
        return suricata

    wazuh = re.match(
        r"^(?P<ts>\d{4} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+?)(?:->(?P<location>[^:]+):)?\s*(?P<message>.*)$",
        line,
    )
    if wazuh:
        return {
            "timestamp": _normalise_timestamp(wazuh.group("ts")),
            "agent": {"name": wazuh.group("host")},
            "location": (wazuh.group("location") or "").strip(),
            "full_log": wazuh.group("message"),
        }

    timestamped = re.match(
        r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<message>.*)$",
        line,
    )
    if timestamped:
        return {
            "timestamp": _normalise_timestamp(timestamped.group("ts")),
            "message": timestamped.group("message"),
        }
    return {"message": line}


def parse_records(data: bytes, filename: str = "", format_hint: str = "auto") -> Tuple[List[Dict[str, Any]], str]:
    """Parse JSON, JSONL/NDJSON (also with a .json suffix), Suricata/AMiner logs, or text."""
    if not data:
        raise IngestError("The uploaded log file is empty.")
    text = data.decode("utf-8-sig", errors="replace").strip()
    if not text:
        raise IngestError("The uploaded log file is empty.")

    hint = (format_hint or "auto").lower()
    json_only = hint == "json"
    if hint in {"auto", "json"}:
        records = _json_records(text)
        if records is not None:
            if not records:
                raise IngestError("No event objects were found in the JSON payload.")
            return records, "json"
        if json_only:
            # Many SIEM exports use a .json suffix for newline-delimited JSON.
            hint = "jsonl"

    records = []
    json_lines = 0
    non_empty = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        non_empty += 1
        if hint in {"auto", "jsonl"}:
            try:
                parsed = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                parsed = None
            if parsed is not None:
                json_lines += 1
                if isinstance(parsed, list):
                    records.extend(item for item in parsed if isinstance(item, dict))
                elif isinstance(parsed, dict):
                    records.append(parsed)
                else:
                    records.append({"message": _as_text(parsed)})
                continue
        if hint == "jsonl":
            message = (
                "The file is not valid JSON or JSONL (each line must be a JSON object)."
                if json_only
                else "Every line must be a JSON object for JSONL input."
            )
            raise IngestError(message)
        records.append(_parse_text_line(line))

    if not records:
        raise IngestError("No events were found in the file.")
    detected = "jsonl" if json_lines == non_empty else "text"
    if hint == "text":
        detected = "text"
    return records, detected


def detect_source(records: List[Dict[str, Any]], filename: str = "") -> str:
    """Score a sample of records as Wazuh, Suricata, AMiner, or generic ECS/text."""
    scores = {"wazuh": 0, "suricata": 0, "aminer": 0, "generic": 0}
    name = (filename or "").lower()
    if "wazuh" in name or "ossec" in name:
        scores["wazuh"] += 2
    if "suricata" in name or "eve" in name:
        scores["suricata"] += 2
    if "aminer" in name:
        scores["aminer"] += 3

    for record in records[:50]:
        if not isinstance(record, dict):
            continue
        if "rule" in record and ("agent" in record or "manager" in record or "full_log" in record):
            scores["wazuh"] += 4
        elif "agent" in record and ("manager" in record or "location" in record):
            scores["wazuh"] += 2
        if "event_type" in record and any(
            key in record for key in ("src_ip", "dest_ip", "flow_id", "proto", "alert")
        ):
            scores["suricata"] += 4
        if isinstance(record.get("alert"), dict) and "signature" in record["alert"]:
            scores["suricata"] += 2
        if isinstance(record.get("AnalysisComponent"), dict) and isinstance(record.get("LogData"), dict):
            scores["aminer"] += 6
        if isinstance(record.get("event"), dict) and ("kind" in record["event"] or "category" in record["event"]):
            scores["generic"] += 1

    if scores["aminer"] > 0 and scores["aminer"] >= max(scores["wazuh"], scores["suricata"]):
        return "aminer"
    if scores["wazuh"] >= scores["suricata"] and scores["wazuh"] > 0:
        return "wazuh"
    if scores["suricata"] > 0:
        return "suricata"
    return "generic"


def _merge_missing(target: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in extra.items():
        if key not in target or target[key] in (None, ""):
            target[key] = value
        elif isinstance(target[key], dict) and isinstance(value, dict):
            target[key] = _merge_missing(dict(target[key]), value)
    return target


def enrich_record(record: Dict[str, Any], source: str, host_map: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Add ECS aliases so the read-only adapter's entity views see the record."""
    if source == "wazuh":
        data = record.get("data") if isinstance(record.get("data"), dict) else {}
        win = data.get("win") if isinstance(data.get("win"), dict) else {}
        eventdata = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
        agent = record.get("agent") if isinstance(record.get("agent"), dict) else {}
        image = _as_text(eventdata.get("image"))
        parent_image = _as_text(eventdata.get("parentImage"))
        host = _as_text(agent.get("name") or agent.get("id"))
        user = _as_text(eventdata.get("user") or eventdata.get("targetUserName") or data.get("dstuser"))
        process: Dict[str, Any] = {}
        if eventdata.get("commandLine"):
            process["command_line"] = _as_text(eventdata.get("commandLine"))
        if image:
            process["executable"] = image
            process["name"] = image.replace("\\", "/").rsplit("/", 1)[-1]
        if eventdata.get("processId") not in (None, ""):
            process["pid"] = _as_int(eventdata.get("processId"))
        if eventdata.get("processGuid"):
            process["entity_id"] = _as_text(eventdata.get("processGuid"))
        parent: Dict[str, Any] = {}
        if eventdata.get("parentProcessId") not in (None, ""):
            parent["pid"] = _as_int(eventdata.get("parentProcessId"))
        if parent_image:
            parent["name"] = parent_image.replace("\\", "/").rsplit("/", 1)[-1]
            parent["executable"] = parent_image
        if parent:
            process["parent"] = parent
        extra: Dict[str, Any] = {"process": process} if process else {}
        if host:
            extra["host"] = {"name": host}
        if user:
            extra["user"] = {"name": user}
        src = data.get("src_ip") or data.get("srcip")
        dst = data.get("dest_ip") or data.get("dstip") or data.get("destip")
        fast = _parse_fast_log(_as_text(record.get("full_log")).strip()) if "[**]" in _as_text(record.get("full_log")) else None
        if fast:
            src = src or fast.get("src_ip")
            dst = dst or fast.get("dest_ip")
        if not dst and data.get("url") and agent.get("ip"):
            dst = agent.get("ip")
        src_host, src_port = _split_host_port(src)
        dst_host, dst_port = _split_host_port(dst)
        if src_host:
            extra["src_ip"] = src_host
        if dst_host:
            extra["dest_ip"] = dst_host
        if src_port is None:
            src_port = _as_int(data.get("src_port"), 0) or (fast.get("src_port") if fast else 0) or None
        if src_port is not None:
            extra["src_port"] = src_port
        if dst_port is None:
            dst_port = _as_int(data.get("dest_port"), 0) or (fast.get("dest_port") if fast else 0) or None
        if dst_port is not None:
            extra["dest_port"] = dst_port
        if data.get("proto"):
            protocol = _as_text(data.get("proto"))
            extra["proto"] = protocol
            extra["protocol"] = protocol
        elif fast and fast.get("proto"):
            extra["proto"] = fast["proto"]
            extra["protocol"] = fast["proto"]
        elif data.get("url"):
            extra["protocol"] = "tcp"
        if data.get("url"):
            extra["url"] = _as_text(data.get("url"))
        return _merge_missing(dict(record), extra)

    if source == "aminer":
        logdata = record.get("LogData") if isinstance(record.get("LogData"), dict) else {}
        aminer = record.get("AMiner") if isinstance(record.get("AMiner"), dict) else {}
        raw_lines = _as_list(logdata.get("RawLogData"))
        raw = " ".join(_as_text(line) for line in raw_lines)
        sensor = _as_text(aminer.get("ID"))
        host = _as_text((host_map or {}).get(sensor)) or sensor
        pid_match = re.search(r"\bpid=(\d+)", raw)
        user_match = re.search(r"\bsudo:\s+(\S[\w.\-]*)\s*:", raw)
        if not user_match:
            user_match = re.search(r"Successful su for (\S+) by", raw)
        if not user_match:
            user_match = re.search(r'\bacct="?([^"\s]+)"?', raw)
        if not user_match:
            user_match = re.search(r"user[=<]\s*<?([\w.\-']+)>?", raw)
        audit = _AUDIT_RE.search(raw)
        command = _decode_hex_cmd(_audit_kv(audit.group("body")).get("cmd", "")) if audit else ""
        process: Dict[str, Any] = {}
        if command:
            process["command_line"] = command
        elif raw:
            process["command_line"] = raw[:500]
        if pid_match:
            process["pid"] = int(pid_match.group(1))
            if host:
                process["entity_id"] = f"proc-{host}-{pid_match.group(1)}"
        extra: Dict[str, Any] = {"process": process} if process else {}
        if host:
            extra["host"] = {"name": host}
            extra["hostname"] = host
            extra["host_id"] = host
        if user_match:
            extra["user"] = {"name": user_match.group(1)}
        return _merge_missing(dict(record), extra) if extra else record

    if source == "suricata":
        fileinfo = record.get("fileinfo") if isinstance(record.get("fileinfo"), dict) else {}
        extra = {}
        if fileinfo:
            file_fields: Dict[str, Any] = {}
            if fileinfo.get("filename"):
                file_fields["name"] = _as_text(fileinfo.get("filename"))
            if fileinfo.get("size") not in (None, ""):
                file_fields["size"] = _as_int(fileinfo.get("size"))
            hashes = {}
            for key in ("md5", "sha1", "sha256"):
                if fileinfo.get(key):
                    hashes[key] = _as_text(fileinfo.get(key))
            if hashes:
                file_fields["hash"] = hashes
            if file_fields:
                extra["file"] = file_fields
        return _merge_missing(dict(record), extra) if extra else record

    return record


_WEAK_AGENT_NAMES = {"wazuh-client", "wazuh-agent", "agent", "localhost", "ubuntu", "debian", "windows"}


def _clean_user(value: Any) -> str:
    """Normalize raw user strings; drop placeholders and full_log-derived garbage."""
    text = _as_text(value).strip().strip("<>").strip()
    if not text or text == "?" or text.startswith("data:") or " " in text:
        return ""
    return text


def _wazuh_host(agent: Dict[str, Any]) -> str:
    name = _as_text(agent.get("name")).strip()
    agent_id = _as_text(agent.get("id")).strip()
    ip = _as_text(agent.get("ip")).strip()
    if name and name.lower() not in _WEAK_AGENT_NAMES:
        return name
    if name and agent_id:
        return f"{name}-{agent_id}"
    return agent_id or ip or name


def _wazuh_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    rule = record.get("rule") if isinstance(record.get("rule"), dict) else {}
    agent = record.get("agent") if isinstance(record.get("agent"), dict) else {}
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    win = data.get("win") if isinstance(data.get("win"), dict) else {}
    eventdata = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
    system = win.get("system") if isinstance(win.get("system"), dict) else {}
    groups = _as_list(rule.get("groups"))
    full_log = _as_text(record.get("full_log")).strip()
    alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
    fast_log = {}
    if not alert and "[**]" in full_log:
        fast_log = _parse_fast_log(full_log) or {}
        alert = fast_log.get("alert") if isinstance(fast_log.get("alert"), dict) else {}
    host = _wazuh_host(agent) or _first(
        data,
        ["hostname", "host"],
        _first(system, ["Computer", "computer"], ""),
    )
    user = _clean_user(
        _first(
            eventdata,
            ["user", "targetUserName", "subjectUserName"],
            _first(data, ["dstuser", "srcuser"], _first(record, ["user", "user_id"], "")),
        )
    )
    if not user and full_log:
        user_match = re.search(r"\buser[=:]\s*<?([\w.\-']+)>?", full_log, re.I)
        if not user_match:
            user_match = re.search(r"\b(?:Accepted|Accepted\s+\w+|for)\s+(?:password\s+for\s+)?([\w.\-']+)\s+from\s", full_log, re.I)
        if not user_match:
            user_match = re.search(r"\b(?:Invalid user|Failed password for)\s+([\w.\-']+)\b", full_log, re.I)
        if user_match:
            user = user_match.group(1)
    rip_match = re.search(r"\brip[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})", full_log) if full_log else None
    rip_ip = rip_match.group(1) if rip_match else ""
    process_guid = _first(eventdata, ["processGuid", "processGuid}"], "")
    process_id = _first(eventdata, ["processId", "process_id"], "")
    process_entity = process_guid or (f"proc-{host}-{process_id}" if host and process_id else "")
    failed = any(word in group.lower() for group in groups for word in ("fail", "denied", "invalid"))
    succeeded = any("success" in group.lower() for group in groups)
    signature = _as_text(alert.get("signature")).strip()
    priority = _as_int(alert.get("severity"), 0)
    severity = {1: 9, 2: 6, 3: 3}.get(priority, 0)
    return {
        "timestamp": _first(record, ["@timestamp", "timestamp", "event.created"]),
        "provider": "Wazuh",
        "event_code": _first(alert, ["signature_id"], _first(rule, ["id"], _first(record, ["id", "event.id"], ""))),
        "category": ",".join(groups) or _first(rule, ["description"], "wazuh"),
        "event_type": groups[0] if groups else "alert",
        "action": signature or _first(rule, ["description"], full_log or "Wazuh event"),
        "outcome": "failure" if failed else ("success" if succeeded else ""),
        "severity": severity or _as_int(rule.get("level"), 0),
        "host_id": _as_text(host),
        "hostname": _as_text(_first(data, ["hostname", "host"], _first(system, ["Computer", "computer"], ""))),
        "user_id": _as_text(user),
        "process_entity_id": _as_text(process_entity),
        "source_ip": _as_text(_first(record, ["src_ip"], _first(data, ["src_ip", "srcip"], rip_ip))),
        "source_port": _as_int(_first(record, ["src_port"], _first(data, ["src_port"], 0)), 0),
        "destination_ip": _as_text(_first(record, ["dest_ip", "destination_ip"], _first(data, ["dest_ip", "dstip", "destip"], ""))),
        "destination_port": _as_int(_first(record, ["dest_port", "destination_port"], _first(data, ["dest_port"], 0)), 0),
        "protocol": _as_text(_first(record, ["protocol", "proto"], _first(data, ["proto"], ""))),
    }


def _suricata_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    alert = record.get("alert") if isinstance(record.get("alert"), dict) else {}
    event_type = _as_text(record.get("event_type")) or "alert"
    priority = _as_int(alert.get("severity"), 0)
    if priority <= 0:
        priority = _as_int(record.get("priority"), 0)
    severity = {1: 9, 2: 6, 3: 3}.get(priority, 0)
    source = record.get("source") if isinstance(record.get("source"), dict) else {}
    destination = record.get("destination") if isinstance(record.get("destination"), dict) else {}
    return {
        "timestamp": _first(record, ["timestamp", "@timestamp", "flow.start"]),
        "provider": "Suricata",
        "event_code": _first(alert, ["signature_id"], _first(record, ["flow_id"], event_type)),
        "category": _SURICATA_CATEGORIES.get(event_type, "network"),
        "event_type": event_type,
        "action": _first(alert, ["signature"], event_type),
        "outcome": _first(alert, ["action"], _first(record, ["flow.state"], "")),
        "severity": severity,
        "host_id": _first(record, ["host", "host_id", "host.name"], ""),
        "hostname": _first(record, ["host.name", "hostname"], ""),
        "user_id": _first(record, ["user", "user_id"], ""),
        "process_entity_id": "",
        "source_ip": _first(record, ["src_ip"], _first(source, ["ip"], "")),
        "source_port": _first(record, ["src_port"], _first(source, ["port"], 0)),
        "destination_ip": _first(record, ["dest_ip"], _first(destination, ["ip"], "")),
        "destination_port": _first(record, ["dest_port"], _first(destination, ["port"], 0)),
        "protocol": _first(record, ["proto", "protocol"], ""),
    }


_AUDIT_RE = re.compile(
    r"type=(?P<atype>\S+)\s+msg=audit\((?P<stamp>[0-9.]+):(?P<serial>\d+)\):\s*(?P<body>.*)", re.S
)
_AUDIT_KV_RE = re.compile(r"(\w+)=('([^']*)'|\"([^\"]*)\"|(\S+))")
_SYSLOG_RE = re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s:\[\]]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)",
    re.S,
)
_APACHE_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+(?P<proto>[^" ]*))?"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
_HEX_CMD_RE = re.compile(r"(?:^|[^0-9a-fA-F])((?:[0-9a-fA-F]{2}){4,})(?:$|[^0-9a-fA-F])")

# Ordered (pattern, severity, category, label); first match wins.
_AMINER_ATTACK_RULES: Tuple[Tuple[re.Pattern, int, str, str], ...] = (
    (re.compile(r"dev/tcp", re.I), 9, "execution", "reverse shell (/dev/tcp)"),
    (re.compile(r"wp_meta=", re.I), 9, "execution", "webshell command (wp_meta)"),
    (re.compile(r"/etc/shadow|/etc/passwd\b|wp_users", re.I), 9, "credential_access", "credential dump"),
    (re.compile(r"USER=root\s*;\s*COMMAND=", re.I), 8, "privilege_escalation", "sudo as root"),
    (re.compile(r"Successful su for", re.I), 7, "privilege_escalation", "su to another account"),
    (re.compile(r"POST\s+/\S*uploads/\S*\.php", re.I), 8, "persistence", "possible webshell upload"),
    (re.compile(r"query\[[A-Z]{1,3}\]\s+\S{40,}", re.I), 7, "exfiltration", "DNS-tunneling pattern"),
    (re.compile(r"type=USER_CMD", re.I), 6, "execution", "sudo command execution"),
    (re.compile(r"Failed password|authentication failure|auth failed", re.I), 4, "authentication", "failed authentication"),
    (re.compile(r"session opened for user|New session \d+ of user", re.I), 4, "authentication", "session opened"),
)


def _decode_hex_cmd(value: str) -> str:
    """Decode audit USER_CMD hex payloads ('636174202F...' -> 'cat /etc/shadow')."""
    if not value:
        return ""
    match = _HEX_CMD_RE.search(value)
    if not match:
        return value
    try:
        decoded = bytes.fromhex(match.group(1)).decode("utf-8", "replace").strip()
    except ValueError:
        return value
    if decoded and decoded.isprintable() and len(decoded) >= 4:
        return decoded
    return value


def _decode_b64_param(value: str) -> str:
    """URL-decoded + base64-decoded query parameter (wp_meta payloads)."""
    if not value:
        return ""
    padded = urllib.parse.unquote(value)
    padded += "=" * (-len(padded) % 4)
    try:
        text = base64.b64decode(padded, validate=False).decode("utf-8", "replace").strip()
    except (ValueError, binascii.Error):
        return ""
    return text if text else ""


def _audit_kv(body: str) -> Dict[str, str]:
    kv: Dict[str, str] = {}
    for match in _AUDIT_KV_RE.finditer(body):
        value = match.group(3) or match.group(4) or match.group(5) or ""
        kv[match.group(1)] = value
        # Nested audit records: msg='op=PAM:... acct="x" exe="y" res=success'
        if "=" in value and ("acct=" in value or value.startswith("op=") or "cmd=" in value):
            for inner in _AUDIT_KV_RE.finditer(value):
                inner_value = inner.group(3) or inner.group(4) or inner.group(5) or ""
                kv.setdefault(inner.group(1), inner_value)
    return kv


def _aminer_host_map(records: List[Dict[str, Any]], record_sources: List[str]) -> Dict[str, str]:
    """Resolve AMiner sensor IDs to real hostnames via embedded ECS (metricbeat) lines."""
    mapping: Dict[str, str] = {}
    ecs_candidates = [record for record, src in zip(records, record_sources) if src == "aminer" and _is_ecs_record(record)]
    for record, rec_source in zip(records, record_sources):
        if rec_source != "aminer" or _is_ecs_record(record):
            continue
        aminer = record.get("AMiner") if isinstance(record.get("AMiner"), dict) else {}
        sensor = _as_text(aminer.get("ID"))
        if not sensor:
            continue
        name = ""
        if ecs_candidates:
            name = _as_text(_first(ecs_candidates[0], ["agent.hostname", "agent.name", "host.name", "host.hostname"]))
        if name:
            mapping.setdefault(sensor, name)
            continue
        logdata = record.get("LogData") if isinstance(record.get("LogData"), dict) else {}
        for line in _as_list(logdata.get("RawLogData")):
            text = _as_text(line).strip()
            if not text.startswith("{"):
                continue
            try:
                parsed = json.loads(text)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                name = _as_text(_first(parsed, ["agent.hostname", "agent.name", "host.name", "host.hostname"]))
                if name:
                    mapping.setdefault(sensor, name)
            break
    return mapping


def _is_ecs_record(record: Dict[str, Any]) -> bool:
    """True for AMiner records whose raw line is an embedded ECS/metricbeat JSON event."""
    if "ecs" in record or "metricset" in record:
        return True
    logdata = record.get("LogData") if isinstance(record.get("LogData"), dict) else {}
    for line in _as_list(logdata.get("RawLogData")):
        text = _as_text(line).strip()
        if text.startswith("{"):
            try:
                parsed = json.loads(text)
            except ValueError:
                return False
            return isinstance(parsed, dict) and ("ecs" in parsed or "metricset" in parsed)
        return False
    return False


def _aminer_fields(record: Dict[str, Any], host_map: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Parse AMiner anomaly records: audit, syslog, apache-access, and ECS-JSON raw lines."""
    component = record.get("AnalysisComponent") if isinstance(record.get("AnalysisComponent"), dict) else {}
    logdata = record.get("LogData") if isinstance(record.get("LogData"), dict) else {}
    aminer = record.get("AMiner") if isinstance(record.get("AMiner"), dict) else {}
    timestamps = _as_list(logdata.get("Timestamps")) or _as_list(logdata.get("DetectionTimestamp"))
    raw_lines = _as_list(logdata.get("RawLogData"))
    raw = " | ".join(_as_text(line) for line in raw_lines)
    sensor = _as_text(aminer.get("ID"))
    host = _as_text((host_map or {}).get(sensor)) or sensor
    training = bool(component.get("TrainingMode"))

    severity = 0 if training else 3
    category = "anomaly"
    rule_label = None
    if not training and not _is_ecs_record(record):
        for pattern, sev, cat, label in _AMINER_ATTACK_RULES:
            if pattern.search(raw):
                severity, category, rule_label = sev, cat, label
                break

    user = ""
    source_ip = ""
    source_port = 0
    destination_ip = ""
    destination_port = 0
    protocol = ""
    process = ""
    action = _as_text(component.get("Message")) or "AMiner anomaly"
    event_kind = "anomaly"

    ecs = None
    for line in raw_lines:
        text = _as_text(line).strip()
        if text.startswith("{"):
            try:
                ecs = json.loads(text)
            except ValueError:
                continue
            break

    if isinstance(ecs, dict):
        event_kind = "ecs"
        host = _as_text(_first(ecs, ["agent.hostname", "agent.name", "host.name"])) or host
        user = _as_text(_first(ecs, ["user.name", "user.id"]))
        source_ip = _as_text(_first(ecs, ["source.ip", "source.address", "client.ip"]))
        destination_ip = _as_text(_first(ecs, ["destination.ip", "destination.address", "server.ip"]))
        destination_port = _as_int(_first(ecs, ["destination.port"]), 0)
        process = _as_text(_first(ecs, ["process.entity_id", "process.pid"]))
        http_method = _as_text(_first(ecs, ["http.request.method"]))
        url = _as_text(_first(ecs, ["url.original", "url.full"]))
        metricset = ecs.get("metricset") if isinstance(ecs.get("metricset"), dict) else {}
        if http_method and url:
            status = _as_text(_first(ecs, ["http.response.status_code"]))
            action = f"{http_method} {url[:400]}" + (f" -> {status}" if status else "")
            protocol = "http"
        elif metricset:
            if not rule_label:
                severity = min(severity, 1)
                category = "metadata"
            action = _as_text(_first(ecs, ["event.action"])) or f"metricbeat {metricset.get('name') or 'metric'} report"
        else:
            action = _as_text(_first(ecs, ["event.action", "message"])) or action
    else:
        audit = _AUDIT_RE.search(raw)
        apache = _APACHE_RE.search(raw)
        syslog = _SYSLOG_RE.search(raw)
        if audit:
            event_kind = "audit"
            kv = _audit_kv(audit.group("body"))
            atype = audit.group("atype")
            op = kv.get("op", "")
            acct = kv.get("acct", "")
            exe = kv.get("exe", "")
            res = kv.get("res", "")
            user = acct
            addr = kv.get("addr", "")
            if addr and addr != "?":
                source_ip = addr
            pid = kv.get("pid", "")
            if host and pid:
                process = f"proc-{host}-{pid}"
            subject = acct or (f"uid={kv.get('uid', '')}" if kv.get("uid") else "unknown")
            head = f"{atype} {op}".strip()
            command = _decode_hex_cmd(kv.get("cmd", ""))
            if command:
                action = f"{head}: {subject} ran {command} (res={res})"
                if not rule_label:
                    severity = max(severity, 6)
                    category = "execution"
            else:
                action = f"{head}: {subject} via {exe or kv.get('terminal', '?')} res={res}"
        elif apache:
            event_kind = "http"
            method = apache.group("method")
            url = apache.group("url")
            status = apache.group("status")
            size = apache.group("size")
            ua = (apache.group("ua") or "").strip()
            source_ip = apache.group("ip")
            action = f"{method} {url[:400]} -> {status} ({size}B)"
            if ua:
                action += f" UA={ua[:100]}"
            wp_match = re.search(r"wp_meta=([^&\s]+)", url)
            if wp_match:
                decoded = _decode_b64_param(wp_match.group(1))
                if decoded:
                    action += f" [wp_meta decoded: {decoded[:300]}]"
            protocol = "http"
        elif syslog:
            event_kind = "syslog"
            prog = syslog.group("prog")
            msg = syslog.group("msg")
            pid = syslog.group("pid")
            if host and pid:
                process = f"proc-{host}-{pid}"
            action = f"{prog}: {msg[:300]}"
            su_match = re.search(r"Successful su for (\S+) by (\S+)", msg)
            open_match = re.search(r"session opened for user (\S+)", msg)
            sudo_match = re.search(r"sudo:\s+(\S[\w.\-]*)\s*:", msg)
            user_match = re.search(r"user[=<]\s*<?([\w.\-']+)>?", msg)
            if su_match:
                user = su_match.group(1)
            elif open_match:
                user = open_match.group(1)
            elif sudo_match:
                user = sudo_match.group(1)
            elif user_match:
                user = user_match.group(1)
            from_ip = re.search(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})", msg)
            if from_ip:
                source_ip = from_ip.group(1)
            prog_lower = prog.lower()
            if prog_lower in {"dnsmasq", "named", "unbound"}:
                if category == "anomaly":
                    category = "network"
                query = re.search(r"query\[([A-Z]{1,3})\]\s+(\S+)\s+from\s+(\S+)", msg)
                if query:
                    protocol = "dns"
            elif prog_lower in {"sshd", "sshd-session"} and category == "anomaly":
                category = "authentication"
            elif prog_lower in {"su", "sudo", "useradd", "groupadd", "passwd"} and category == "anomaly":
                category = "privilege_escalation"
        else:
            user_match = re.search(r'\bacct="?([^"\s]+)"?', raw)
            if user_match:
                user = user_match.group(1)
            if host:
                pid_match = re.search(r"\bpid=(\d+)", raw)
                if pid_match:
                    process = f"proc-{host}-{pid_match.group(1)}"
            action = raw[:400] or action

    return {
        "timestamp": timestamps[0] if timestamps else _first(record, ["@timestamp", "timestamp"]),
        "provider": "AMiner",
        "event_code": _as_text(component.get("AnalysisComponentType")) or "anomaly",
        "category": category,
        "event_type": event_kind,
        "action": action[:600],
        "outcome": "training" if training else "detected",
        "severity": severity,
        "host_id": host,
        "hostname": host,
        "user_id": user,
        "process_entity_id": process,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
    }


def _generic_fields(record: Dict[str, Any], source: str) -> Dict[str, Any]:
    event = record.get("event") if isinstance(record.get("event"), dict) else {}
    host = _first(
        record,
        ["host.name", "host.id", "host_id", "agent.name", "agent.id", "hostname", "computer"],
        "",
    )
    process = _first(record, ["process.entity_id", "process.pid", "process_guid"], "")
    pid = _first(record, ["process.pid", "pid"], "")
    if not process and pid and host:
        process = f"proc-{host}-{pid}"
    category = _first(event, ["category"], _first(record, ["category"], ""))
    event_type = _first(event, ["type"], _first(record, ["event_type"], ""))
    return {
        "timestamp": _first(record, ["@timestamp", "timestamp", "event.created", "time", "TimeCreated"]),
        "provider": _as_text(_first(event, ["provider"], _first(record, ["provider"], source.title()))),
        "event_code": _as_text(_first(event, ["code", "id"], _first(record, ["event_id", "id"], ""))),
        "category": _as_text(category),
        "event_type": _as_text(event_type) or "event",
        "action": _as_text(_first(event, ["action"], _first(record, ["action", "message"], ""))),
        "outcome": _as_text(_first(event, ["outcome"], _first(record, ["outcome"], ""))),
        "severity": _as_int(_first(event, ["severity"], _first(record, ["severity"], 0)), 0),
        "host_id": _as_text(host),
        "hostname": _as_text(host),
        "user_id": _as_text(_first(record, ["user.name", "user.id", "user_id", "username"], "")),
        "process_entity_id": _as_text(process),
    }


def normalize_record(
    record: Dict[str, Any],
    source: str,
    index: int,
    seen_ids: set,
    host_map: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    # hostname column mirrors host_id's friendly name so the db adapter's hosts view
    # resolves agent IPs to real machines.
    """Map one source record onto the canonical events columns."""
    if source == "wazuh":
        fields = _wazuh_fields(record)
    elif source == "suricata":
        fields = _suricata_fields(record)
    elif source == "aminer":
        fields = _aminer_fields(record, host_map)
    else:
        fields = _generic_fields(record, source)

    raw_id = _as_text(_first(record, ["event.id", "event_id", "id"], ""))
    if not raw_id:
        digest = hashlib.sha256(
            (str(index) + json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)).encode("utf-8")
        ).hexdigest()[:16]
        raw_id = f"evt-{digest}"
    event_id = raw_id[:200]
    suffix = 1
    while event_id in seen_ids:
        event_id = f"{raw_id[:190]}-{suffix}"
        suffix += 1
    seen_ids.add(event_id)

    return {
        "event_id": event_id,
        "timestamp": _normalise_timestamp(fields.get("timestamp")),
        "provider": _as_text(fields.get("provider")),
        "event_code": _as_text(fields.get("event_code")),
        "category": _as_text(fields.get("category")),
        "event_type": _as_text(fields.get("event_type")),
        "action": _as_text(fields.get("action")),
        "outcome": _as_text(fields.get("outcome")),
        "severity": _as_int(fields.get("severity"), 0),
        "host_id": _as_text(fields.get("host_id")),
        "user_id": _as_text(fields.get("user_id")),
        "process_entity_id": _as_text(fields.get("process_entity_id")),
        "source_ip": _as_text(fields.get("source_ip")) or None,
        "source_port": _as_int(fields.get("source_port"), 0) or None,
        "destination_ip": _as_text(fields.get("destination_ip")) or None,
        "destination_port": _as_int(fields.get("destination_port"), 0) or None,
        "protocol": _as_text(fields.get("protocol")).lower() or None,
        "hostname": _as_text(fields.get("hostname")) or _as_text(fields.get("host_id")),
        "raw_json": json.dumps(record, ensure_ascii=False, default=str),
    }


def infer_schema(records: List[Dict[str, Any]], max_fields: int = 500) -> Dict[str, Any]:
    """Infer a flattened field/type map from the first records."""
    fields: Dict[str, Dict[str, Any]] = {}
    sample = records[:500]

    def add(path: str, value: Any) -> None:
        info = fields.setdefault(path, {"path": path, "types": set(), "count": 0})
        info["count"] += 1
        if value is None:
            info["types"].add("null")
        elif isinstance(value, bool):
            info["types"].add("boolean")
        elif isinstance(value, (int, float)):
            info["types"].add("number")
        elif isinstance(value, str):
            info["types"].add("string")
        elif isinstance(value, list):
            info["types"].add("array")
        elif isinstance(value, dict):
            info["types"].add("object")

    def walk(value: Any, prefix: str) -> None:
        if len(fields) >= max_fields:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(child, dict):
                    add(path, child)
                    walk(child, path)
                elif isinstance(child, list) and child and isinstance(child[0], dict):
                    add(path, child)
                    walk(child[0], f"{path}[]")
                else:
                    add(path, child)
        elif isinstance(value, list):
            add(prefix, value)

    for record in sample:
        walk(record, "")

    return {
        "sampled_records": len(sample),
        "fields": [
            {"path": info["path"], "types": sorted(info["types"]), "count": info["count"]}
            for info in sorted(fields.values(), key=lambda item: item["path"])
        ],
    }


def _configure_database(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            provider TEXT,
            event_code TEXT,
            category TEXT,
            event_type TEXT,
            action TEXT,
            outcome TEXT,
            severity INTEGER NOT NULL DEFAULT 0,
            host_id TEXT,
            user_id TEXT,
            process_entity_id TEXT,
            source_ip TEXT,
            source_port INTEGER,
            destination_ip TEXT,
            destination_port INTEGER,
            protocol TEXT,
            hostname TEXT,
            raw_json TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX idx_events_timestamp ON events(timestamp)")
    conn.execute("CREATE INDEX idx_events_host ON events(host_id)")
    conn.execute("CREATE INDEX idx_events_user ON events(user_id)")
    conn.execute("CREATE INDEX idx_events_category ON events(category)")
    conn.execute("CREATE INDEX idx_events_code ON events(event_code)")
    conn.execute("CREATE INDEX idx_events_source_ip ON events(source_ip)")
    conn.execute("CREATE INDEX idx_events_destination_ip ON events(destination_ip)")
    conn.execute(
        "CREATE TABLE ingest_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )


def build_database(
    records: List[Dict[str, Any]],
    output_path: Path,
    source: str,
    format_name: str,
    filename: str = "",
    overwrite: bool = False,
    sources: Optional[List[str]] = None,
    per_file: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Write normalized records to a new SQLite database atomically.

    ``sources`` optionally carries a per-record source name (merged databases).
    """
    if not records:
        raise IngestError("No events to write.")
    output_path = Path(output_path)
    if output_path.exists() and not overwrite:
        raise IngestError(f"Output already exists: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    record_sources = list(sources) if sources else [source] * len(records)
    host_map = _aminer_host_map(records, record_sources)
    prepared = [enrich_record(record, record_sources[i], host_map) for i, record in enumerate(records)]
    schema = infer_schema(prepared)
    seen_ids: set = set()
    normalized = [
        normalize_record(record, record_sources[index], index, seen_ids, host_map=host_map)
        for index, record in enumerate(prepared)
    ]

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{output_path.stem}-", suffix=".ingest", dir=str(output_path.parent)
    )
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        conn = sqlite3.connect(str(tmp_path))
        try:
            _configure_database(conn)
            placeholders = ", ".join("?" for _ in EVENT_COLUMNS)
            conn.executemany(
                f"INSERT INTO events ({', '.join(EVENT_COLUMNS)}) VALUES ({placeholders})",
                [tuple(row[column] for column in EVENT_COLUMNS) for row in normalized],
            )
            metadata = {
                "source": source,
                "format": format_name,
                "rows": str(len(normalized)),
                "filename": Path(filename).name if filename else "",
                "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "schema": json.dumps(schema, ensure_ascii=False),
            }
            if per_file:
                metadata["files"] = json.dumps(per_file, ensure_ascii=False)
            conn.executemany(
                "INSERT INTO ingest_meta (key, value) VALUES (?, ?)", metadata.items()
            )
            conn.commit()
        finally:
            conn.close()
        os.replace(tmp_path, output_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    return {
        "path": str(output_path),
        "name": output_path.name,
        "rows": len(normalized),
        "source": source,
        "format": format_name,
        "schema": schema,
    }


def ingest_bytes(
    data: bytes,
    filename: str,
    output_path: Path,
    source: str = "auto",
    format_hint: str = "auto",
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Parse raw log bytes and build a canonical telemetry database."""
    hint = (format_hint or "auto").lower()
    if hint == "auto":
        suffix = Path(filename).suffix.lower()
        if suffix == ".json":
            hint = "json"
        elif suffix in {".jsonl", ".ndjson"}:
            hint = "jsonl"
    records, detected_format = parse_records(data, filename, hint)
    detected_source = detect_source(records, filename)
    chosen_source = detected_source if source in {"", "auto"} else source
    return build_database(
        records,
        output_path,
        source=chosen_source,
        format_name=detected_format,
        filename=filename,
        overwrite=overwrite,
    )


def ingest_merged(
    entries: List[Tuple[bytes, str]],
    output_path: Path,
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Ingest several related log files (e.g. *_wazuh.json + *_aminer.json) into one database."""
    if not entries:
        raise IngestError("No input files were provided.")
    all_records: List[Dict[str, Any]] = []
    sources: List[str] = []
    per_file: List[Dict[str, Any]] = []
    for data, filename in entries:
        if not data:
            raise IngestError(f"The uploaded log file is empty: {filename}")
        records, fmt = parse_records(data, filename, "auto")
        detected = detect_source(records, filename)
        all_records.extend(records)
        sources.extend([detected] * len(records))
        per_file.append({"filename": Path(filename).name, "source": detected, "format": fmt, "rows": len(records)})
    unique_sources = list(dict.fromkeys(entry["source"] for entry in per_file))
    output_path = Path(output_path)
    if output_path.suffix.lower() != ".db":
        output_path = output_path.with_suffix(".db")
    result = build_database(
        all_records,
        output_path,
        source="+".join(unique_sources),
        format_name="merged",
        filename=", ".join(entry["filename"] for entry in per_file),
        overwrite=overwrite,
        sources=sources,
        per_file=per_file,
    )
    result["files"] = per_file
    return result


def ingest_file(
    input_path: Path,
    output_path: Optional[Path] = None,
    source: str = "auto",
    format_hint: str = "auto",
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Ingest a log file from disk into a ``.db`` file."""
    input_path = Path(input_path)
    if not input_path.is_file():
        raise FileNotFoundError(f"Log file not found: {input_path}")
    if input_path.suffix.lower() not in _SUPPORTED_SUFFIXES:
        raise IngestError(
            "Supported inputs: " + ", ".join(sorted(_SUPPORTED_SUFFIXES))
        )
    output_path = Path(output_path) if output_path else input_path.with_suffix(".db")
    return ingest_bytes(
        input_path.read_bytes(),
        filename=input_path.name,
        output_path=output_path,
        source=source,
        format_hint=format_hint,
        overwrite=overwrite,
    )
