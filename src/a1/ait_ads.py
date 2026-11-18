"""AIT-ADS adapter: turn AMiner alert logs into benchmarkable SQLite cases.

The AIT-ADS download (Zenodo 8263181) ships per-scenario Wazuh and AMiner
JSONL files plus a separate ``labels.csv``.  Wazuh windows contain hundreds of
thousands of low-signal web-400 alerts, so this adapter uses the AMiner files:
they are already anomaly-filtered, much smaller, and preserve raw audit/web/DNS
log lines needed for evidence tracing.
"""

import csv
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Attack-step names used by the public AIT-ADS labels.csv.
AIT_STEP_ANCHORS = {
    "network_scans": (["scan", "nmap", "recon", "port scan"], False),
    "service_scans": (["service scan", "scan", "port", "recon"], False),
    "wpscan": (["wpscan", "wordpress", "wp-login", "cms"], False),
    "dirb": (["dirb", "directory", "web content", "brute"], False),
    "webshell": (["webshell", "web shell", "shell", "upload"], True),
    "cracking": (["crack", "password", "brute", "hydra", "failed login"], False),
    "reverse_shell": (["reverse shell", "reverse_shell", "callback", "c2"], True),
    "privilege_escalation": (["privilege", "sudo", "root", "escalat"], True),
    "service_stop": (["service stop", "systemctl", "stop service"], False),
    "dnsteal": (["dnsteal", "dns", "exfil", "tunnel"], True),
}


def _parse_ts(value) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load_ait_labels(labels_csv: str, scenario: Optional[str] = None) -> dict:
    """Read labels.csv into ``{scenario: [(step, start, end), ...]}``."""
    path = Path(labels_csv)
    if not path.exists():
        raise FileNotFoundError(f"AIT-ADS labels not found: {path}")
    labels: dict = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            name = (row.get("scenario") or "").strip()
            if not name or (scenario and name != scenario):
                continue
            start = _parse_ts(row.get("start"))
            end = _parse_ts(row.get("end"))
            if start is None or end is None:
                continue
            labels.setdefault(name, []).append((row.get("attack", "attack"), start, end))
    return labels


def select_attack_cluster(windows: list) -> tuple:
    """Pick the first attack day; ignore later service-stop/exfil stragglers.

    AIT-ADS labels sometimes place cleanup/exfiltration on the next day.  One
    case should stay within a tractable window, so keep steps starting within
    six hours of the first step and take their min-start/max-end envelope.
    """
    ordered = sorted((item for item in windows if item[0] not in ("service_stop", "dnsteal")), key=lambda item: item[1])
    if not ordered:
        ordered = sorted(windows, key=lambda item: item[1])
    first_start = ordered[0][1]
    # Keep the first attack day. Labels can carry cleanup/exfil timestamps on a
    # different day (even earlier in the file), which would otherwise become the
    # anchor and hide the actual intrusion.
    cluster = [item for item in windows if first_start <= item[1] <= first_start + 6 * 3600]
    return first_start, max(item[2] for item in cluster), cluster


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _extract_user(raw: str) -> str:
    for pattern in (r'\bacct="([^"]+)"', r"\buser=([^\s,]+)", r"\busername=([^\s,]+)"):
        match = re.search(pattern, raw)
        if match and match.group(1) not in ("?", "(unknown)"):
            return match.group(1)
    return ""


def _extract_host(raw: str, fallback: str) -> str:
    match = re.search(r"\bhostname=([^\s,]+)", raw)
    if match and match.group(1) not in ("?", "(none)"):
        return match.group(1)
    match = re.search(r"\baddr=([0-9.]+)", raw)
    if match:
        return match.group(1)
    return fallback


def _extract_process(raw: str) -> tuple:
    exe = re.search(r'\bexe="?([^"\s]+)"?', raw)
    comm = re.search(r'\bcomm="?([^"\s]+)"?', raw)
    pid = re.search(r"\bpid=(\d+)", raw)
    name = ""
    if comm:
        name = comm.group(1).rsplit("/", 1)[-1]
    elif exe:
        name = exe.group(1).rsplit("/", 1)[-1]
    return name, (exe.group(1) if exe else ""), (int(pid.group(1)) if pid else 0)


def _record_fields(record: dict, seq: int, scenario: str):
    log_data = record.get("LogData") or {}
    raw_lines = log_data.get("RawLogData") or []
    raw = "\n".join(str(line) for line in raw_lines)
    timestamps = log_data.get("Timestamps") or []
    epoch = _parse_ts(timestamps[0]) if timestamps else None
    if epoch is None:
        return None
    component = record.get("AnalysisComponent") or {}
    resources = " ".join(str(r).lower() for r in (log_data.get("LogResources") or []))
    if "apache" in resources or "access" in resources:
        category = "web"
    elif "dns" in resources:
        category = "network"
    elif "audit" in resources:
        category = "process"
    else:
        category = "alert"

    aminer_id = str((record.get("AMiner") or {}).get("ID") or "")
    host = _extract_host(raw, aminer_id or "unknown")
    user = _extract_user(raw)
    process_name, executable, pid = _extract_process(raw)
    url_match = re.search(r'"(?:GET|POST|HEAD|PUT|DELETE)\s+([^\s"]+)', raw)
    url = url_match.group(1) if url_match else ""
    src_ip = aminer_id if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", aminer_id) else ""
    dst_ip = ""
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw):
        if ip != src_ip:
            dst_ip = ip
            break

    slug = re.sub(r"[^a-z0-9]+", "-", scenario.lower()).strip("-")
    return {
        "event_id": f"evt-ait-{slug}-{seq:05d}",
        "timestamp": _iso(epoch),
        "host_id": host,
        "user_id": user,
        "provider": "AMiner",
        "event_code": str(component.get("AnalysisComponentIdentifier") or ""),
        "event_type": str(component.get("AnalysisComponentName") or "AMiner anomaly"),
        "action": str(component.get("Message") or ""),
        "category": category,
        "severity": 3,
        "message": raw[:2000],
        "raw_json": json.dumps(record, ensure_ascii=False),
        "process_entity_id": f"proc-ait-{slug}-{seq:05d}",
        "process_name": process_name,
        "command_line": raw,
        "pid": pid,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "file_path": executable,
        "url": url,
    }


SCHEMA = """
CREATE TABLE events (
    event_id TEXT PRIMARY KEY, timestamp TEXT, host_id TEXT, user_id TEXT,
    provider TEXT, event_code TEXT, event_type TEXT, action TEXT, category TEXT,
    severity INTEGER, message TEXT, raw_json TEXT, process_entity_id TEXT,
    process_name TEXT, command_line TEXT, pid INTEGER, src_ip TEXT, dst_ip TEXT,
    file_path TEXT, url TEXT
);
CREATE INDEX idx_events_ts ON events(timestamp);
CREATE INDEX idx_events_category ON events(category);
CREATE INDEX idx_events_host ON events(host_id);
CREATE INDEX idx_events_src ON events(src_ip);
"""


def build_ait_database(
    aminer_path: str,
    scenario: str,
    windows: list,
    db_path: str,
    rebuild: bool = False,
) -> dict:
    """Filter AMiner alerts to the attack window and write a canonical DB."""
    target = Path(db_path)
    if target.exists() and not rebuild:
        return {"db_path": str(target), "events": _count_events(target), "cached": True}

    start, end, cluster = select_attack_cluster(windows)
    lo, hi = start - 300, end + 300
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(".tmp.db")
    if temp.exists():
        temp.unlink()

    conn = sqlite3.connect(temp)
    conn.executescript(SCHEMA)
    seq = 0
    with open(aminer_path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            timestamps = (record.get("LogData") or {}).get("Timestamps") or []
            epoch = _parse_ts(timestamps[0]) if timestamps else None
            if epoch is None or not (lo <= epoch <= hi):
                continue
            row = _record_fields(record, seq, scenario)
            if not row:
                continue
            seq += 1
            columns = list(row)
            conn.execute(
                f"INSERT OR REPLACE INTO events ({','.join(columns)}) VALUES ({','.join('?'*len(columns))})",
                [row[c] for c in columns],
            )
    conn.commit()
    conn.close()
    if target.exists():
        target.unlink()
    temp.replace(target)
    return {
        "db_path": str(target),
        "events": seq,
        "cached": False,
        "window_start": _iso(start),
        "window_end": _iso(end),
        "steps": [step for step, _, _ in cluster],
    }


def _count_events(db_path: Path) -> int:
    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        count = conn.execute("SELECT count(*) FROM events").fetchone()[0]
        conn.close()
        return int(count)
    except Exception:
        return 0


def _query_rows(db_path: str, sql: str, params=()) -> list:
    conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def _top_values(rows: list, column: str, limit: int = 3) -> list:
    counts: dict = {}
    for row in rows:
        value = str(row.get(column) or "").strip()
        if value and value not in ("unknown", "?", "(none)"):
            counts[value] = counts.get(value, 0) + 1
    return sorted(counts, key=counts.get, reverse=True)[:limit]


def build_ait_case(
    ait_dir: str,
    labels_csv: str,
    scenario: str,
    out_dir: str = "benchmark_ait",
    rebuild: bool = False,
) -> dict:
    labels = load_ait_labels(labels_csv, scenario)
    if not labels:
        raise ValueError(f"No AIT-ADS labels for scenario '{scenario}' in {labels_csv}")
    windows = labels[scenario]
    start, end, cluster = select_attack_cluster(windows)
    db_path = Path(out_dir) / f"ait_{scenario}.db"
    build = build_ait_database(
        str(Path(ait_dir) / f"{scenario}_aminer.json"), scenario, windows, str(db_path), rebuild
    )
    rows = _query_rows(str(db_path), "SELECT host_id, src_ip, url, process_name FROM events")
    hosts = _top_values(rows, "host_id", 3)
    src_ips = _top_values(rows, "src_ip", 2)
    urls = _top_values(rows, "url", 2)
    key_iocs = [value for value in src_ips + urls if value][:3]
    if not key_iocs:
        key_iocs = hosts[:1]

    step_checks = []
    for step, _, _ in cluster:
        anchors, critical = AIT_STEP_ANCHORS.get(step, ([step.replace("_", " ")], False))
        step_checks.append({
            "id": step,
            "description": step.replace("_", " "),
            "any_of": list(anchors),
            "weight": 2 if critical else 1,
            "critical": critical,
        })

    case_id = f"AIT-{re.sub(r'[^A-Za-z0-9]+', '-', scenario).upper()}"
    prompt = (
        f"Investigate AMiner anomaly alerts in the {scenario} environment between "
        f"{_iso(start)} and {_iso(end)} UTC. The alert stream covers web access, "
        f"host audit, and DNS telemetry. Determine whether the activity is a "
        f"coordinated multi-stage intrusion, and support the verdict with specific "
        f"event IDs, hosts, and raw-log details."
    )
    return {
        "case_id": case_id,
        "prompt": prompt,
        "case_label": "malicious",
        "verdict_boundary": "confirmed_malicious",
        "confidence": "high",
        "evidence_basis": [step.replace("_", " ") for step, _, _ in cluster],
        "evidence_checks": step_checks,
        "expected_hosts": hosts,
        "key_iocs": key_iocs,
        "distractors": [],
        "db_path": str(db_path.resolve()),
        "database": str(db_path.resolve()),
        "events": build.get("events", 0),
        "window_start": _iso(start),
        "window_end": _iso(end),
        "split": "ait",
    }


def build_ait_cases(
    ait_dir: str,
    labels_csv: str,
    scenarios: Optional[list] = None,
    out_dir: str = "benchmark_ait",
    rebuild: bool = False,
) -> list:
    available = load_ait_labels(labels_csv)
    chosen = scenarios or sorted(available)
    cases = []
    for scenario in chosen:
        if scenario not in available:
            print(f"[!] AIT-ADS scenario '{scenario}' not in {labels_csv} -- skipping.")
            continue
        aminer = Path(ait_dir) / f"{scenario}_aminer.json"
        if not aminer.exists():
            print(f"[!] Missing AMiner file: {aminer} -- skipping.")
            continue
        print(f"[*] Preparing AIT-ADS case: {scenario}")
        try:
            cases.append(build_ait_case(ait_dir, labels_csv, scenario, out_dir, rebuild))
        except Exception as exc:
            print(f"[!] Could not build AIT-ADS case '{scenario}': {exc}")
    return cases
