"""Input-reflection Stage 1: Alert Prep Node.
Deterministically enriches alerts before triage with regex extraction,
hostname resolution, and UTC time window parsing.
"""
import re
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Tuple, Optional

from a1.db import EndpointDatabase
from a1.config import get_db_path


def _parse_iso_utc(ts_str: str) -> Optional[datetime]:
    """Parse common timestamp formats to a UTC datetime object."""
    clean = ts_str.strip().replace(" ", "T")
    if clean.endswith("Z"):
        clean = clean[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M%z",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(clean, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _format_utc(dt: datetime) -> str:
    """Format datetime as strict ISO 8601 UTC with Z."""
    utc_dt = dt.astimezone(timezone.utc)
    if utc_dt.microsecond:
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_db_timestamp_bounds(db: EndpointDatabase) -> Tuple[datetime, datetime]:
    """Get the observed event timestamp bounds, or a recent fallback if empty."""
    try:
        rows = db.execute_query(
            "SELECT MIN(timestamp) as min_ts, MAX(timestamp) as max_ts FROM events",
            max_rows=1,
        )
        if rows and rows[0].get("min_ts") and rows[0].get("max_ts"):
            start_dt = _parse_iso_utc(str(rows[0]["min_ts"]))
            end_dt = _parse_iso_utc(str(rows[0]["max_ts"]))
            if start_dt and end_dt:
                return start_dt, end_dt
    except Exception:
        pass
    now = datetime.now(timezone.utc)
    return now - timedelta(hours=2), now + timedelta(hours=2)


def extract_regex_entities(alert_text: str) -> Dict[str, Any]:
    """Regex-extract entities: host IDs, IPv4, DOMAIN\\user, UPPERCASE hostnames, CVE IDs."""
    # host IDs like host-[\w-]+
    host_ids = list(dict.fromkeys(re.findall(r"\bhost-[\w-]+\b", alert_text, re.IGNORECASE)))

    # IPv4 addresses
    raw_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", alert_text)
    ipv4s = list(dict.fromkeys(ip for ip in raw_ips if all(0 <= int(x) <= 255 for x in ip.split("."))))

    # DOMAIN\user
    domain_users = list(dict.fromkeys(re.findall(
        r"\b[A-Za-z0-9_.-]+\\[A-Za-z0-9_.-]+\b",
        alert_text
    )))

    # CVE IDs
    cves = list(dict.fromkeys(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", alert_text, re.IGNORECASE)))

    # UPPERCASE hostnames (e.g. WS-OPS-01, SRV-FILE-01, WS-FIN-01, FINANCE-WKSTN-01)
    raw_hosts = re.findall(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\b", alert_text)
    uppercase_hostnames = []
    for h in raw_hosts:
        h_upper = h.upper()
        if h_upper.startswith(("HOST-", "CVE-", "NTLM-")):
            continue
        if h_upper not in uppercase_hostnames:
            uppercase_hostnames.append(h_upper)

    # Process / artifact names
    artifacts = list(dict.fromkeys(re.findall(
        r"\b[\w.-]+\.(?:exe|dll|ps1|bat|vbs|dmp|sys)\b",
        alert_text,
        re.IGNORECASE
    )))

    # User IDs like u-[\w-]+ or user mentions
    user_ids = list(dict.fromkeys(re.findall(r"\bu-[\w-]+\b", alert_text, re.IGNORECASE)))

    return {
        "host_ids": host_ids,
        "ipv4s": ipv4s,
        "domain_users": domain_users,
        "uppercase_hostnames": uppercase_hostnames,
        "cves": cves,
        "artifacts": artifacts,
        "user_ids": user_ids,
    }


def resolve_hostnames(
    hostnames: List[str],
    ipv4s: List[str],
    db: EndpointDatabase
) -> Tuple[Dict[str, str], List[str]]:
    """Resolve every hostname (and IP) to its host ID via the hosts table verbatim."""
    resolved: Dict[str, str] = {}
    unresolved: List[str] = []

    try:
        hosts_rows = db.execute_query("SELECT host_id, host_name, raw_json FROM hosts", max_rows=100)
    except Exception:
        hosts_rows = []

    host_lookup = {}
    ip_lookup = {}
    for r in hosts_rows:
        hid = str(r["host_id"])
        hname = str(r.get("host_name") or "")
        if hname:
            host_lookup[hname.upper()] = hid
        raw_str = r.get("raw_json") or ""
        if raw_str:
            try:
                data = json.loads(raw_str)
                if isinstance(data, dict):
                    if "host.hostname" in data:
                        host_lookup[str(data["host.hostname"]).upper()] = hid
                    if "host.name" in data:
                        host_lookup[str(data["host.name"]).upper()] = hid
                    if "host.ip" in data:
                        ip_lookup[str(data["host.ip"]).strip()] = hid
            except Exception:
                pass

    for hn in hostnames:
        hn_key = hn.upper()
        if hn_key in host_lookup:
            resolved[hn] = host_lookup[hn_key]
        else:
            unresolved.append(hn)

    # Also resolve IPs to host_id if possible
    for ip in ipv4s:
        if ip in ip_lookup:
            resolved[f"IP:{ip}"] = ip_lookup[ip]

    return resolved, unresolved


def parse_alert_time_window(
    alert_text: str,
    db: EndpointDatabase
) -> Tuple[Optional[str], Optional[str], bool]:
    """Parse any time window in the alert to absolute UTC.
    Default to the database's observed event range if absent.
    Returns: (start_time_iso, end_time_iso, is_default)
    """
    # Accept date-only values as well as ISO timestamps.
    ts_matches = re.findall(
        r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?[Z+-]?\S*)?\b",
        alert_text
    )
    parsed_dts: List[Tuple[datetime, bool]] = []
    for m in ts_matches:
        dt = _parse_iso_utc(m)
        if dt:
            parsed_dts.append((dt, len(m) == 10))

    if len(parsed_dts) >= 2:
        parsed_dts.sort(key=lambda item: item[0])
        start_dt = parsed_dts[0][0]
        end_dt, end_is_date_only = parsed_dts[-1]
        if end_is_date_only:
            end_dt += timedelta(days=1) - timedelta(microseconds=1)
        return _format_utc(start_dt), _format_utc(end_dt), False
    elif len(parsed_dts) == 1:
        anchor, is_date_only = parsed_dts[0]
        if is_date_only:
            end_dt = anchor + timedelta(days=1) - timedelta(microseconds=1)
            return _format_utc(anchor), _format_utc(end_dt), False
        # ±2 hours around a timestamp with an explicit time
        start_dt = anchor - timedelta(hours=2)
        end_dt = anchor + timedelta(hours=2)
        return _format_utc(start_dt), _format_utc(end_dt), False

    # Keep the full available evidence scope when the alert has no time anchor.
    start_dt, end_dt = _get_db_timestamp_bounds(db)
    return _format_utc(start_dt), _format_utc(end_dt), True


def alert_prep_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Alert Prep Node: deterministic input reflection before triage."""
    alert_text = state.get("alert_context", "")
    db = EndpointDatabase(get_db_path())

    # 1. Regex entity extraction
    entities = extract_regex_entities(alert_text)

    # 2. Hostname resolution
    resolved_hosts, unresolved_hosts = resolve_hostnames(
        entities["uppercase_hostnames"],
        entities["ipv4s"],
        db
    )

    # 3. Parse time window
    start_time, end_time, is_default_time = parse_alert_time_window(alert_text, db)

    # 4. Record what is missing
    missing: List[str] = []
    if is_default_time:
        missing.append("time_window")
    if not entities["host_ids"] and not resolved_hosts:
        missing.append("host_id")
    if not entities["domain_users"] and not entities["user_ids"]:
        missing.append("user")
    if not entities["artifacts"]:
        missing.append("process_or_file")

    # 5. Deterministic Input-Reflection Checks
    check_host_pass = len(unresolved_hosts) == 0
    check_time_pass = bool(start_time and end_time and start_time < end_time)

    # Print input reflection status
    print("\n[INPUT-REFLECTION: ALERT PREP]")
    if check_host_pass:
        resolved_str = ", ".join(f"{k}->{v}" for k, v in resolved_hosts.items()) if resolved_hosts else "none specified"
        print(f"  [PASS] Hostname resolution: all hostnames resolved ({resolved_str})")
    else:
        print(f"  [FAIL] Hostname resolution: unresolved hostnames: {', '.join(unresolved_hosts)}")

    if check_time_pass:
        note = "(defaulted to database event range)" if is_default_time else "(parsed from alert)"
        print(f"  [PASS] Time window valid: {start_time} -> {end_time} {note}")
    else:
        print(f"  [FAIL] Time window invalid or inverted: {start_time} >= {end_time}")

    # Revision loop: 1 enrichment revision max on failure
    if not (check_host_pass and check_time_pass):
        print("  [*] Performing 1-step alert enrichment revision...")
        if not check_time_pass:
            # Enforce sane fallback
            fallback_start, fallback_end = _get_db_timestamp_bounds(db)
            start_time = _format_utc(fallback_start)
            end_time = _format_utc(fallback_end)
            if "time_window" not in missing:
                missing.append("time_window")

        check_host_pass = len(unresolved_hosts) == 0
        check_time_pass = bool(start_time and end_time and start_time < end_time)
        host_status = "PASS" if check_host_pass else "FAIL (unresolved marked missing)"
        time_status = "PASS" if check_time_pass else "FAIL"
        print(f"  [Revision Result] Hostnames: {host_status} | Time Window: {time_status}")

    # Gather all canonical host IDs (direct + resolved)
    all_host_ids = list(dict.fromkeys(entities["host_ids"] + list(resolved_hosts.values())))

    enriched_alert: Dict[str, Any] = {
        "raw_alert": alert_text,
        "entities": {
            "host_ids": all_host_ids,
            "hostnames": entities["uppercase_hostnames"],
            "resolved_hosts": resolved_hosts,
            "unresolved_hostnames": unresolved_hosts,
            "ipv4s": entities["ipv4s"],
            "domain_users": entities["domain_users"],
            "user_ids": entities["user_ids"],
            "cves": entities["cves"],
            "artifacts": entities["artifacts"],
        },
        "time_window": {
            "start_time": start_time,
            "end_time": end_time,
            "is_default": is_default_time,
        },
        "missing": missing,
        "input_reflection_checks": {
            "hostnames_resolved": check_host_pass,
            "time_window_valid": check_time_pass,
        },
    }

    return {
        "enriched_alert": enriched_alert,
        "input_reflection_status": enriched_alert["input_reflection_checks"],
    }
