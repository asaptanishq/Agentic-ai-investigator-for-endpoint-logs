"""Input-reflection Stage 2: Evidence Packing Node.
Runs after the investigation review gate, before correlation.
Builds a compact structured evidence pack from the telemetry ledger's kept rows.
Deterministic checks verify hypothesis coverage, hostname resolution, and time window sanity.
"""
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Set, Optional, Tuple

def _to_utc_datetime(ts_str: str) -> datetime:
    clean = str(ts_str).strip()
    if clean.endswith("Z"):
        clean = clean[:-1] + "+00:00"
    return datetime.fromisoformat(clean)

def _extract_rows_from_tool_messages(messages: List[Any]) -> Tuple[List[Dict[str, Any]], int]:
    """Parse all ToolMessage contents in the conversation into normalized event records."""
    raw_records: List[Dict[str, Any]] = []
    total_raw_rows = 0

    for msg in messages:
        if getattr(msg, "type", "") != "tool":
            continue
        content = getattr(msg, "content", "")
        if not content:
            continue
        try:
            data = json.loads(content)
        except Exception:
            continue

        if isinstance(data, list):
            total_raw_rows += len(data)
            for item in data:
                if isinstance(item, dict):
                    raw_records.append(item)
        elif isinstance(data, dict):
            # Inspect matches, ancestors, descendants, network_connections, files, registry_events, events
            for key in ("matches", "events", "network_connections", "files", "registry_events", "resolved_entities", "spawned_processes", "parent_process", "process_details", "processes"):
                if key in data and isinstance(data[key], list):
                    total_raw_rows += len(data[key])
                    for item in data[key]:
                        if isinstance(item, dict):
                            enriched_item = dict(item)
                            for context_key in ("process_entity_id", "host_id"):
                                if data.get(context_key) and not enriched_item.get(context_key):
                                    enriched_item[context_key] = data[context_key]
                            raw_records.append(enriched_item)
            for tree_key in ("ancestors", "descendants"):
                if tree_key in data and isinstance(data[tree_key], list):
                    total_raw_rows += len(data[tree_key])
                    for item in data[tree_key]:
                        if isinstance(item, dict):
                            raw_records.append(item)
            if "target_process" in data and isinstance(data["target_process"], dict):
                total_raw_rows += 1
                raw_records.append(data["target_process"])

    # Merge duplicate views of the same event, preferring any available fields.
    records_by_id: Dict[str, Dict[str, Any]] = {}
    for record in raw_records:
        event_id = record.get("event_id") or record.get("child_event_id")
        if not event_id:
            continue
        existing = records_by_id.get(str(event_id))
        if existing is None:
            records_by_id[str(event_id)] = dict(record)
            continue
        for key, value in record.items():
            if key == "details" and isinstance(value, dict):
                existing[key] = {**existing.get(key, {}), **value}
            elif value not in (None, "", [], {}) and existing.get(key) in (None, "", [], {}):
                existing[key] = value

    # Build normalized event records; entity-only rows have no event ID and are not telemetry events.
    kept_events: List[Dict[str, Any]] = []

    for eid, r in records_by_id.items():
        eid = r.get("event_id") or r.get("child_event_id")
        ts = r.get("timestamp") or r.get("child_timestamp") or ""
        hid = r.get("host_id") or ""
        pid = r.get("process_entity_id") or r.get("child_process_entity_id") or ""
        pname = r.get("process_name") or r.get("child_process_name") or ""
        action = r.get("action") or ""
        details = r.get("details") or {}

        # Formulate a one-line summary
        summary_parts = []
        if hid:
            summary_parts.append(f"[{hid}]")
        if pname:
            summary_parts.append(pname)
        elif pid:
            summary_parts.append(f"proc:{pid}")
        if action:
            summary_parts.append(action)
        elif r.get("event_type"):
            summary_parts.append(str(r["event_type"]))

        # Check for files / network / registry / auth details
        if "file_name" in r:
            summary_parts.append(f"file:{r['file_name']}")
        if "destination_ip" in r:
            summary_parts.append(f"dest:{r['destination_ip']}:{r.get('destination_port', '')}")
        if "registry_key" in r or "registry_path" in r:
            reg_target = r.get("registry_path") or r.get("registry_key")
            summary_parts.append(f"reg:{reg_target}")
        if "parent_process_name" in r and r["parent_process_name"]:
            summary_parts.append(f"(parent: {r['parent_process_name']})")
        cmd = r.get("command_line") or r.get("child_command_line") or details.get("command_line")
        if cmd:
            summary_parts.append(f"cmd:{str(cmd)[:70]}")
        for detail_key in (
            "file_name", "file_path", "file_size", "destination_ip",
            "destination_port", "destination_domain", "registry_path",
            "registry_key", "registry_value", "authentication_package",
            "logon_type", "source_ip",
        ):
            value = details.get(detail_key)
            if value not in (None, "", [], {}):
                summary_parts.append(f"{detail_key}:{value}")
        if "user_name" in details:
            summary_parts.append(f"user:{details['user_name']}")

        summary = " ".join(summary_parts) if summary_parts else (str(r)[:100])

        kept_events.append({
            "event_id": eid or f"gen-{len(kept_events)+1}",
            "timestamp": ts,
            "host_id": hid,
            "process_entity_id": pid,
            "process_name": pname,
            "summary": summary,
            "raw": r,
        })

    excluded_count = max(0, total_raw_rows - len(kept_events))
    return kept_events, excluded_count


def _build_chronological_timeline(kept_events: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Sort events chronologically and produce compact (event_id, time, one-line summary) entries."""
    valid_time_events = [e for e in kept_events if e.get("timestamp")]
    no_time_events = [e for e in kept_events if not e.get("timestamp")]

    valid_time_events.sort(key=lambda x: str(x.get("timestamp", "")))
    ordered = valid_time_events + no_time_events

    timeline = []
    for item in ordered:
        event = {
            "event_id": item["event_id"],
            "timestamp": item.get("timestamp") or "N/A",
            "host_id": item.get("host_id") or "N/A",
            "summary": item["summary"],
        }
        raw = item.get("raw", {})
        for key in (
            "action", "event_code", "process_entity_id", "process_name", "parent_process_name",
            "command_line", "file_name", "file_path", "file_size", "destination_ip",
            "destination_port", "destination_domain", "source_ip", "network_direction",
            "registry_path", "registry_key", "registry_value", "details",
        ):
            if key in raw and raw[key] not in (None, "", [], {}):
                event[key] = raw[key]
        timeline.append(event)
    return timeline


def _filter_events_to_time_window(
    kept_events: List[Dict[str, Any]],
    start_time: Optional[str],
    end_time: Optional[str],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    """Keep timestamped evidence within scope; preserve unknown-time rows for review."""
    if not start_time or not end_time:
        return kept_events, [], []

    start_dt = _to_utc_datetime(start_time)
    end_dt = _to_utc_datetime(end_time)
    in_scope = []
    out_of_scope_ids = []
    missing_time_ids = []
    for event in kept_events:
        timestamp = event.get("timestamp")
        if not timestamp:
            missing_time_ids.append(event["event_id"])
            in_scope.append(event)
            continue
        try:
            event_dt = _to_utc_datetime(str(timestamp))
        except ValueError:
            missing_time_ids.append(event["event_id"])
            in_scope.append(event)
            continue
        if start_dt <= event_dt <= end_dt:
            in_scope.append(event)
        else:
            out_of_scope_ids.append(event["event_id"])
    return in_scope, out_of_scope_ids, missing_time_ids


def _build_entity_set(kept_events: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Extract unique sets of hosts, users, processes, files, IPs, registry keys."""
    hosts = set()
    users = set()
    processes = set()
    files = set()
    ips = set()
    reg_keys = set()

    for e in kept_events:
        r = e.get("raw", {})
        if e.get("host_id"):
            hosts.add(e["host_id"])
        if r.get("user_id"):
            users.add(r["user_id"])
        if e.get("process_entity_id"):
            processes.add(e["process_entity_id"])
        if e.get("process_name"):
            processes.add(e["process_name"])
        if r.get("parent_process_name"):
            processes.add(r["parent_process_name"])
        if r.get("parent_process_entity_id"):
            processes.add(r["parent_process_entity_id"])
        if r.get("file_name"):
            files.add(r["file_name"])
        if r.get("sha256"):
            files.add(r["sha256"])
        if r.get("destination_ip"):
            ips.add(r["destination_ip"])
        if r.get("source_ip"):
            ips.add(r["source_ip"])
        if r.get("registry_path"):
            reg_keys.add(r["registry_path"])
        if r.get("registry_key"):
            reg_keys.add(r["registry_key"])
        if r.get("registry_path") and r.get("registry_key"):
            reg_keys.add(f"{r['registry_path']}\\{r['registry_key']}")

        details = r.get("details", {})
        if isinstance(details, dict):
            if details.get("parent_process_entity_id"):
                processes.add(details["parent_process_entity_id"])
            if "destination_ip" in details:
                ips.add(details["destination_ip"])
            if "file_name" in details:
                files.add(details["file_name"])
            if "registry_path" in details:
                reg_keys.add(details["registry_path"])
            if "user_name" in details:
                users.add(details["user_name"])

    return {
        "hosts": sorted(hosts),
        "users": sorted(users),
        "processes": sorted(processes),
        "files": sorted(files),
        "network_ips": sorted(ips),
        "registry_keys": sorted(reg_keys),
    }


def _map_hypotheses_evidence(
    hypotheses: List[str],
    kept_events: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """Map each hypothesis to supporting/refuting event IDs or mark 'no evidence'."""
    mapping: Dict[str, Dict[str, Any]] = {}

    for h in hypotheses:
        h_lower = h.lower()
        supporting: List[str] = []
        refuting: List[str] = []

        keywords = [w.strip() for w in re.findall(r"\b[a-zA-Z0-9_-]{3,}\b", h_lower)]
        # Filter out common stop words
        stop_words = {"the", "and", "for", "with", "from", "that", "this", "were", "was", "activity", "suspicious", "determine", "whether", "represents"}
        keywords = [k for k in keywords if k not in stop_words]

        for e in kept_events:
            summary_lower = e["summary"].lower()
            raw_str = json.dumps(e.get("raw", {})).lower()
            text = f"{summary_lower} {raw_str}"

            # Check matches
            matches = any(k in text for k in keywords)
            if matches:
                if "benign" in h_lower and ("malicious" in text or "exploit" in text):
                    refuting.append(e["event_id"])
                else:
                    supporting.append(e["event_id"])

        supporting = list(dict.fromkeys(supporting))
        refuting = list(dict.fromkeys(refuting))

        candidate_ids = list(dict.fromkeys(supporting + refuting))

        mapping[h] = {
            "status": "candidate evidence found" if candidate_ids else "no candidate evidence",
            "candidate_event_ids": candidate_ids,
            "event_count": len(candidate_ids),
            "match_basis": "literal keyword overlap only; not a support/refutation judgment",
        }

    return mapping


def evidence_packing_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Evidence Packing Node: builds structured pack and runs input reflection checks."""
    messages = state.get("messages", [])
    hypotheses = state.get("hypotheses", [])
    if not hypotheses:
        hypotheses = ["Investigate suspicious endpoint activity"]

    enriched_alert = state.get("enriched_alert", {})
    time_window = enriched_alert.get("time_window", {})
    start_time = time_window.get("start_time")
    end_time = time_window.get("end_time")

    # 1. Parse kept rows & excluded count
    kept_events, excluded_count = _extract_rows_from_tool_messages(messages)
    kept_events, out_of_scope_event_ids, missing_time_event_ids = _filter_events_to_time_window(
        kept_events, start_time, end_time
    )
    excluded_count += len(out_of_scope_event_ids)

    # 2. Build chronological timeline
    timeline = _build_chronological_timeline(kept_events)

    # 3. Build entity set
    entity_set = _build_entity_set(kept_events)

    # 4. Map hypotheses to evidence
    hypo_map = _map_hypotheses_evidence(hypotheses, kept_events)

    # 5. Deterministic Input-Reflection Checks
    # Check 1: Hostnames resolved
    check_host_pass = True
    if enriched_alert.get("entities", {}).get("unresolved_hostnames"):
        check_host_pass = False

    # Check 2: Time window present and sane (start < end)
    check_time_pass = bool(start_time and end_time and start_time < end_time)

    # Literal keyword matches are candidates, not semantic adjudications.
    check_hypo_pass = bool(hypo_map) and all(
        info["event_count"] >= 1 for info in hypo_map.values()
    )
    check_scope_pass = not out_of_scope_event_ids

    print("\n[INPUT-REFLECTION: EVIDENCE PACKING]")
    if check_host_pass:
        print("  [PASS] Hostname resolution: all hostnames resolved to host_id")
    else:
        print(f"  [FAIL] Hostname resolution: {enriched_alert.get('entities', {}).get('unresolved_hostnames')}")

    if check_time_pass:
        print(f"  [PASS] Time window sane: {start_time} < {end_time}")
    else:
        print(f"  [FAIL] Time window sane: {start_time} vs {end_time}")

    hypo_summary_strs = [
        f"H{i+1}: {info['status']} ({info['event_count']} candidate event(s))"
        for i, (h, info) in enumerate(hypo_map.items())
    ]
    matched_hypotheses = sum(info["event_count"] > 0 for info in hypo_map.values())
    print(
        f"  [INFO] Heuristic keyword overlap: {matched_hypotheses}/{len(hypo_map)} hypotheses; "
        f"not semantic support/refutation ({'; '.join(hypo_summary_strs)})"
    )
    if check_scope_pass:
        print("  [PASS] Time scope: no out-of-window events included")
    else:
        print(f"  [WARN] Time scope: excluded {len(out_of_scope_event_ids)} out-of-window event(s)")

    evidence_pack: Dict[str, Any] = {
        "timeline": timeline,
        "hypotheses_evidence": hypo_map,
        "entity_set": entity_set,
        "excluded_row_count": excluded_count,
        "excluded_out_of_scope_event_ids": out_of_scope_event_ids,
        "missing_timestamp_event_ids": missing_time_event_ids,
        "total_kept_events": len(kept_events),
        "time_window": {
            "start_time": start_time,
            "end_time": end_time,
        },
        "input_reflection_checks": {
            "hostnames_resolved": check_host_pass,
            "time_window_sane": check_time_pass,
            "hypotheses_covered": check_hypo_pass,
            "time_scope_respected": check_scope_pass,
        },
    }

    return {
        "evidence_pack": evidence_pack,
        "input_reflection_status": evidence_pack["input_reflection_checks"],
    }
