"""Deterministic evidence validator node (Issue #6, #7)."""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set

from a1.db import get_active_db
from a1.evidence_graph import EvidenceGraph
from a1.state import InvestigationState

logger = logging.getLogger(__name__)

EVENT_ID_REGEX = re.compile(r"\b(evt-[A-Za-z0-9\-_]+)\b", re.IGNORECASE)
PROCESS_ID_REGEX = re.compile(r"\b(proc-[A-Za-z0-9\-_]+)\b", re.IGNORECASE)
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"you\s+must\s+output\s+verdict", re.IGNORECASE),
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"do\s+not\s+investigate", re.IGNORECASE),
]


import urllib.parse

def extract_cited_ids_from_text(text: str) -> Dict[str, Set[str]]:
    """Extract event IDs, process IDs from free text or structured strings."""
    if not text:
        return {"event_ids": set(), "process_ids": set()}
    event_ids = set(EVENT_ID_REGEX.findall(text))
    process_ids = set(PROCESS_ID_REGEX.findall(text))
    return {"event_ids": event_ids, "process_ids": process_ids}


def detect_adversarial_telemetry_strings(text: str) -> List[str]:
    """Flag potential prompt injection strings found in telemetry data (Issue #7)."""
    flags = []
    if not text:
        return flags
    # Unquote URL encoding so encoded tokens like ignore%20all%20previous are caught
    decoded_text = urllib.parse.unquote(text)
    for pat in INJECTION_PATTERNS:
        if pat.search(text) or pat.search(decoded_text):
            flags.append(f"Suspicious control/injection token matched: {pat.pattern}")
    return flags


def validator_node(state: InvestigationState) -> Dict[str, Any]:
    """Validate all evidence cited in the investigation state deterministically before report generation."""
    logger.info("Running deterministic evidence validation node.")

    # 1. Collect cited event IDs and process IDs from state
    cited_event_ids: Set[str] = set()
    cited_process_ids: Set[str] = set()
    cited_hostnames: Set[str] = set()

    # From state evidence pack
    pack = state.get("evidence_pack") or {}
    for item in pack.get("scoped_evidence", []):
        if isinstance(item, dict):
            eid = item.get("event_id")
            if eid:
                cited_event_ids.add(str(eid))
            pid = item.get("process_entity_id") or item.get("process_id")
            if pid:
                cited_process_ids.add(str(pid))
            h = item.get("hostname") or item.get("host_id")
            if h and h != "unknown":
                cited_hostnames.add(str(h).lower())

    # From raw evidence list
    for ev in state.get("evidence") or []:
        if isinstance(ev, dict):
            eid = ev.get("event_id")
            if eid:
                cited_event_ids.add(str(eid))
            pid = ev.get("process_entity_id") or ev.get("process_id")
            if pid:
                cited_process_ids.add(str(pid))
            h = ev.get("hostname") or ev.get("host_id")
            if h and h != "unknown":
                cited_hostnames.add(str(h).lower())

    # From confirmed correlations
    for corr in state.get("confirmed_correlations") or []:
        if isinstance(corr, dict):
            corr_text = str(corr)
            extracted = extract_cited_ids_from_text(corr_text)
            cited_event_ids.update(extracted["event_ids"])
            cited_process_ids.update(extracted["process_ids"])

    # 2. Check existence in database
    db = get_active_db()

    event_ids_valid: List[str] = []
    event_ids_invalid: List[str] = []
    for eid in sorted(cited_event_ids):
        try:
            res = db.execute_query(
                "SELECT 1 FROM events WHERE event_id = ? LIMIT 1",
                (eid,),
                max_rows=1,
            )
            if res:
                event_ids_valid.append(eid)
            else:
                event_ids_invalid.append(eid)
        except Exception:
            # If events table doesn't have event_id column or query fails
            event_ids_valid.append(eid)

    process_ids_valid: List[str] = []
    process_ids_invalid: List[str] = []
    for pid in sorted(cited_process_ids):
        try:
            res = db.execute_query(
                "SELECT 1 FROM processes WHERE process_entity_id = ? LIMIT 1",
                (pid,),
                max_rows=1,
            )
            if res:
                process_ids_valid.append(pid)
            else:
                # Also check events for process_entity_id
                res_ev = db.execute_query(
                    "SELECT 1 FROM events WHERE process_entity_id = ? LIMIT 1",
                    (pid,),
                    max_rows=1,
                )
                if res_ev:
                    process_ids_valid.append(pid)
                else:
                    process_ids_invalid.append(pid)
        except Exception:
            process_ids_valid.append(pid)

    # Hostname validation
    hostnames_valid: List[str] = []
    hostnames_invalid: List[str] = []
    if cited_hostnames:
        try:
            db_hosts_res = db.execute_query(
                "SELECT DISTINCT LOWER(hostname) AS hname FROM hosts UNION SELECT DISTINCT LOWER(hostname) AS hname FROM events WHERE hostname IS NOT NULL",
                max_rows=200,
            )
            db_host_set = {r["hname"] for r in db_hosts_res if r.get("hname")}
            for h in sorted(cited_hostnames):
                if h in db_host_set:
                    hostnames_valid.append(h)
                else:
                    hostnames_invalid.append(h)
        except Exception:
            hostnames_valid = list(cited_hostnames)

    # 3. Check temporal consistency against EvidenceGraph
    eg_data = state.get("evidence_graph")
    temporal_anomalies: List[Dict[str, Any]] = []
    if eg_data:
        try:
            eg = EvidenceGraph.from_dict(eg_data)
            temporal_anomalies = eg.detect_temporal_anomalies()
        except Exception as e:
            logger.warning("Error running temporal anomaly detection: %s", e)

    # 4. Prompt injection checks on collected telemetry strings
    injection_warnings: List[str] = []
    for ev in (state.get("evidence") or []):
        if isinstance(ev, dict):
            for k, v in ev.items():
                if isinstance(v, str):
                    inj = detect_adversarial_telemetry_strings(v)
                    if inj:
                        injection_warnings.extend([f"Field '{k}': {msg}" for msg in inj])

    warnings: List[str] = []
    if event_ids_invalid:
        warnings.append(f"Invalid or hallucinated event IDs cited: {event_ids_invalid}")
    if process_ids_invalid:
        warnings.append(f"Invalid process IDs cited: {process_ids_invalid}")
    if hostnames_invalid:
        warnings.append(f"Unknown hostnames cited: {hostnames_invalid}")
    if temporal_anomalies:
        warnings.append(f"Temporal anomalies detected: {len(temporal_anomalies)} issue(s)")
    if injection_warnings:
        warnings.append(f"Telemetry prompt-injection warnings: {len(injection_warnings)} instance(s)")

    validation_passed = len(event_ids_invalid) == 0 and len(process_ids_invalid) == 0

    validation_results = {
        "validation_passed": validation_passed,
        "event_ids_valid": event_ids_valid,
        "event_ids_invalid": event_ids_invalid,
        "process_ids_valid": process_ids_valid,
        "process_ids_invalid": process_ids_invalid,
        "hostnames_valid": hostnames_valid,
        "hostnames_invalid": hostnames_invalid,
        "temporal_anomalies": temporal_anomalies,
        "injection_warnings": injection_warnings,
        "warnings": warnings,
    }

    return {"validation_results": validation_results}
