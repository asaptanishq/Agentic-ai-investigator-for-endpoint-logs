"""Unit tests for Input-Reflection Nodes (Alert Prep & Evidence Packing),
Report Recovery, and Data Retrieval Enhancements.
"""
import json

import pytest
from pathlib import Path
from langchain_core.messages import ToolMessage, AIMessage, HumanMessage

from a1.nodes.alert_prep_node import (
    extract_regex_entities,
    resolve_hostnames,
    parse_alert_time_window,
    alert_prep_node,
)
from a1.nodes.evidence_packing_node import (
    _extract_rows_from_tool_messages,
    _build_chronological_timeline,
    _build_entity_set,
    _map_hypotheses_evidence,
    evidence_packing_node,
)
from a1.nodes.report_node import IncidentVerdict, _format_bullet_points, _format_text_as_bullets
from a1.llm import set_active_llm, get_active_llm_info
from a1.tools.timeline import search_timeline
from a1.db import EndpointDatabase


def test_alert_prep_regex_extraction():
    alert = (
        "Investigate suspicious activity on WS-FIN-01 (host-001) involving user CORP\\jdoe "
        "connecting to 10.10.1.10 and running powershell.exe to exploit CVE-2024-38077."
    )
    entities = extract_regex_entities(alert)
    assert "host-001" in entities["host_ids"]
    assert "10.10.1.10" in entities["ipv4s"]
    assert "CORP\\jdoe" in entities["domain_users"]
    assert "WS-FIN-01" in entities["uppercase_hostnames"]
    assert "CVE-2024-38077" in entities["cves"]
    assert "powershell.exe" in entities["artifacts"]


def test_alert_prep_hostname_resolution():
    """Resolution is exercised against hostnames present in the active database."""
    db = EndpointDatabase()
    rows = db.execute_query(
        "SELECT host_id, host_name FROM hosts "
        "WHERE host_name IS NOT NULL AND host_name <> '' LIMIT 1",
        max_rows=1,
    )
    if not rows:
        pytest.skip("Active telemetry database records no hostnames to resolve")

    host = rows[0]
    resolved, unresolved = resolve_hostnames([host["host_name"], "WS-NOT-IN-TELEMETRY"], [], db)

    assert resolved[host["host_name"]] == host["host_id"]
    assert "WS-NOT-IN-TELEMETRY" in unresolved


def test_alert_prep_time_window_fallback():
    db = EndpointDatabase()
    start_t, end_t, is_default = parse_alert_time_window("No time specified in this alert", db)
    assert is_default is True
    assert start_t < end_t


def test_default_time_window_covers_full_database_range():
    database_path = (
        Path(__file__).resolve().parents[1]
        / "endpoint_security_dataset_expanded_corrected"
        / "attack_data_exfiltration.db"
    )
    db = EndpointDatabase(database_path)
    bounds = db.execute_query(
        "SELECT MIN(timestamp) as min_ts, MAX(timestamp) as max_ts FROM events",
        max_rows=1,
    )[0]

    start_t, end_t, is_default = parse_alert_time_window(
        "Investigate suspicious activity on WS-DEV-02", db
    )

    assert is_default is True
    assert start_t == bounds["min_ts"]
    assert end_t == bounds["max_ts"]


def test_date_only_alert_is_full_day_and_not_a_hostname():
    alert = "Investigate suspicious activity on WS-OPS-01 on 2026-09-10"

    entities = extract_regex_entities(alert)
    start_t, end_t, is_default = parse_alert_time_window(alert, None)

    assert entities["uppercase_hostnames"] == ["WS-OPS-01"]
    assert (start_t, end_t, is_default) == (
        "2026-09-10T00:00:00Z",
        "2026-09-10T23:59:59.999999Z",
        False,
    )


def test_lateral_movement_database_attack_chain_is_inside_date_scope():
    database_path = (
        Path(__file__).resolve().parents[1]
        / "endpoint_security_dataset_expanded_corrected"
        / "attack_lateral_movement.db"
    )
    db = EndpointDatabase(database_path)
    alert = "Investigate suspicious activity on WS-OPS-01 on 2026-09-10"
    start_t, end_t, is_default = parse_alert_time_window(alert, db)

    rows = db.execute_query(
        "SELECT event_id FROM events WHERE timestamp >= ? AND timestamp <= ? "
        "AND event_id BETWEEN ? AND ? ORDER BY timestamp",
        (start_t, end_t, "evt-atkA-0000027", "evt-atkA-0000040"),
        max_rows=20,
    )

    assert is_default is False
    assert len(rows) == 14
    assert rows[0]["event_id"] == "evt-atkA-0000027"
    assert rows[-1]["event_id"] == "evt-atkA-0000040"


def test_alert_prep_node_execution():
    """The node resolves a hostname that exists in the active database."""
    db = EndpointDatabase()
    rows = db.execute_query(
        "SELECT host_id, host_name FROM hosts "
        "WHERE host_name IS NOT NULL AND host_name <> '' LIMIT 1",
        max_rows=1,
    )
    if not rows:
        pytest.skip("Active telemetry database records no hostnames to resolve")

    host_name = rows[0]["host_name"]
    expected_host_id = rows[0]["host_id"]

    state = {
        "alert_context": (
            f"Suspicious execution on {host_name} at 2026-09-10T08:00:00Z by user CORP\\admin"
        )
    }
    result = alert_prep_node(state)
    assert "enriched_alert" in result
    enriched = result["enriched_alert"]
    assert expected_host_id in enriched["entities"]["host_ids"]
    assert enriched["input_reflection_checks"]["hostnames_resolved"] is True
    assert enriched["input_reflection_checks"]["time_window_valid"] is True


def test_evidence_packing_from_tool_messages():
    tool_data = [
        {
            "event_id": "evt-001",
            "timestamp": "2026-09-01T08:05:00Z",
            "host_id": "host-001",
            "process_entity_id": "proc-001",
            "process_name": "powershell.exe",
            "action": "process_started",
            "event_code": "1",
            "details": {
                "command_line": "powershell.exe -enc ...",
                "parent_process_entity_id": "proc-parent",
            }
        },
        {
            "event_id": "evt-002",
            "timestamp": "2026-09-01T08:10:00Z",
            "host_id": "host-001",
            "process_entity_id": "proc-001",
            "action": "network_connection",
            "destination_ip": "198.51.100.5",
            "details": {}
        }
    ]
    messages = [
        HumanMessage(content="Investigate"),
        ToolMessage(content=json.dumps(tool_data), tool_call_id="call_1", name="search_timeline")
    ]
    kept, excluded = _extract_rows_from_tool_messages(messages)
    assert len(kept) == 2
    assert kept[0]["event_id"] == "evt-001"
    assert kept[1]["event_id"] == "evt-002"

    timeline = _build_chronological_timeline(kept)
    assert len(timeline) == 2
    assert timeline[0]["event_id"] == "evt-001"
    assert timeline[0]["event_code"] == "1"

    entities = _build_entity_set(kept)
    assert "host-001" in entities["hosts"]
    assert "proc-001" in entities["processes"]
    assert "proc-parent" in entities["processes"]
    assert "198.51.100.5" in entities["network_ips"]


def test_evidence_packing_merges_duplicate_events_and_skips_entity_rows():
    tool_data = [
        {"event_id": "evt-001", "action": "process_started", "timestamp": ""},
        {"event_id": "evt-001", "timestamp": "2026-09-01T08:05:00Z", "process_name": "powershell.exe"},
        {"process_entity_id": "proc-no-event", "process_name": "orphan.exe"},
    ]
    messages = [ToolMessage(content=json.dumps(tool_data), tool_call_id="c1", name="find_process_associations")]

    kept, excluded = _extract_rows_from_tool_messages(messages)

    assert len(kept) == 1
    assert kept[0]["event_id"] == "evt-001"
    assert kept[0]["timestamp"] == "2026-09-01T08:05:00Z"
    assert excluded == 2


def test_evidence_packing_inherits_process_context_for_association_rows():
    association_data = {
        "process_entity_id": "proc-001",
        "network_connections": [{"event_id": "evt-net", "destination_ip": "203.0.113.10"}],
        "events": [{"event_id": "evt-net", "action": "network_connection"}],
    }
    messages = [
        ToolMessage(content=json.dumps(association_data), tool_call_id="c1", name="find_process_associations")
    ]

    kept, _ = _extract_rows_from_tool_messages(messages)

    assert len(kept) == 1
    assert kept[0]["process_entity_id"] == "proc-001"
    assert kept[0]["raw"]["action"] == "network_connection"


def test_evidence_packing_node_hypothesis_coverage():
    tool_data = [
        {
            "event_id": "evt-001",
            "timestamp": "2026-09-01T08:05:00Z",
            "host_id": "host-001",
            "process_name": "powershell.exe",
            "action": "process_started",
        }
    ]
    state = {
        "messages": [
            ToolMessage(content=json.dumps(tool_data), tool_call_id="c1", name="search_timeline")
        ],
        "hypotheses": [
            "Powershell process was spawned maliciously",
            "Routine scheduled synchronization"
        ],
        "enriched_alert": {
            "time_window": {"start_time": "2026-09-01T07:00:00Z", "end_time": "2026-09-01T10:00:00Z"},
            "entities": {"unresolved_hostnames": []}
        }
    }
    result = evidence_packing_node(state)
    assert "evidence_pack" in result
    pack = result["evidence_pack"]
    assert pack["input_reflection_checks"]["hypotheses_covered"] is False
    # Literal token matches are candidates, not semantic support/refutation.
    h_cov = pack["hypotheses_evidence"]
    assert any(info["status"] == "no candidate evidence" for info in h_cov.values())


def test_evidence_packing_excludes_out_of_window_events():
    tool_data = [
        {"event_id": "evt-in", "timestamp": "2026-09-10T09:13:00Z", "host_id": "host-a01"},
        {"event_id": "evt-out", "timestamp": "2026-09-11T00:30:00Z", "host_id": "host-a01"},
    ]
    state = {
        "messages": [ToolMessage(content=json.dumps(tool_data), tool_call_id="c1", name="search_timeline")],
        "hypotheses": ["Investigate suspicious endpoint activity"],
        "enriched_alert": {
            "time_window": {"start_time": "2026-09-10T00:00:00Z", "end_time": "2026-09-10T23:59:59.999999Z"},
            "entities": {"unresolved_hostnames": []},
        },
    }

    pack = evidence_packing_node(state)["evidence_pack"]

    assert [item["event_id"] for item in pack["timeline"]] == ["evt-in"]
    assert pack["excluded_out_of_scope_event_ids"] == ["evt-out"]


def test_incident_verdict_partial_json_recovery():
    # Exactly replicates the failure mode observed in Terminal 21204:
    partial_data = {
        "verdict": "malicious",
        "verdict_boundary": "confirmed_malicious",
        "investigation_reasoning": "Detected procdump accessing lsass followed by lateral movement and UpdaterSvc2 persistence.",
        "evidence_basis": ["evt-atkA-0000028 procdump accessed lsass", "evt-atkA-0000037 service created"]
    }
    # IncidentVerdict should succeed and not raise validation errors for missing fields
    verdict_obj = IncidentVerdict(**partial_data)
    assert verdict_obj.verdict == "malicious"
    assert verdict_obj.verdict_boundary == "confirmed_malicious"
    assert verdict_obj.confidence == 0.8
    assert len(verdict_obj.evidence_basis) == 2


def test_bullet_formatting_helpers():
    text = "Paragraph 1 with reasoning.\nParagraph 2 with more details."
    formatted = _format_text_as_bullets(text)
    assert formatted.startswith("- Paragraph 1")
    assert "\n- Paragraph 2" in formatted

    bullets = _format_bullet_points(["evt-01 matched", "evt-02 confirmed"])
    assert bullets == "- evt-01 matched\n- evt-02 confirmed"


def test_llm_selection():
    set_active_llm(provider="ollama", model="llama3.1")
    info = get_active_llm_info()
    assert info["provider"] == "ollama"
    assert info["model"] == "llama3.1"

    set_active_llm(provider="openai", model="gpt-4o")
    info = get_active_llm_info()
    assert info["provider"] == "openai"
    assert info["model"] == "gpt-4o"


def test_timeline_keyword_and_multi_category():
    """Keyword and multi-category search run against discovered telemetry."""
    db = EndpointDatabase()
    rows = db.execute_query(
        "SELECT host_id, action FROM events "
        "WHERE host_id IS NOT NULL AND host_id <> '' "
        "AND action IS NOT NULL AND action <> '' LIMIT 1",
        max_rows=1,
    )
    if not rows:
        pytest.skip("Active telemetry database contains no events to search")

    host_id = rows[0]["host_id"]
    keyword = rows[0]["action"]

    # Test keyword search
    res = json.loads(search_timeline.invoke({
        "host_id": host_id,
        "keyword": keyword,
        "limit": 10
    }))
    assert isinstance(res, list)
    assert len(res) > 0

    # Test multi-category search
    res2 = json.loads(search_timeline.invoke({
        "host_id": host_id,
        "category": "process,network",
        "limit": 10
    }))
    assert isinstance(res2, list)
    assert len(res2) > 0
