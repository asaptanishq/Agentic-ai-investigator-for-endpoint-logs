import json

import pytest

from a1.tools import (
    get_database_schema,
    query_telemetry,
    find_process_relationships,
    trace_process_tree,
    find_process_associations,
    search_timeline,
    get_entity_context,
)


def _query(sql: str) -> list:
    """Run a read-only query through the tool and return the parsed rows."""
    return json.loads(query_telemetry.invoke({"sql_query": sql}))


def _first(sql: str):
    """Return the first matching row, or ``None`` when the query returns nothing.

    Tests use this to discover fixtures in whichever telemetry database is
    active, rather than hard-coding identifiers from a dataset that may not
    ship with the repository.
    """
    rows = _query(sql)
    return rows[0] if rows else None


_PARENT_CHILD_PAIR_SQL = (
    "SELECT child.host_id AS host_id, child.process_name AS child_name, "
    "parent.process_name AS parent_name "
    "FROM processes AS child "
    "JOIN processes AS parent ON parent.process_entity_id = child.parent_entity_id "
    "WHERE child.process_name IS NOT NULL AND child.process_name <> '' "
    "AND parent.process_name IS NOT NULL AND parent.process_name <> '' LIMIT 1"
)


def test_tool_get_database_schema():
    res = get_database_schema.invoke({})
    data = json.loads(res)
    assert "events" in data
    assert "processes" in data

def test_tool_query_telemetry():
    res = query_telemetry.invoke({"sql_query": "SELECT host_id, host_name FROM hosts LIMIT 2"})
    data = json.loads(res)
    assert isinstance(data, list)
    assert len(data) > 0
    assert "host_id" in data[0]

def test_tool_trace_process_tree():
    # First find an existing process entity ID
    query_res = json.loads(query_telemetry.invoke({"sql_query": "SELECT process_entity_id FROM processes LIMIT 1"}))
    pid_entity = query_res[0]["process_entity_id"]
    
    tree_res = trace_process_tree.invoke({"process_entity_id": pid_entity, "direction": "both"})
    data = json.loads(tree_res)
    assert "target_process" in data
    assert data["target_process"]["process_entity_id"] == pid_entity
    assert "ancestors" in data
    assert "descendants" in data

def test_tool_find_process_relationships():
    pair = _first(_PARENT_CHILD_PAIR_SQL)
    if not pair:
        pytest.skip("Active telemetry database records no parent-child process pairs")

    res = find_process_relationships.invoke({
        "host_id": pair["host_id"],
        "child_process_name": pair["child_name"],
        "parent_process_name": pair["parent_name"],
    })
    data = json.loads(res)
    assert data["matches"]
    assert all(m["host_id"] == pair["host_id"] for m in data["matches"])
    match = next(
        m for m in data["matches"]
        if m["child_process_name"].lower() == pair["child_name"].lower()
        and m["parent_process_name"].lower() == pair["parent_name"].lower()
    )
    assert match["child_process_entity_id"]
    assert match["parent_process_entity_id"]
    assert match["child_timestamp"]

def test_tool_find_process_associations():
    query_res = json.loads(query_telemetry.invoke({"sql_query": "SELECT process_entity_id FROM processes LIMIT 1"}))
    pid_entity = query_res[0]["process_entity_id"]

    assoc_res = find_process_associations.invoke({"process_entity_id": pid_entity})
    data = json.loads(assoc_res)
    assert data["process_entity_id"] == pid_entity
    assert "network_connections" in data
    assert "files" in data
    assert "registry_events" in data

def test_tool_search_timeline():
    res = search_timeline.invoke({
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-12-31T23:59:59Z",
        "limit": 5
    })
    data = json.loads(res)
    assert isinstance(data, list)

def test_search_timeline_comma_separated_keywords_are_alternatives(monkeypatch):
    from a1.tools import timeline

    captured = {}

    class FakeDatabase:
        def execute_query(self, query, params, max_rows):
            captured["query"] = query
            captured["params"] = params
            captured["max_rows"] = max_rows
            return [{
                "event_id": "evt-1",
                "timestamp": "2026-09-10T09:13:00Z",
                "provider": "Sysmon",
                "event_code": "1",
                "category": '["process"]',
                "event_type": '["start"]',
                "action": "process_started",
                "outcome": "success",
                "host_id": "host-a01",
                "user_id": "user-1",
                "process_entity_id": "proc-1",
                "raw_json": json.dumps({
                    "process.name": "procdump.exe",
                    "process.parent.entity_id": "proc-ps",
                    "process.parent.name": "powershell.exe",
                    "process.integrity_level": "high",
                }),
            }]

    monkeypatch.setattr(timeline, "_get_db", lambda: FakeDatabase())

    data = json.loads(search_timeline.invoke({"keyword": "procdump,lsass,dmp"}))

    assert len(data) == 1
    assert data[0]["details"]["parent_process_entity_id"] == "proc-ps"
    assert data[0]["details"]["parent_process_name"] == "powershell.exe"
    assert data[0]["details"]["integrity_level"] == "high"
    assert " OR " in captured["query"]
    assert captured["params"] == (
        "%procdump%", "%procdump%", "%procdump%", "%procdump%",
        "%lsass%", "%lsass%", "%lsass%", "%lsass%",
        "%dmp%", "%dmp%", "%dmp%", "%dmp%",
    )

def test_tool_get_entity_context():
    query_res = json.loads(query_telemetry.invoke({"sql_query": "SELECT host_id FROM hosts LIMIT 1"}))
    host_id = query_res[0]["host_id"]

    res = get_entity_context.invoke({"entity_type": "host", "entity_id": host_id})
    data = json.loads(res)
    assert data["host_id"] == host_id
    assert "total_events" in data

def test_tool_find_process_relationships_child_only():
    pair = _first(_PARENT_CHILD_PAIR_SQL)
    if not pair:
        pytest.skip("Active telemetry database records no parent-child process pairs")

    res = find_process_relationships.invoke({
        "host_id": pair["host_id"],
        "child_process_name": pair["child_name"],
    })
    data = json.loads(res)
    assert "matches" in data
    assert len(data["matches"]) > 0
    assert all(m["host_id"] == pair["host_id"] for m in data["matches"])
    assert any(
        m["child_process_name"].lower() == pair["child_name"].lower()
        for m in data["matches"]
    )


def test_tool_find_process_relationships_parent_only():
    pair = _first(_PARENT_CHILD_PAIR_SQL)
    if not pair:
        pytest.skip("Active telemetry database records no parent-child process pairs")

    res = find_process_relationships.invoke({
        "host_id": pair["host_id"],
        "parent_process_name": pair["parent_name"],
    })
    data = json.loads(res)
    assert "matches" in data
    assert len(data["matches"]) > 0
    assert all(m["host_id"] == pair["host_id"] for m in data["matches"])
    assert any(
        m["parent_process_name"].lower() == pair["parent_name"].lower()
        for m in data["matches"]
    )


def test_tool_pivot_indicator_aliases():
    """Alias handling is verified against real indicators discovered at runtime."""
    from a1.tools.pivot import pivot_on_indicator

    ip_row = _first(
        "SELECT destination_ip FROM network_connections "
        "WHERE destination_ip IS NOT NULL AND destination_ip <> '' LIMIT 1"
    )
    hash_row = _first(
        "SELECT sha256 FROM files WHERE sha256 IS NOT NULL AND sha256 <> '' LIMIT 1"
    )
    if not ip_row or not hash_row:
        pytest.skip("Active telemetry database has no network or file indicators to pivot on")

    res_ip = json.loads(pivot_on_indicator.invoke({
        "indicator_type": "ip",
        "indicator_value": ip_row["destination_ip"],
    }))
    assert res_ip["indicator_type"] == "destination_ip"
    assert res_ip["match_count"] > 0
    assert res_ip["hosts_seen_on"]

    res_hash = json.loads(pivot_on_indicator.invoke({
        "indicator_type": "hash",
        "indicator_value": hash_row["sha256"],
    }))
    assert res_hash["indicator_type"] == "sha256"
    assert res_hash["match_count"] > 0


def test_tool_query_telemetry_self_healing_diagnostics():
    """Verify query_telemetry returns actionable schema diagnostics on syntax/column errors."""
    # Test column typo
    res_col = json.loads(query_telemetry.invoke({"sql_query": "SELECT process_nam FROM processes LIMIT 1"}))
    assert res_col["status"] == "query_error"
    assert "process_name" in res_col["diagnostic_hint"]
    assert "processes" in res_col["available_tables"]

    # Test table typo
    res_tbl = json.loads(query_telemetry.invoke({"sql_query": "SELECT * FROM processez LIMIT 1"}))
    assert res_tbl["status"] == "query_error"
    assert "processes" in res_tbl["diagnostic_hint"]

    # Test 0-match query returns structured diagnostics
    res_zero = json.loads(query_telemetry.invoke({"sql_query": "SELECT * FROM hosts WHERE host_id = 'NONEXISTENT_HOST_12345'"}))
    assert res_zero["status"] == "zero_records_found"
    assert "available_tables" in res_zero


def test_investigation_memory_accumulation():
    """Verify investigation_memory accumulates forensic entities across iterations."""
    from a1.nodes.investigator_node import _update_investigation_memory, _format_investigation_memory
    from langchain_core.messages import ToolMessage

    tool_msg1 = ToolMessage(
        content=json.dumps({
            "matches": [
                {
                    "process_entity_id": "proc-test-01",
                    "process_name": "powershell.exe",
                    "pid": 1234,
                    "host_id": "host-test-01",
                    "command_line": "powershell.exe -enc test",
                }
            ]
        }),
        tool_call_id="call-01",
        name="find_process_relationships"
    )

    tool_msg2 = ToolMessage(
        content=json.dumps([
            {
                "action": "network_connection",
                "source_ip": "10.0.0.1",
                "destination_ip": "198.51.100.1",
                "destination_port": 443,
                "process_entity_id": "proc-test-01",
                "event_id": "evt-net-01"
            },
            {
                "action": "file_created",
                "file_name": "payload.exe",
                "file_path": "C:\\Temp\\payload.exe",
                "process_entity_id": "proc-test-01",
                "event_id": "evt-file-01"
            }
        ]),
        tool_call_id="call-02",
        name="search_timeline"
    )

    mem = _update_investigation_memory({}, [tool_msg1, tool_msg2])
    assert "proc-test-01" in mem["discovered_processes"]
    assert mem["discovered_processes"]["proc-test-01"]["process_name"] == "powershell.exe"
    assert "host-test-01" in mem["discovered_hosts"]
    assert any(n["destination_ip"] == "198.51.100.1" for n in mem["discovered_network"])
    assert any(f["file_name"] == "payload.exe" for f in mem["discovered_files"])

    formatted = _format_investigation_memory(mem)
    assert "CURRENT INVESTIGATION WORKING MEMORY" in formatted
    assert "powershell.exe" in formatted
    assert "198.51.100.1" in formatted

