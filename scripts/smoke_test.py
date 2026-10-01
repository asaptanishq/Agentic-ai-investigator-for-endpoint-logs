"""Standalone smoke test for the agent package."""
import json, os, sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = PROJECT_ROOT / "endpoint_security_dataset_expanded_corrected"

# The original five-scenario agent bundle
# (agent_bundle/agent_endpoint_security.db) is no longer part of the repository,
# so prefer a telemetry database that actually ships here. An externally set
# ENDPOINT_DB_PATH always wins.
_PREFERRED_DBS = ("attack_lateral_movement.db", "attack_data_exfiltration.db")
_DB_CANDIDATES = [DATASET_DIR / name for name in _PREFERRED_DBS]
_DB_CANDIDATES += [p for p in sorted(DATASET_DIR.glob("*.db")) if p not in _DB_CANDIDATES]
TELEMETRY_DB = _DB_CANDIDATES[0] if _DB_CANDIDATES else DATASET_DIR / "agent_bundle" / "agent_endpoint_security.db"
os.environ.setdefault("ENDPOINT_DB_PATH", str(TELEMETRY_DB))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

passed, failed = [], []
def check(name, fn):
    try:
        out = fn()
        passed.append(name)
        print(f"  PASS  {name}" + (f" -- {out}" if out else ""))
    except Exception as e:
        failed.append(name)
        print(f"  FAIL  {name}: {type(e).__name__}: {e}")

print("== 1. imports (also proves lazy DB init: no crash at import) ==")
from a1.tools import ALL_INVESTIGATION_TOOLS
from a1.tools.query import get_database_schema, query_telemetry
from a1.tools.process import find_process_relationships, trace_process_tree
from a1.tools.association import find_process_associations
from a1.tools.timeline import search_timeline
from a1.tools.entity import get_entity_context
from a1.tools.pivot import pivot_on_indicator
from a1.nodes.investigator_node import should_continue
from a1.db import EndpointDatabase
from langchain_core.messages import AIMessage, HumanMessage


def db_rows(sql, params=(), max_rows=50):
    """Read fixtures directly from whichever telemetry database is active."""
    return EndpointDatabase().execute_query(sql, params, max_rows=max_rows)


print(f"  PASS  imports -- {len(ALL_INVESTIGATION_TOOLS)} tools registered")

print(f"== 2. tools against the active telemetry DB ({TELEMETRY_DB.name}) ==")
check("get_database_schema", lambda: f"{len(json.loads(get_database_schema.invoke({})))} tables/views")

def t_query_raw():
    res = json.loads(query_telemetry.invoke({
        "sql_query": "SELECT event_id, raw_json FROM events WHERE raw_json IS NOT NULL ORDER BY length(raw_json) DESC LIMIT 4",
        "max_rows": 4}))
    assert len(res) == 4
    big = [r for r in res if "raw_json_projected" in r]
    small = [r for r in res if "raw_json" in r]
    assert big, "expected at least one payload over the projection threshold"
    proj = big[0]["raw_json_projected"]
    assert "process.command_line" in proj, f"command_line must survive projection, got {sorted(proj)}"
    assert "process.hash.sha256" in proj, "hash must survive projection"
    assert "event.id" not in proj, "bulk keys must be dropped"
    assert "host.os.version" not in proj, "bulk keys must be dropped"
    return (f"{len(big)} projected (kept {sorted(proj)[:5]}...), "
            f"{len(small)} kept whole, full-row chars {len(json.dumps(big[0]))} vs orig ~1600")
check("query_telemetry raw_json projection", t_query_raw)

def t_rel():
    host = db_rows("SELECT host_id FROM hosts LIMIT 1")
    host_id = host[0]["host_id"] if host else "host-unknown"
    res = json.loads(find_process_relationships.invoke({
        "host_id": host_id, "child_process_name": "powershell.exe",
        "parent_process_name": "pwsh-parent-probe"}))
    return f"runs with required args, {len(res['matches'])} matches (0 ok for bogus parent)"
check("find_process_relationships (no scenario defaults)", t_rel)

def t_tree():
    row = db_rows(
        "SELECT process_entity_id, process_name FROM processes "
        "WHERE parent_entity_id IS NOT NULL AND parent_entity_id <> '' LIMIT 1")
    assert row, "active telemetry database records no child processes"
    entity_id, expected_name = row[0]["process_entity_id"], row[0]["process_name"]
    res = json.loads(trace_process_tree.invoke({"process_entity_id": entity_id}))
    assert res["target_process"]["process_name"] == expected_name
    return (f"{expected_name}: {len(res['ancestors'])} ancestors, "
            f"{len(res['descendants'])} descendants")
check("trace_process_tree", t_tree)

def t_assoc():
    row = db_rows("SELECT process_entity_id FROM processes LIMIT 1")
    assert row, "active telemetry database records no processes"
    res = json.loads(find_process_associations.invoke({"process_entity_id": row[0]["process_entity_id"]}))
    assert all(k in res for k in ("network_connections", "files", "registry_events", "events"))
    return "all 4 association buckets present"
check("find_process_associations", t_assoc)

def t_timeline():
    bounds = db_rows("SELECT MIN(timestamp) AS mn, MAX(timestamp) AS mx FROM events")[0]
    host = db_rows("SELECT host_id FROM events WHERE host_id IS NOT NULL AND host_id <> '' LIMIT 1")
    assert host, "active telemetry database contains no host-attributed events"
    res = json.loads(search_timeline.invoke({
        "start_time": bounds["mn"], "end_time": bounds["mx"],
        "host_id": host[0]["host_id"], "limit": 5}))
    assert isinstance(res, list)
    assert len(res) > 0
    return f"{len(res)} events for {host[0]['host_id']} inside the recorded window"
check("search_timeline", t_timeline)

def t_entity():
    host = db_rows("SELECT host_id FROM hosts LIMIT 1")
    user = db_rows("SELECT user_id FROM users LIMIT 1")
    assert host, "active telemetry database has no hosts"
    assert user, "active telemetry database has no users"
    h = json.loads(get_entity_context.invoke({"entity_type": "host", "entity_id": host[0]["host_id"]}))
    u = json.loads(get_entity_context.invoke({"entity_type": "user", "entity_id": user[0]["user_id"]}))
    assert h["host_id"] == host[0]["host_id"]
    assert u["user_id"] == user[0]["user_id"]
    return f"host {host[0]['host_id']} + user {user[0]['user_id']} resolve"
check("get_entity_context", t_entity)

def t_pivot():
    ip_row = db_rows("SELECT destination_ip FROM network_connections "
                     "WHERE destination_ip IS NOT NULL AND destination_ip <> '' LIMIT 1")
    hash_row = db_rows("SELECT sha256 FROM files WHERE sha256 IS NOT NULL AND sha256 <> '' LIMIT 1")
    exe_row = db_rows("SELECT process_name FROM processes "
                      "WHERE process_name IS NOT NULL AND process_name <> '' LIMIT 1")
    assert ip_row, "active telemetry database has no pivotable destination_ip"
    assert hash_row, "active telemetry database has no pivotable sha256"
    assert exe_row, "active telemetry database has no pivotable process_name"
    r1 = json.loads(pivot_on_indicator.invoke({"indicator_type": "sha256",
        "indicator_value": hash_row[0]["sha256"]}))
    r2 = json.loads(pivot_on_indicator.invoke({"indicator_type": "destination_ip",
        "indicator_value": ip_row[0]["destination_ip"]}))
    r3 = json.loads(pivot_on_indicator.invoke({"indicator_type": "executable",
        "indicator_value": exe_row[0]["process_name"]}))
    assert r1["match_count"] >= 1
    assert "hosts_seen_on" in r1
    assert r2["match_count"] >= 1
    assert r3["match_count"] >= 1
    return f"sha256:{r1['match_count']} ip:{r2['match_count']} exe:{r3['match_count']} hosts:{r3['hosts_seen_on'][:3]}"
check("pivot_on_indicator (new tool)", t_pivot)

def t_bad_indicator():
    out = pivot_on_indicator.invoke({"indicator_type": "bogus", "indicator_value": "x"})
    assert "Invalid indicator_type" in out
    return "bad type rejected cleanly"
check("pivot_on_indicator invalid type", t_bad_indicator)

print("== 3. investigator routing logic (no LLM needed) ==")
def t_route_min_steps():
    # step 1, model returns text with NO tool calls -> must loop back, not correlate
    s = {"messages": [HumanMessage(content="plan"), AIMessage(content="done")], "iteration_count": 1}
    assert should_continue(s) == "investigator", "step-1 tool-free conclusion must not advance"
    # step 2, still no tools -> now allowed to correlate
    s["iteration_count"] = 2
    assert should_continue(s) == "correlate"
    return "zero-evidence conclusion blocked on step 1, allowed on step 2"
check("should_continue minimum-steps guard", t_route_min_steps)

def t_route_tools_and_cap():
    s = {"messages": [AIMessage(content="", tool_calls=[{"name": "x", "args": {}, "id": "1", "type": "tool_call"}])],
         "iteration_count": 1}
    assert should_continue(s) == "tools"
    s2 = {"messages": [AIMessage(content="done")], "iteration_count": 8}
    assert should_continue(s2) == "correlate"
    return "tool_calls -> tools; iteration cap -> correlate"
check("should_continue tools/cap paths", t_route_tools_and_cap)

print("== 4. graph compiles (LLM not called) ==")
def t_graph():
    from a1.graph import create_investigation_graph
    app = create_investigation_graph()
    return f"compiled: {type(app).__name__}"
check("create_investigation_graph", t_graph)

print("== 5. benchmark: case_id matching + fallback auto-FAIL ==")
def t_benchmark():
    import tempfile
    import a1.benchmark as B

    calls = []
    class StubApp:
        def invoke(self, state):
            calls.append(state["alert_context"][:20])
            # simulate: correct verdict BUT report fell back -> must be FAIL
            return {"verdict": "suspicious", "verdict_boundary": "unconfirmed_malicious",
                    "confidence": 0.3, "report_fallback_used": True, "messages": []}

    # case_labels.json is evaluator-only metadata that is not shipped with the
    # repository, so synthesise a minimal labels file for the benchmark prompts.
    tmp_dir = Path(tempfile.mkdtemp(prefix="a1-benchmark-"))
    labels = [
        {"case_id": case_id, "case_label": "suspicious", "verdict_boundary": "unconfirmed_malicious"}
        for case_id in list(B.BENCHMARK_PROMPTS)[:2]
    ]
    (tmp_dir / "case_labels.json").write_text(json.dumps(labels), encoding="utf-8")

    original_dataset_dir = B.DATASET_DIR
    original_graph_factory = B.create_investigation_graph
    B.DATASET_DIR = tmp_dir
    B.create_investigation_graph = lambda: StubApp()
    try:
        benchmark_output = StringIO()
        with redirect_stdout(benchmark_output):
            out = B.run_benchmark(limit=2)
    finally:
        B.DATASET_DIR = original_dataset_dir
        B.create_investigation_graph = original_graph_factory

    assert len(out["results"]) == 2
    assert all(r["fallback_used"] for r in out["results"])
    assert out["verdict_accuracy"] == 0.0, "fallback runs must score 0 even with right verdict"
    assert out["results"][0]["case_id"] in B.BENCHMARK_PROMPTS
    return (f"{len(out['results'])} cases matched by case_id; intentional fallback rejection "
            f"verified ({out['verdict_accuracy']:.0%} accuracy)")
check("benchmark matching + fallback rule", t_benchmark)

print("== 6. anti-loop fixes (from the 24-step run) ==")
def t_readonly_guardrail():
    out = query_telemetry.invoke({"sql_query": "DROP TABLE events"})
    assert "Security violation" in out, f"expected a guardrail rejection, got: {out[:120]}"
    assert db_rows("SELECT COUNT(*) AS c FROM events")[0]["c"] > 0, "events must survive"
    return "mutations blocked by the read-only guardrail; table intact"
check("query_telemetry blocks mutations (read-only guardrail)", t_readonly_guardrail)

def t_empty_tree_note():
    # Pick a process with no recorded parent AND no recorded children; the old
    # output "0 ancestors, 0 descendants" made the model retry 17x.
    row = db_rows(
        "SELECT process_entity_id FROM processes "
        "WHERE (parent_entity_id IS NULL OR parent_entity_id = '') "
        "AND process_entity_id NOT IN ("
        "  SELECT parent_entity_id FROM processes "
        "  WHERE parent_entity_id IS NOT NULL AND parent_entity_id <> '') LIMIT 1")
    assert row, "active telemetry database records no parentless, childless processes"
    res = json.loads(trace_process_tree.invoke({"process_entity_id": row[0]["process_entity_id"]}))
    assert res["ancestors"] == []
    assert res["descendants"] == []
    assert "repeating" in res.get("note", "").lower(), "note must tell the model not to retry"
    return "empty tree now carries a do-not-repeat note"
check("trace_process_tree empty-result note", t_empty_tree_note)

def t_schema_hint():
    from a1.nodes.investigator_node import _get_schema_hint
    hint = _get_schema_hint()
    assert "processes(" in hint
    assert "process_name" in hint
    assert "events(" in hint
    # events must NOT list process_name (the model's exact mistake)
    events_line = [l for l in hint.splitlines() if l.strip().startswith("events(")][0]
    assert "process_name" not in events_line
    # cached on second call
    assert _get_schema_hint() is hint
    return "real columns injected; events.process_name absent as in the DB"
check("schema hint injection", t_schema_hint)

def t_repetition_guard():
    import sys
    # NOTE: a1.nodes.__init__ re-exports the investigator_node *function* under
    # the same name as the submodule, so plain `import ... as IN` binds the
    # function. sys.modules gets the real module.
    IN = sys.modules["a1.nodes.investigator_node"]
    from langchain_core.messages import ToolMessage
    prior_tc = {"name": "trace_process_tree",
                "args": {"process_entity_id": "proc-exp-0000157", "direction": "both"},
                "id": "call_1", "type": "tool_call"}
    prior_ai = AIMessage(content="", tool_calls=[prior_tc])
    state = {"messages": [HumanMessage(content="investigate host-001"),
                          prior_ai,
                          ToolMessage(content="{}", tool_call_id="call_1")],
             "iteration_count": 3, "repeat_nudges": 0}
    orig_get_llm = IN.get_llm

    class StubLLM:
        def __init__(self, resp): self.resp = resp
        def bind_tools(self, tools): return self
        def invoke(self, messages):
            # schema hint must be in the system prompt
            assert "DATABASE SCHEMA" in messages[0].content
            return self.resp

    repeat_resp = AIMessage(content="", tool_calls=[dict(prior_tc, id="call_2")])
    IN.get_llm = lambda **kw: StubLLM(repeat_resp)
    try:
        out = IN.investigator_node(state)
        msgs = out["messages"]
        assert len(msgs) == 2, "expected [unexecuted response, nudge]"
        assert msgs[1].content.startswith(IN._NUDGE_PREFIX)
        assert out["repeat_nudges"] == 1
        # nudge routes back to investigator for another attempt
        assert IN.should_continue({"messages": state["messages"] + msgs,
                                   "iteration_count": out["iteration_count"],
                                   "repeat_nudges": 1}) == "investigator"

        # model repeats AGAIN after the nudge -> circuit breaker fires
        state2 = {"messages": state["messages"] + msgs, "iteration_count": 4, "repeat_nudges": 1}
        out2 = IN.investigator_node(state2)
        assert out2["repeat_nudges"] == 2
        assert IN.should_continue({"messages": state2["messages"] + out2["messages"],
                                   "iteration_count": out2["iteration_count"],
                                   "repeat_nudges": 2}) == "correlate"

        # a FRESH (non-repeat) call passes through untouched
        fresh_resp = AIMessage(content="", tool_calls=[
            {"name": "find_process_associations",
             "args": {"process_entity_id": "proc-exp-0000002"}, "id": "call_3", "type": "tool_call"}])
        IN.get_llm = lambda **kw: StubLLM(fresh_resp)
        out3 = IN.investigator_node(state)
        assert len(out3["messages"]) == 1
        assert "repeat_nudges" not in out3
        assert IN.should_continue({"messages": state["messages"] + out3["messages"],
                                   "iteration_count": out3["iteration_count"],
                                   "repeat_nudges": 0}) == "tools"
    finally:
        IN.get_llm = orig_get_llm
    return "repeat -> nudge -> retry -> circuit-breaker; fresh calls unaffected"
check("repetition guard + circuit breaker", t_repetition_guard)

print(f"\n{len(passed)} passed, {len(failed)} failed")
if __name__ == "__main__":
    sys.exit(1 if failed else 0)
