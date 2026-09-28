import importlib
import json

from a1.graph import create_investigation_graph
from langchain_core.messages import AIMessage, ToolMessage

def test_graph_compilation():
    graph = create_investigation_graph()
    assert graph is not None

    # Check node names registered in the graph
    node_names = list(graph.nodes.keys())
    assert "alert_prep" in node_names
    assert "triage" in node_names
    assert "investigator" in node_names
    assert "tools" in node_names
    assert "evidence_packing" in node_names
    assert "correlate" in node_names
    assert "report" in node_names


def test_investigator_requests_missing_smb_link_for_ntlm_sequence(monkeypatch):
    investigator = importlib.import_module("a1.nodes.investigator_node")
    auth_rows = []
    for event_id, timestamp, action in (
        ("evt-fail-1", "2026-09-10T09:32:00Z", "logon_failed"),
        ("evt-fail-2", "2026-09-10T09:35:10Z", "logon_failed"),
        ("evt-success", "2026-09-10T09:36:02Z", "logon_success"),
    ):
        auth_rows.append({
            "event_id": event_id,
            "timestamp": timestamp,
            "host_id": "host-a02",
            "action": action,
            "details": {
                "source_ip": "10.10.2.20",
                "destination_ip": "10.10.2.30",
                "authentication_package": "NTLM",
                "logon_type": 3,
                "user_name": "jdoe",
                "user_domain": "CORP",
            },
        })
    auth_message = ToolMessage(content=json.dumps(auth_rows), tool_call_id="auth-query")

    class StubLLM:
        def bind_tools(self, tools):
            return self

        def invoke(self, messages):
            return AIMessage(content="The investigation is complete.")

    monkeypatch.setattr(investigator, "get_llm", lambda: StubLLM())
    state = {
        "messages": [auth_message],
        "iteration_count": 2,
        "repeat_nudges": 0,
        "enriched_alert": {"entities": {"host_ids": ["host-a01", "host-a02"]}},
    }

    output = investigator.investigator_node(state)

    assert output["lateral_network_nudge_sent"] is True
    assert "host-a01" in output["messages"][-1].content
    assert "TCP/445" in output["messages"][-1].content
    route_state = {
        **state,
        "messages": state["messages"] + output["messages"],
        "iteration_count": output["iteration_count"],
    }
    assert investigator.should_continue(route_state) == "investigator"

    smb_rows = [{
        "event_id": "evt-smb",
        "timestamp": "2026-09-10T09:31:00Z",
        "host_id": "host-a01",
        "action": "network_connection",
        "details": {
            "source_ip": "10.10.2.20",
            "destination_ip": "10.10.2.30",
            "destination_port": 445,
        },
    }]
    smb_message = ToolMessage(content=json.dumps(smb_rows), tool_call_id="smb-query")
    assert investigator._missing_smb_auth_correlation([auth_message, smb_message]) is None


def test_investigator_requests_full_scope_auth_review_when_requested(monkeypatch):
    investigator = importlib.import_module("a1.nodes.investigator_node")

    class StubLLM:
        def bind_tools(self, tools):
            return self

        def invoke(self, messages):
            return AIMessage(content="The investigation is complete.")

    monkeypatch.setattr(investigator, "get_llm", lambda: StubLLM())
    state = {
        "alert_context": "Investigate data staging and evaluate afternoon logon events.",
        "messages": [],
        "iteration_count": 4,
        "repeat_nudges": 0,
        "enriched_alert": {
            "entities": {"host_ids": ["host-b01"]},
            "time_window": {
                "start_time": "2026-09-11T08:05:00Z",
                "end_time": "2026-09-11T14:04:49Z",
            },
        },
    }

    output = investigator.investigator_node(state)

    assert output["requested_auth_nudge_sent"] is True
    assert "host-b01" in output["messages"][-1].content
    assert "category='authentication'" in output["messages"][-1].content
    assert "2026-09-11T08:05:00Z" in output["messages"][-1].content
    route_state = {
        **state,
        "messages": output["messages"],
        "iteration_count": output["iteration_count"],
    }
    assert investigator.should_continue(route_state) == "investigator"

    auth_query = AIMessage(content="", tool_calls=[{
        "name": "search_timeline",
        "args": {
            "host_id": "host-b01",
            "category": "authentication",
            "start_time": "2026-09-11T08:05:00Z",
            "end_time": "2026-09-11T14:04:49Z",
        },
        "id": "auth-query",
        "type": "tool_call",
    }])
    assert investigator._missing_requested_auth_hosts({
        **state,
        "messages": [auth_query],
    }) == []


def test_investigator_requests_separate_named_archive_creation_event(monkeypatch):
    investigator = importlib.import_module("a1.nodes.investigator_node")

    class StubLLM:
        def bind_tools(self, tools):
            return self

        def invoke(self, messages):
            return AIMessage(content="The investigation is complete.")

    monkeypatch.setattr(investigator, "get_llm", lambda: StubLLM())
    command_message = ToolMessage(content=json.dumps([{
        "event_id": "evt-command",
        "timestamp": "2026-09-11T10:06:00Z",
        "host_id": "host-b01",
        "action": "process_started",
        "process_entity_id": "proc-7z",
        "details": {"command_line": "7z.exe a -psecret stage.7z"},
    }]), tool_call_id="archive-command")
    state = {
        "alert_context": "Investigate exfiltration involving the staged archive stage.7z.",
        "messages": [command_message],
        "iteration_count": 3,
        "repeat_nudges": 0,
        "enriched_alert": {
            "entities": {"host_ids": ["host-b01"]},
            "time_window": {
                "start_time": "2026-09-11T08:05:00Z",
                "end_time": "2026-09-11T14:04:49Z",
            },
        },
    }

    output = investigator.investigator_node(state)

    assert output["requested_archive_nudge_sent"] is True
    assert "category='file'" in output["messages"][-1].content
    assert "keyword='stage.7z'" in output["messages"][-1].content
    route_state = {
        **state,
        "messages": state["messages"] + output["messages"],
        "iteration_count": output["iteration_count"],
    }
    assert investigator.should_continue(route_state) == "investigator"

    creation_message = ToolMessage(content=json.dumps([{
        "event_id": "evt-file-created",
        "timestamp": "2026-09-11T10:09:00Z",
        "host_id": "host-b01",
        "action": "file_created",
        "process_entity_id": "proc-7z",
        "details": {"file_name": "stage.7z"},
    }]), tool_call_id="archive-file")
    assert investigator._missing_requested_archive_files({
        **state,
        "messages": [command_message, creation_message],
    }) == []
