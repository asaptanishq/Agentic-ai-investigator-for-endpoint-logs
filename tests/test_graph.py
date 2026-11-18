import json

from a1.graph import create_investigation_graph
from a1.nodes.investigator_node import _condense_older_tool_output

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


def test_condensed_tool_output_preserves_anchors_and_json():
    raw = json.dumps({
        "events": [
            {"event_id": f"evt-{i}", "process_entity_id": "proc-1", "timestamp": "2026-09-11T10:00:00Z", "raw_payload": "x" * 2000}
            for i in range(30)
        ]
    })
    condensed = _condense_older_tool_output(raw)
    parsed = json.loads(condensed)
    assert parsed["events"]
    assert parsed["events"][0]["event_id"] == "evt-0"
    assert "raw_payload" not in parsed["events"][0]
    assert len(parsed["events"]) <= 20
