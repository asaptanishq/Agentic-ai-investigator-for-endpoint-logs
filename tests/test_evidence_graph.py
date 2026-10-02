"""Unit tests for EvidenceGraph and temporal anomaly detection."""
import pytest
from src.a1.evidence_graph import (
    EvidenceGraph,
    EvidenceEntity,
    EvidenceEdge,
    EntityType,
    RelationshipType,
)


def test_evidence_graph_add_and_retrieve():
    graph = EvidenceGraph()
    entity1 = EvidenceEntity(
        entity_id="proc-100",
        entity_type=EntityType.PROCESS,
        properties={"process_name": "powershell.exe", "command_line": "powershell.exe -enc ..."},
        source_event_ids=["evt-001"],
        timestamps=["2026-03-01T10:00:00Z"],
    )
    graph.add_entity(entity1)
    retrieved = graph.get_entity("proc-100")
    assert retrieved is not None
    assert retrieved.entity_id == "proc-100"
    assert retrieved.properties["process_name"] == "powershell.exe"

    # Merge properties on duplicate addition
    entity1_update = EvidenceEntity(
        entity_id="proc-100",
        entity_type=EntityType.PROCESS,
        properties={"pid": 4321},
        source_event_ids=["evt-002"],
        timestamps=["2026-03-01T10:05:00Z"],
    )
    graph.add_entity(entity1_update)
    merged = graph.get_entity("proc-100")
    assert merged.properties["pid"] == 4321
    assert merged.properties["process_name"] == "powershell.exe"
    assert set(merged.source_event_ids) == {"evt-001", "evt-002"}
    assert len(merged.timestamps) == 2


def test_evidence_graph_edges_and_neighbors():
    graph = EvidenceGraph()
    p1 = EvidenceEntity(entity_id="proc-parent", entity_type=EntityType.PROCESS)
    p2 = EvidenceEntity(entity_id="proc-child", entity_type=EntityType.PROCESS)
    host = EvidenceEntity(entity_id="host-srv1", entity_type=EntityType.HOST)

    graph.add_entity(p1)
    graph.add_entity(p2)
    graph.add_entity(host)

    edge1 = EvidenceEdge(
        source_id="proc-parent",
        target_id="proc-child",
        relationship=RelationshipType.SPAWNED,
        source_event_id="evt-10",
    )
    edge2 = EvidenceEdge(
        source_id="proc-parent",
        target_id="host-srv1",
        relationship=RelationshipType.OBSERVED_ON,
    )
    graph.add_edge(edge1)
    graph.add_edge(edge2)

    neighbors = graph.get_neighbors("proc-parent")
    neighbor_ids = {n.entity_id for n in neighbors}
    assert "proc-child" in neighbor_ids
    assert "host-srv1" in neighbor_ids

    # Path finding
    path = graph.find_path("host-srv1", "proc-child")
    assert path == ["host-srv1", "proc-parent", "proc-child"]


def test_evidence_graph_timeline_and_temporal_anomalies():
    graph = EvidenceGraph()

    # Create parent with later timestamp than child (temporal anomaly)
    parent = EvidenceEntity(
        entity_id="proc-p",
        entity_type=EntityType.PROCESS,
        properties={"start_time": "2026-03-01T12:00:00Z"},
    )
    child = EvidenceEntity(
        entity_id="proc-c",
        entity_type=EntityType.PROCESS,
        properties={"start_time": "2026-03-01T11:00:00Z"},
    )
    graph.add_entity(parent)
    graph.add_entity(child)
    graph.add_edge(
        EvidenceEdge(
            source_id="proc-p",
            target_id="proc-c",
            relationship=RelationshipType.PARENT_OF,
        )
    )

    anomalies = graph.detect_temporal_anomalies()
    assert len(anomalies) >= 1
    assert anomalies[0]["type"] == "impossible_parent_child_timing"

    # Add timeline events
    graph.add_timeline_event("2026-03-01T10:00:00Z", "evt-1", "Initial login")
    graph.add_timeline_event("2026-03-01T10:30:00Z", "evt-2", "Process execution")
    timeline = graph.get_timeline()
    assert len(timeline) == 2
    assert timeline[0]["event_id"] == "evt-1"
    assert timeline[1]["event_id"] == "evt-2"


def test_evidence_graph_tool_ingestion_and_serialization():
    graph = EvidenceGraph()

    tool_rows = [
        {
            "event_id": "evt-exp-001",
            "timestamp": "2026-03-01T09:00:00Z",
            "hostname": "WORKSTATION-01",
            "user": "Alice",
            "process_id": "proc-exp-001",
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c whoami",
        },
        {
            "event_id": "evt-exp-002",
            "timestamp": "2026-03-01T09:01:00Z",
            "hostname": "WORKSTATION-01",
            "process_id": "proc-exp-002",
            "parent_process_id": "proc-exp-001",
            "process_name": "whoami.exe",
            "destination_ip": "10.0.0.5",
            "file_path": "C:\\temp\\out.txt",
        },
    ]

    graph.ingest_tool_result("query_telemetry", {}, tool_rows)

    assert "host-workstation-01" in graph.entities
    assert "user-alice" in graph.entities
    assert "proc-exp-001" in graph.entities
    assert "proc-exp-002" in graph.entities
    assert "ip-10.0.0.5" in graph.entities
    assert "file-c:\\temp\\out.txt" in graph.entities

    # Check serialization round-trip
    serialized = graph.to_dict()
    restored = EvidenceGraph.from_dict(serialized)
    assert len(restored.entities) == len(graph.entities)
    assert len(restored.edges) == len(graph.edges)
    assert len(restored.timeline) == len(graph.timeline)
