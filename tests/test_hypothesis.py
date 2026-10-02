"""Unit tests for HypothesisTracker lifecycle management."""
import pytest
from src.a1.hypothesis import HypothesisTracker, HypothesisStatus


def test_hypothesis_lifecycle():
    tracker = HypothesisTracker()
    h1 = tracker.add_hypothesis("Attacker used compromised credentials on HOST-A", hypothesis_id="H1")
    assert h1.id == "H1"
    assert h1.status == HypothesisStatus.ACTIVE
    assert len(tracker.get_all()) == 1

    # Add supporting evidence
    tracker.update_status("H1", HypothesisStatus.SUPPORTED, evidence_id="evt-100", reason="Found 4624 login event")
    assert h1.status == HypothesisStatus.SUPPORTED
    assert "evt-100" in h1.supporting_evidence
    assert len(h1.notes) == 1

    # Add contradicting evidence
    h2 = tracker.add_hypothesis("Malicious service installed on HOST-B", hypothesis_id="H2")
    tracker.update_status("H2", HypothesisStatus.CONTRADICTED, evidence_id="evt-200", reason="Service was legitimate AV update")
    assert h2.status == HypothesisStatus.CONTRADICTED
    assert "evt-200" in h2.contradicting_evidence

    # Missing evidence gaps
    h3 = tracker.add_hypothesis("Data exfiltration over DNS", hypothesis_id="H3")
    tracker.add_missing_evidence("H3", "DNS query logs missing for 2026-03-01")
    gaps = tracker.get_evidence_gaps()
    assert any(g["hypothesis_id"] == "H3" and g["type"] == "missing_evidence" for g in gaps)

    # Serialization roundtrip
    data = tracker.to_dict()
    restored = HypothesisTracker.from_dict(data)
    assert len(restored.get_all()) == 3
    assert restored.get_hypothesis("H1").status == HypothesisStatus.SUPPORTED
    assert restored.get_hypothesis("H2").status == HypothesisStatus.CONTRADICTED
    assert "evt-100" in restored.get_hypothesis("H1").supporting_evidence


def test_dynamic_hypothesis_creation():
    """Verify dynamic hypotheses can be created from evidence."""
    tracker = HypothesisTracker()
    tracker.add_hypothesis("Initial: credential theft", hypothesis_id="H1")

    h = tracker.add_dynamic_hypothesis(
        description="Persistence via scheduled task OneDriveSync",
        triggering_evidence=["evt-001"],
        provenance="Registry TaskCache modification detected",
        iteration=3,
    )
    assert h is not None
    assert h.source == "dynamic"
    assert h.id.startswith("HD")
    assert h.provenance == "Registry TaskCache modification detected"
    assert h.created_at_iteration == 3
    assert len(tracker.get_all()) == 2


def test_dynamic_hypothesis_deduplication():
    """Duplicate hypotheses should not be created."""
    tracker = HypothesisTracker()
    tracker.add_hypothesis("Lateral movement to domain controller", hypothesis_id="H1")

    h = tracker.add_dynamic_hypothesis(
        description="Lateral movement to domain controller via SMB",
        triggering_evidence=["evt-002"],
        provenance="test",
        iteration=2,
    )
    assert h is None  # Too similar to H1


def test_dynamic_hypothesis_max_cap():
    """Active hypothesis count should be capped."""
    from src.a1.hypothesis import MAX_ACTIVE_HYPOTHESES
    tracker = HypothesisTracker()
    for i in range(MAX_ACTIVE_HYPOTHESES):
        tracker.add_hypothesis(f"Hypothesis number {i} regarding anomalous behavior", hypothesis_id=f"H{i}")

    h = tracker.add_dynamic_hypothesis(
        description="One more completely unique hypothesis for staging",
        triggering_evidence=["evt-999"],
        provenance="test",
        iteration=5,
    )
    assert h is None  # At cap


def test_dynamic_hypothesis_requires_evidence():
    """No hypothesis without triggering evidence."""
    tracker = HypothesisTracker()
    h = tracker.add_dynamic_hypothesis(
        description="Random speculative hypothesis",
        triggering_evidence=[],
        provenance="no evidence",
        iteration=1,
    )
    assert h is None


def test_original_hypotheses_preserved():
    """Dynamic hypotheses must not overwrite or remove originals."""
    tracker = HypothesisTracker()
    tracker.add_hypothesis("Original H1", hypothesis_id="H1")
    tracker.add_hypothesis("Original H2", hypothesis_id="H2")

    tracker.add_dynamic_hypothesis(
        description="New dynamic finding for archive creation",
        triggering_evidence=["evt-100"],
        provenance="test",
        iteration=3,
    )

    assert tracker.get_hypothesis("H1") is not None
    assert tracker.get_hypothesis("H2") is not None
    assert len(tracker.get_all()) == 3


def test_dynamic_hypothesis_serialization_roundtrip():
    """Dynamic hypothesis fields must survive to_dict/from_dict."""
    tracker = HypothesisTracker()
    tracker.add_dynamic_hypothesis(
        description="Persistence via registry Run key",
        triggering_evidence=["evt-100"],
        provenance="Registry Run key modified",
        iteration=3,
    )

    data = tracker.to_dict()
    restored = HypothesisTracker.from_dict(data)
    h = restored.get_all()[0]
    assert h.source == "dynamic"
    assert h.provenance == "Registry Run key modified"
    assert h.triggering_evidence == ["evt-100"]
    assert h.created_at_iteration == 3


def test_unresolved_hypotheses_preserved_in_report():
    """Unresolved hypotheses should be available for reporting."""
    tracker = HypothesisTracker()
    tracker.add_hypothesis("H1 text", hypothesis_id="H1")
    tracker.update_status("H1", HypothesisStatus.SUPPORTED, evidence_id="evt-1")

    tracker.add_dynamic_hypothesis(
        description="Unresolved dynamic lateral connection",
        triggering_evidence=["evt-2"],
        provenance="test",
        iteration=4,
    )

    unresolved = tracker.get_unresolved()
    assert len(unresolved) == 1
    assert unresolved[0].source == "dynamic"

