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
