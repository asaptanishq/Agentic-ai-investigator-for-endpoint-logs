from a1.benchmark import (
    _CITATION_RE,
    _score_confidence_calibration,
    _score_evidence_grounding,
    _score_evidence_recall,
    _score_report_quality,
)


class _FakeDB:
    def __init__(self, rows):
        self.rows = rows

    def execute_query(self, sql, params=(), max_rows=50):
        table = "events" if "FROM events" in sql else "processes"
        column = "process_entity_id" if "process_entity_id" in sql else "event_id"
        return [{"c": 1}] if (table, column, params[0]) in self.rows else [{"c": 0}]


def test_grounding_accepts_event_only_process_ids(monkeypatch):
    fake = _FakeDB({("events", "event_id", "evt-e1"), ("events", "process_entity_id", "proc-p1")})
    monkeypatch.setattr("a1.db.EndpointDatabase", lambda: fake)

    pts, hallucinated, total, unverified = _score_evidence_grounding("evt-e1 proc-p1")

    assert (pts, hallucinated, total, unverified) == (20.0, 0, 2, 0)


def test_grounding_flags_unknown_process_id(monkeypatch):
    fake = _FakeDB({("events", "event_id", "evt-e1")})
    monkeypatch.setattr("a1.db.EndpointDatabase", lambda: fake)

    pts, hallucinated, total, _ = _score_evidence_grounding("evt-e1 proc-nope-1")

    assert (pts, hallucinated, total) == (10.0, 1, 2)


def test_citation_regex_skips_truncated_fragment():
    assert _CITATION_RE.findall("proc-atk and proc-atkA-0001") == ["proc-atkA-0001"]


def test_report_quality_credit_for_suricata_citations():
    report = (
        "## Executive Summary\n"
        "| Timestamp (UTC) | Event ID |\n|---|---|\n"
        "| 2026-10-16T00:00:00Z | x |\n| 2026-10-16T00:01:00Z | y |\n"
        + "detail " * 200
        + "\n## Evidence Gap\n## Next Steps\n"
        "evt-a-1 suri-20261016-0001"
    )
    without_suri = report.replace("suri-20261016-0001", "not-an-id")

    assert _score_report_quality(report) - _score_report_quality(without_suri) == 2.0


def test_calibration_uses_verdict_not_boundary():
    state = {"confidence": 0.9}
    assert _score_confidence_calibration(state, True, False, False)[0] == 9.9


def test_empty_evidence_basis_scores_zero():
    assert _score_evidence_recall([], "anything") == (0.0, 0.0)
