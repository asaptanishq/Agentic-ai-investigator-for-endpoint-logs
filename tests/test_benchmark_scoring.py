from a1.benchmark import (
    _CITATION_RE,
    _confusion_metrics,
    _score_confidence_calibration,
    _score_evidence_checks,
    _score_evidence_grounding,
    _score_evidence_recall,
    _score_investigation_efficiency,
    _score_ioc_coverage,
    _score_report_quality,
)


class _FakeDB:
    """Small DB double: returns a row for SELECT *, counts for existence checks."""

    def __init__(self, rows):
        self.rows = rows

    def execute_query(self, sql, params=(), max_rows=50):
        table = "events" if "FROM events" in sql else "processes"
        if "count(*)" in sql:
            column = "process_entity_id" if "process_entity_id" in sql else "event_id"
            return [{"c": 1}] if (table, column, params[0]) in self.rows else [{"c": 0}]
        for key, row in self.rows.items():
            if key[0] == table and key[2] == params[0]:
                return [row]
        return []


def _fake_db():
    return _FakeDB({
        ("events", "event_id", "evt-e1"): {
            "event_id": "evt-e1", "process_entity_id": "proc-p1",
            "message": "procdump.exe dumped lsass memory", "host_id": "host-a01",
        },
        ("processes", "process_entity_id", "proc-p1"): {
            "process_entity_id": "proc-p1", "process_name": "procdump.exe",
            "command_line": "procdump.exe -ma lsass.exe",
        },
    })


def test_grounding_accepts_event_only_process_ids(monkeypatch):
    # proc-p1 exists only on events.*, not processes.*
    fake = _FakeDB({("events", "event_id", "evt-e1"): {
        "event_id": "evt-e1", "message": "procdump.exe dumped lsass",
    }, ("events", "process_entity_id", "proc-p1"): {
        "event_id": "evt-e2", "process_entity_id": "proc-p1",
        "message": "procdump.exe dumped lsass memory",
    }})
    monkeypatch.setattr("a1.db.EndpointDatabase", lambda: fake)

    report = "procdump.exe dumped lsass evt-e1 proc-p1"
    pts, hallucinated, total, unverified = _score_evidence_grounding(report)

    assert (pts, hallucinated, total, unverified) == (20.0, 0, 2, 0)


def test_grounding_flags_unknown_process_id(monkeypatch):
    monkeypatch.setattr("a1.db.EndpointDatabase", _fake_db)

    report = "procdump.exe dumped lsass evt-e1 proc-nope-1"
    pts, hallucinated, total, _ = _score_evidence_grounding(report, detailed=True)[:4]

    assert hallucinated == 1 and total == 2
    assert pts == 8.0  # 10 for one real of two, minus 2 for the fake


def test_grounding_rejects_citation_with_unrelated_claim(monkeypatch):
    monkeypatch.setattr("a1.db.EndpointDatabase", _fake_db)

    report = "Outbound C2 beacon to 203.0.113.9 evt-e1"
    pts, hallucinated, total, _, supported, rate = _score_evidence_grounding(report, detailed=True)

    assert (hallucinated, total, supported) == (0, 1, 0)
    assert pts == 0.0 and rate == 0.0


def test_citation_regex_skips_truncated_fragment():
    assert _CITATION_RE.findall("proc-atk and proc-atkA-0001") == ["proc-atkA-0001"]


def test_report_quality_timeline_citation_credit():
    report = (
        "## Forensic Timeline Matrix\n"
        "| Timestamp (UTC) | Event ID |\n|---|---|\n"
        "| 2026-10-16T00:00:00Z | suri-20261016-0001 |\n"
        "| 2026-10-16T00:01:00Z | suri-20261016-0002 |\n"
    )
    without = report.replace("suri-20261016-0001", "unknown").replace("suri-20261016-0002", "unknown")

    assert _score_report_quality(report) - _score_report_quality(without) == 4.0


def test_calibration_uses_verdict_not_boundary():
    state = {"confidence": 0.9}
    assert _score_confidence_calibration(state, True, False, False)[0] == 9.6


def test_constant_half_confidence_is_worth_only_half_the_dimension():
    state = {"confidence": 0.5}
    assert _score_confidence_calibration(state, True, True, False)[0] == 0.0
    assert _score_confidence_calibration(state, False, False, False)[0] == 0.0


def test_empty_evidence_basis_scores_zero():
    assert _score_evidence_recall([], "anything") == (0.0, 0.0)


def test_weighted_evidence_checks_and_critical_failure():
    checks = [
        {"id": "a", "any_of": ["procdump", "lsass"], "weight": 1},
        {"id": "b", "any_of": ["smb"], "weight": 1},
        {"id": "c", "any_of": ["webshell"], "weight": 2, "critical": True},
    ]
    pts, coverage, results = _score_evidence_checks(checks, "procdump and smb were seen")
    assert round(pts, 1) == 10.0
    assert coverage == 0.5
    assert [r["passed"] for r in results] == [True, True, False]


def test_ioc_coverage_is_separate_from_narrative_checks():
    pts, ratio, covered = _score_ioc_coverage(["203.0.113.77", "UpdaterSvc2"], "Beacon to 203.0.113.77")
    assert round(pts, 1) == 2.5
    assert ratio == 0.5
    assert covered == ["203.0.113.77"]


def test_efficiency_does_not_reward_doing_nothing():
    assert _score_investigation_efficiency({"iteration_count": 0, "quality_metrics": {}}, False) == 0.0
    active = _score_investigation_efficiency(
        {"iteration_count": 3, "quality_metrics": {"total_tool_calls": 4, "duplicate_calls": 0}}, False
    )
    assert active == 10.0


def test_confusion_matrix_counts_ambiguous_errors():
    results = [
        {"expected_label": "malicious", "agent_verdict": "suspicious"},
        {"expected_label": "benign", "agent_verdict": "suspicious"},
        {"expected_label": "inconclusive", "agent_verdict": "malicious"},
        {"expected_label": "malicious", "agent_verdict": "malicious"},
    ]
    confusion = _confusion_metrics(results)
    matrix = confusion["matrix"]
    assert matrix["malicious"]["suspicious"] == 1
    assert matrix["benign"]["suspicious"] == 1
    assert matrix["inconclusive"]["malicious"] == 1
    assert 0.0 <= confusion["macro_f1"] <= 1.0
