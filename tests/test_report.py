import importlib

from a1.nodes.report_node import (
    IncidentVerdict,
    _remove_contradicted_timestamp_gaps,
    _sanitize_unverified_citations,
    _sanitize_unverified_paths,
    _unsupported_citations,
    _validation_warnings,
)
report_module = importlib.import_module("a1.nodes.report_node")
from a1.nodes.triage_node import TriagePlan
from a1.nodes.correlation_node import CorrelationAndGapAnalysis


def _verdict(confidence):
    return IncidentVerdict(
        verdict="suspicious",
        verdict_boundary="unconfirmed_malicious",
        confidence=confidence,
        executive_summary="summary",
        attack_chain=[],
        evidence_basis=[],
        benign_explanations_considered=[],
        evidence_gaps=[],
        recommended_next_steps=[],
    )


def test_incident_verdict_accepts_normalized_confidence():
    assert _verdict(0.7).confidence == 0.7


def test_incident_verdict_normalizes_percentage_confidence():
    assert _verdict(70).confidence == 0.7
    assert _verdict("70%").confidence == 0.7


def test_report_validation_warnings_surface_incomplete_analysis():
    evidence_pack = {
        "input_reflection_checks": {
            "hostnames_resolved": True,
            "time_window_sane": True,
            "time_scope_respected": True,
            "hypotheses_covered": False,
        }
    }
    state = {"triage_fallback_used": True, "correlation_retry_used": True}

    warnings = _validation_warnings(state, evidence_pack)

    assert any("keyword overlap is heuristic only" in warning for warning in warnings)
    assert any("Triage used a fallback" in warning for warning in warnings)
    assert any("Correlation required" in warning for warning in warnings)


def test_report_flags_citations_outside_scoped_evidence():
    evidence_pack = {
        "timeline": [{"event_id": "evt-1"}],
        "entity_set": {"processes": ["proc-1", "powershell.exe"]},
    }

    unsupported = _unsupported_citations(["evt-1 proc-1 evt-not-in-pack proc-not-in-pack corr-04"], evidence_pack)

    assert unsupported == ["corr-04", "evt-not-in-pack", "proc-not-in-pack"]


def test_report_redacts_unverified_correlation_reference():
    evidence_pack = {"timeline": [{"event_id": "evt-1"}]}

    sanitized, unsupported = _sanitize_unverified_citations("Supported by corr-04 and evt-1.", evidence_pack)

    assert sanitized == "Supported by [unverified reference omitted] and evt-1."
    assert unsupported == ["corr-04"]


def test_triage_plan_normalizes_json_object_and_list_shapes():
    plan = TriagePlan(
        hypotheses=[{"type": "Suspicious", "description": "Investigate process execution."}],
        initial_entities={"hosts": ["host-a01"], "users": [], "processes": [], "files": []},
        investigation_plan=[{"step": 1, "target": "Process", "action": "Review events."}],
    )

    assert plan.hypotheses == ["Investigate process execution."]
    assert plan.initial_entities == ["host-a01"]
    assert "Review events" in plan.investigation_plan


def test_correlation_and_report_normalize_structured_list_items():
    analysis = CorrelationAndGapAnalysis(confirmed_correlations=[{"event_id": "evt-1"}])
    report = IncidentVerdict(
        verdict="MALICIOUS",
        investigation_reasoning=["Observed process execution.", "Observed lateral movement."],
        attack_chain=[{"event_id": "evt-1", "action": "process started"}],
    )

    assert "evt-1" in analysis.confirmed_correlations[0]
    assert report.verdict == "malicious"
    assert "Observed lateral movement" in report.investigation_reasoning
    assert "evt-1" in report.attack_chain[0]


def test_report_omits_paths_not_present_in_scoped_evidence():
    evidence_pack = {"timeline": [{"raw": {"details": {"file_path": "C:\\Windows\\Temp\\updatersvc2.exe"}}}]}

    sanitized, unsupported = _sanitize_unverified_paths(
        "Observed `C:\\Windows\\Temp\\updatersv` during service setup.", evidence_pack
    )

    assert "C:\\Windows\\Temp\\updatersv" not in sanitized
    assert "`" not in sanitized
    assert unsupported == ["C:\\Windows\\Temp\\updatersv"]


def test_report_removes_missing_timestamp_claims_contradicted_by_timeline():
    evidence_pack = {"timeline": [{"event_id": "evt-1", "timestamp": "2026-09-10T09:14:15Z"}]}

    remaining, removed = _remove_contradicted_timestamp_gaps(
        ["Missing timestamp for evt-1"], evidence_pack
    )

    assert remaining == []
    assert removed == ["Missing timestamp for evt-1"]

def test_incident_verdict_handles_leaked_control_tokens():
    # Model returns raw closing channel token
    verdict1 = IncidentVerdict(verdict="<channel|>", verdict_boundary="<channel|>")
    assert verdict1.verdict == "suspicious"
    assert verdict1.verdict_boundary == "unconfirmed_malicious"

    # Model returns channel token prepended to genuine verdict
    verdict2 = IncidentVerdict(
        verdict="<channel|>malicious",
        verdict_boundary="<channel|>confirmed_malicious",
        executive_summary="<|channel>thought internal reasoning<channel|> Summary text",
        evidence_basis=["<channel|> evt-001 procdump execution"]
    )
    assert verdict2.verdict == "malicious"
    assert verdict2.verdict_boundary == "confirmed_malicious"
    assert "<channel|>" not in verdict2.executive_summary
    assert "<channel|>" not in verdict2.evidence_basis[0]


def test_evaluate_case_rubric_scoring():
    """Verify that evaluate_case_rubric calculates correct multi-dimensional points."""
    from a1.benchmark import evaluate_case_rubric
    from langchain_core.messages import AIMessage

    mock_case = {
        "case_label": "malicious",
        "verdict_boundary": "confirmed_malicious",
        "evidence_basis": ["powershell.exe", "lsass.dmp", "procdump.exe"]
    }

    from a1.db import EndpointDatabase
    db = EndpointDatabase()
    real_eid_row = db.execute_query("SELECT event_id FROM events LIMIT 1")
    real_pid_row = db.execute_query("SELECT process_entity_id FROM processes LIMIT 1")
    real_eid = real_eid_row[0]["event_id"] if real_eid_row else "evt-dummy"
    real_pid = real_pid_row[0]["process_entity_id"] if real_pid_row else "proc-dummy"

    grounded_report = f"""# DFIR Incident Investigation Report
## Verdict: MALICIOUS (confirmed_malicious)
## Executive Summary
Observed powershell.exe executing procdump.exe creating lsass.dmp.

## Forensic Timeline Matrix
| Timestamp | Host | Process | Action | Event ID |
| 2026-09-10T09:00:00Z | host-a01 | powershell.exe | start | {real_eid} |

## Indicator of Compromise (IOC) Matrix
| Artifact | Type | Value | Status |
| procdump.exe | Process | {real_pid} | Malicious |

## Next Steps & Playbook
1. Isolate endpoint host-a01 immediately.
"""

    mock_state = {
        "verdict": "malicious",
        "verdict_boundary": "confirmed_malicious",
        "report_fallback_used": False,
        "iteration_count": 3,
        "repeat_nudges": 0,
        "messages": [AIMessage(content=grounded_report)],
        "investigation_memory": {
            "discovered_processes": {real_pid: {"process_name": "procdump.exe"}},
            "discovered_hosts": ["host-a01"],
        }
    }

    rubric = evaluate_case_rubric(mock_case, mock_state)
    assert rubric["verdict_score"] == 20.0
    assert rubric["recall_score"] == 30.0
    assert rubric["grounding_score"] == 25.0
    assert rubric["efficiency_score"] == 15.0
    assert rubric["report_score"] == 10.0
    assert rubric["composite_score"] == 100.0
    assert "A+" in rubric["grade"]


