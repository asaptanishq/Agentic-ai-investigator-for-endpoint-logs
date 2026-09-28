import importlib

from a1.nodes.report_node import (
    _confirmed_credential_lateral_service_chain,
    _confirmed_data_exfiltration_chain,
    _post_cleanup_interactive_logon_pair,
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


def test_confirmed_data_exfiltration_chain_requires_correlated_stages():
    timeline = [
        {"event_id": "evt-cmd", "timestamp": "2026-09-11T10:06:00Z", "host_id": "host-a", "process_entity_id": "proc-7z", "raw": {"action": "process_started", "host_id": "host-a", "process_entity_id": "proc-7z", "details": {"name": "7z.exe", "command_line": "7z.exe a -psecret stage.7z"}}},
        {"event_id": "evt-create", "timestamp": "2026-09-11T10:09:00Z", "host_id": "host-a", "process_entity_id": "proc-7z", "raw": {"action": "file_created", "host_id": "host-a", "process_entity_id": "proc-7z", "details": {"name": "7z.exe", "file_name": "stage.7z", "file_path": "C:\\Temp\\stage.7z"}}},
        {"event_id": "evt-task", "timestamp": "2026-09-11T10:16:30Z", "host_id": "host-a", "process_entity_id": "proc-task", "raw": {"action": "process_started", "host_id": "host-a", "process_entity_id": "proc-task", "details": {"name": "schtasks.exe", "command_line": "schtasks.exe /create /tn OneDriveSync"}}},
        {"event_id": "evt-net-1", "timestamp": "2026-09-11T10:25:00Z", "host_id": "host-a", "process_entity_id": "proc-ps", "raw": {"action": "network_connection", "host_id": "host-a", "process_entity_id": "proc-ps", "details": {"destination_ip": "203.0.113.77", "source_ip": "10.0.0.1"}}},
        {"event_id": "evt-net-2", "timestamp": "2026-09-11T10:31:00Z", "host_id": "host-a", "process_entity_id": "proc-ps", "raw": {"action": "network_connection", "host_id": "host-a", "process_entity_id": "proc-ps", "details": {"destination_ip": "203.0.113.77", "source_ip": "10.0.0.1"}}},
        {"event_id": "evt-net-3", "timestamp": "2026-09-11T10:37:00Z", "host_id": "host-a", "process_entity_id": "proc-ps", "raw": {"action": "network_connection", "host_id": "host-a", "process_entity_id": "proc-ps", "details": {"destination_ip": "203.0.113.77", "source_ip": "10.0.0.1"}}},
        {"event_id": "evt-delete", "timestamp": "2026-09-11T11:02:00Z", "host_id": "host-a", "process_entity_id": "proc-ps", "raw": {"action": "file_deleted", "host_id": "host-a", "process_entity_id": "proc-ps", "details": {"file_name": "stage.7z", "file_path": "C:\\Temp\\stage.7z"}}},
    ]

    evidence = _confirmed_data_exfiltration_chain({"timeline": timeline})

    assert evidence["archive_creation_id"] == "evt-create"
    assert evidence["task_event_ids"] == ["evt-task"]
    assert evidence["network_event_ids"] == ["evt-net-1", "evt-net-2", "evt-net-3"]
    assert evidence["deletion_id"] == "evt-delete"
    assert _confirmed_data_exfiltration_chain({"timeline": timeline[:-1]}) is None

    without_command = _confirmed_data_exfiltration_chain({"timeline": timeline[1:]})

    assert without_command["archive_staging_id"] == "evt-create"
    assert without_command["archive_command_id"] == ""
    assert without_command["password_protected"] is False


def test_confirmed_credential_lateral_service_chain_requires_linked_stages():
    def event(event_id, timestamp, host_id, action, process_id, **details):
        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "host_id": host_id,
            "action": action,
            "process_entity_id": process_id,
            "raw": {"details": details},
        }

    timeline = [
        event("evt-ps", "2026-09-10T09:12:00Z", "host-a01", "process_started", "proc-ps", name="powershell.exe"),
        event(
            "evt-procdump", "2026-09-10T09:13:00Z", "host-a01", "process_started", "proc-dump",
            name="procdump.exe", command_line="procdump.exe -ma lsass.exe lsass.dmp",
            parent_process_entity_id="proc-ps", parent_process_name="powershell.exe",
        ),
        event("evt-access", "2026-09-10T09:13:22Z", "host-a01", "process_accessed", "proc-dump", event_code="10", target_process_name="lsass.exe"),
        event("evt-dump", "2026-09-10T09:14:00Z", "host-a01", "file_created", "proc-dump", file_name="lsass.dmp"),
        event("evt-smb", "2026-09-10T09:31:00Z", "host-a01", "network_connection", "proc-ps", name="powershell.exe", source_ip="10.10.2.20", destination_ip="10.10.2.30", destination_port=445),
        event("evt-fail-1", "2026-09-10T09:32:00Z", "host-a02", "logon_failed", "", source_ip="10.10.2.20", destination_ip="10.10.2.30", destination_port=445, authentication_package="NTLM", logon_type=3, user_name="jdoe", user_domain="CORP"),
        event("evt-fail-2", "2026-09-10T09:33:00Z", "host-a02", "logon_failed", "", source_ip="10.10.2.20", destination_ip="10.10.2.30", destination_port=445, authentication_package="NTLM", logon_type=3, user_name="jdoe", user_domain="CORP"),
        event("evt-success", "2026-09-10T09:36:00Z", "host-a02", "logon_success", "", source_ip="10.10.2.20", destination_ip="10.10.2.30", destination_port=445, authentication_package="NTLM", logon_type=3, user_name="jdoe", user_domain="CORP"),
        event("evt-drop", "2026-09-10T09:40:15Z", "host-a02", "file_created", "proc-sc", file_path="C:\\Windows\\Temp\\updatersvc2.exe"),
        event("evt-imagepath", "2026-09-10T09:40:30Z", "host-a02", "registry_value_set", "proc-sc", registry_path="HKLM\\SYSTEM\\CurrentControlSet\\Services\\UpdaterSvc2", registry_key="ImagePath", registry_value="C:\\Windows\\Temp\\updatersvc2.exe"),
        event("evt-service", "2026-09-10T09:41:00Z", "host-a02", "process_started", "proc-service", executable="C:\\Windows\\Temp\\updatersvc2.exe", parent_process_name="services.exe", integrity_level="system"),
    ]

    evidence = _confirmed_credential_lateral_service_chain({"timeline": timeline})

    assert evidence["source_process_id"] == "proc-ps"
    assert evidence["user_name"] == "CORP\\jdoe"
    assert evidence["failure_event_ids"] == ["evt-fail-1", "evt-fail-2"]
    assert evidence["service_registry_event_id"] == "evt-imagepath"
    assert evidence["service_execution_event_id"] == "evt-service"
    assert _confirmed_credential_lateral_service_chain({"timeline": timeline[:1] + timeline[2:]}) is None
    assert _confirmed_credential_lateral_service_chain({"timeline": timeline[:-3]}) is None


def test_report_confirms_correlated_lateral_chain_over_model_verdict(monkeypatch):
    chain = {
        "source_process_id": "proc-ps",
        "credential_process_id": "proc-dump",
        "service_process_id": "proc-sc",
        "source_host_id": "host-a01",
        "target_host_id": "host-a02",
        "user_name": "CORP\\jdoe",
        "service_name": "UpdaterSvc2",
        "service_path": "C:\\Windows\\Temp\\updatersvc2.exe",
        "service_signature_status": "",
        "procdump_event_id": "evt-procdump",
        "lsass_access_event_id": "evt-access",
        "dump_file_event_id": "evt-dump",
        "smb_event_ids": ["evt-smb"],
        "failure_event_ids": ["evt-fail-1", "evt-fail-2"],
        "success_event_id": "evt-success",
        "service_file_event_id": "evt-drop",
        "service_registry_event_id": "evt-imagepath",
        "service_execution_event_id": "evt-service",
    }

    class FakeStructuredLLM:
        def invoke(self, messages):
            return IncidentVerdict(
                verdict="suspicious",
                verdict_boundary="unconfirmed_malicious",
                executive_summary="The model undercalled this chain.",
                investigation_reasoning="The model response is deliberately conservative.",
                evidence_gaps=[
                    "Missing parent process for proc-dump; cannot confirm its parent.",
                    "Missing parent process for proc-sc; the service creation initiator is unknown.",
                ],
            )

    class FakeLLM:
        def with_structured_output(self, schema):
            return FakeStructuredLLM()

    monkeypatch.setattr(report_module, "get_llm", lambda: FakeLLM())
    monkeypatch.setattr(
        report_module,
        "_confirmed_credential_lateral_service_chain",
        lambda evidence_pack: chain,
    )
    event_ids = [
        "evt-procdump", "evt-access", "evt-dump", "evt-smb", "evt-fail-1",
        "evt-fail-2", "evt-success", "evt-drop", "evt-imagepath", "evt-service",
    ]
    state = {
        "evidence_pack": {
            "timeline": [
                {"event_id": event_id, "timestamp": "2026-09-10T09:00:00Z"}
                for event_id in event_ids
            ],
            "entity_set": {"processes": ["proc-ps", "proc-dump", "proc-sc"]},
        },
        "enriched_alert": {},
        "hypotheses": [],
    }

    result = report_module.report_node(state)
    report = result["messages"][0].content

    assert result["verdict"] == "malicious"
    assert result["verdict_boundary"] == "confirmed_malicious"
    assert "Missing parent process for proc-dump" not in report
    assert "Missing parent process for proc-sc" in report
    assert "Corroborated credential-theft and lateral-movement chain" in report
    assert "unsigned status is not independently verified" in report


def test_post_cleanup_interactive_logon_pair_is_separately_identified():
    evidence_pack = {
        "timeline": [
            {"event_id": "evt-morning-fail", "timestamp": "2026-09-11T11:36:40Z", "host_id": "host-a", "action": "logon_failed", "user_id": "user-a", "details": {"user_name": "dev02", "logon_type": 2, "authentication_package": "Kerberos"}},
            {"event_id": "evt-morning-success", "timestamp": "2026-09-11T11:36:42Z", "host_id": "host-a", "action": "logon_success", "user_id": "user-a", "details": {"user_name": "dev02", "logon_type": 2, "authentication_package": "Kerberos"}},
            {"event_id": "evt-fail", "timestamp": "2026-09-11T12:56:27Z", "host_id": "host-a", "action": "logon_failed", "user_id": "user-a", "details": {"user_name": "dev02", "logon_type": 2, "authentication_package": "Kerberos"}},
            {"event_id": "evt-success", "timestamp": "2026-09-11T13:07:13Z", "host_id": "host-a", "action": "logon_success", "user_id": "user-a", "details": {"user_name": "dev02", "logon_type": 2, "authentication_package": "Kerberos"}},
        ]
    }

    pair = _post_cleanup_interactive_logon_pair(evidence_pack, "2026-09-11T11:02:00Z")

    assert pair[0]["event_id"] == "evt-fail"
    assert pair[1]["event_id"] == "evt-success"
    assert _post_cleanup_interactive_logon_pair(evidence_pack, "2026-09-11T13:00:00Z") is None


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