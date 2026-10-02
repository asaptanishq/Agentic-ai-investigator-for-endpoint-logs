"""Unit tests for ExperimentRunner and InvestigationTrace (Issues #14, #15, #18)."""
import json
import pytest
from pathlib import Path
from a1.investigation_trace import InvestigationTrace, TraceStep
from a1.experiment import ExperimentRunner, ExperimentConfig


def test_investigation_trace_serialization_and_replay(tmp_path):
    trace = InvestigationTrace(
        initial_alert="Suspicious PowerShell spawned procdump",
        model_config={"model": "gemma4:31b", "provider": "ollama"},
        hypotheses=[{"id": "H1", "description": "Credential dumping", "status": "supported"}],
        steps=[
            TraceStep(
                step_number=1,
                objective="Find parent and child processes",
                tool_name="find_process_relationships",
                tool_args={"host_id": "WS-OPS-01", "child_process_name": "procdump.exe"},
                result_summary="Found procdump.exe spawned by powershell.exe",
                evidence_graph_nodes=2,
                evidence_graph_edges=1,
                hypothesis_addressed="H1",
            )
        ],
        final_verdict="malicious",
        final_boundary="confirmed_malicious",
        final_report="# DFIR Incident Investigation Report\n\n## Verdict: MALICIOUS",
        validation_results={"validation_passed": True, "event_ids_valid": ["evt-001"]},
    )

    trace_file = tmp_path / "test_trace.json"
    trace.save(trace_file)
    assert trace_file.exists()

    loaded = InvestigationTrace.load(trace_file)
    assert loaded.initial_alert == trace.initial_alert
    assert len(loaded.steps) == 1
    assert loaded.steps[0].tool_name == "find_process_relationships"

    replay_out = loaded.replay()
    assert replay_out["status"] == "replayed_successfully"
    assert replay_out["replayed_verdict"] == "malicious"
    assert replay_out["total_steps"] == 1


def test_experiment_runner_ab_comparison_and_ablation(tmp_path):
    runner = ExperimentRunner(output_dir=tmp_path)

    config_baseline = ExperimentConfig(
        name="Baseline",
        enable_evidence_graph=False,
        enable_adaptive_planner=False,
        enable_validator=False,
    )
    config_improved = ExperimentConfig(
        name="Improved",
        enable_evidence_graph=True,
        enable_adaptive_planner=True,
        enable_validator=True,
    )

    # Test A/B comparison across benchmark cases
    ab_result = runner.run_comparison(
        config_baseline,
        config_improved,
        cases=["ATK-A", "BEN-A", "INC-A"],
        mock_mode=True,
    )
    assert "score_delta" in ab_result
    assert ab_result["improved"]["average_composite_score"] >= ab_result["baseline"]["average_composite_score"]
    assert (tmp_path / "ab_comparison_results.json").exists()

    # Test 5-stage ablation study
    ablation_result = runner.run_ablation(
        cases=["ATK-A", "BEN-A"],
        mock_mode=True,
    )
    assert len(ablation_result["stages"]) == 5
    assert (tmp_path / "ablation_study_results.json").exists()
