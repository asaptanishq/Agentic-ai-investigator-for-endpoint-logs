"""Unit tests for ExperimentRunner (Issues #14, #15, #18)."""
import json
import pytest
from pathlib import Path
from a1.experiment import ExperimentRunner, ExperimentConfig


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


def test_experiment_runner_live_mode_execution(tmp_path, monkeypatch):
    runner = ExperimentRunner(output_dir=tmp_path)
    config = ExperimentConfig(name="LiveTest")

    # Mock the graph stream to return a realistic final state without making remote network calls
    class FakeApp:
        def stream(self, initial_state, stream_mode="values"):
            yield {
                "verdict": "malicious",
                "verdict_boundary": "confirmed_malicious",
                "report_fallback_used": False,
                "iteration_count": 3,
                "repeat_nudges": 0,
                "messages": [{"content": "## Verdict: malicious\nCiting evt-exp-001 proc-exp-001"}],
                "investigation_memory": {},
            }

    monkeypatch.setattr("a1.graph.create_investigation_graph", lambda: FakeApp())
    res = runner.evaluate_configuration(config, cases=["ATK-A"], mock_mode=False)

    assert res["cases_evaluated"] == 1
    assert "composite_score" in res["results"][0]["rubric"]
    assert res["results"][0]["rubric"]["verdict_score"] == 20.0

