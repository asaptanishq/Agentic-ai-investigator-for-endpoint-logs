"""Unit tests for conservative failure states across the investigation pipeline (Issue #4)."""
import pytest
from a1.nodes.report_node import _attempt_verdict_recovery
from a1.nodes.correlation_node import correlation_node
from a1.nodes.structured_output import StructuredOutputRetryError


def test_report_fallback_is_not_malicious():
    """Report synthesis failure must not claim malicious certainty."""
    result = _attempt_verdict_recovery("unparseable garbage", ["gap1"], {})
    assert result["verdict"] != "malicious"
    assert result["verdict"] in ("suspicious", "inconclusive")
    assert result["fallback_used"] is True


def test_report_fallback_with_correlations_is_suspicious():
    """When correlations exist, report recovery defaults to suspicious with unconfirmed_malicious."""
    state = {
        "confirmed_correlations": [{"description": "Correlated anomalous process spawned"}],
        "inconsistencies_or_benign_explanations": ["Admin script possible"],
    }
    result = _attempt_verdict_recovery("unparseable garbage", ["gap1"], state)
    assert result["verdict"] == "suspicious"
    assert result["verdict_boundary"] == "unconfirmed_malicious"
    assert result["confidence"] <= 0.65
    assert result["fallback_used"] is True


def test_report_fallback_without_correlations_is_inconclusive():
    """When no correlations exist and synthesis fails, report recovery returns inconclusive."""
    state = {
        "confirmed_correlations": [],
        "inconsistencies_or_benign_explanations": [],
    }
    result = _attempt_verdict_recovery("unparseable garbage", ["gap1"], state)
    assert result["verdict"] == "inconclusive"
    assert result["confidence"] <= 0.50
    assert result["fallback_used"] is True


def test_correlation_total_failure_returns_empty_confirmed(monkeypatch):
    """When correlation recovery fails and timeline is empty, confirmed correlations must be empty."""
    import sys
    import a1.nodes.correlation_node
    cn_module = sys.modules["a1.nodes.correlation_node"]

    class BrokenLLM:
        def with_structured_output(self, *args, **kwargs):
            return self
        def invoke(self, *args, **kwargs):
            raise RuntimeError("API failure")

    monkeypatch.setattr(cn_module, "get_llm", lambda: BrokenLLM())
    monkeypatch.setattr(
        cn_module,
        "invoke_structured_with_retry",
        lambda *args, **kwargs: (_ for _ in ()).throw(StructuredOutputRetryError(RuntimeError("first"), RuntimeError("retry"))),
    )

    state = {
        "messages": [],
        "evidence_pack": {"scoped_evidence": [], "timeline": []},
        "hypotheses": ["Test hypothesis"],
    }
    res = correlation_node(state)
    assert res["confirmed_correlations"] == []
    assert res["correlation_fallback_used"] is True
    assert any("Correlation analysis failed" in g for g in res["evidence_gaps"])
