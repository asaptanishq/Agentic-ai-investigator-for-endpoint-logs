"""Investigation trace recording, serialization, and deterministic replay (Issue #18)."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TraceStep:
    step_number: int
    objective: str
    tool_name: str
    tool_args: Dict[str, Any]
    result_summary: str
    evidence_graph_nodes: int = 0
    evidence_graph_edges: int = 0
    hypothesis_addressed: Optional[str] = None


@dataclass
class InvestigationTrace:
    initial_alert: str
    model_config: Dict[str, Any]
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    steps: List[TraceStep] = field(default_factory=list)
    final_verdict: Optional[str] = None
    final_boundary: Optional[str] = None
    final_report: Optional[str] = None
    validation_results: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "initial_alert": self.initial_alert,
            "model_config": self.model_config,
            "hypotheses": self.hypotheses,
            "steps": [asdict(s) for s in self.steps],
            "final_verdict": self.final_verdict,
            "final_boundary": self.final_boundary,
            "final_report": self.final_report,
            "validation_results": self.validation_results,
            "metadata": self.metadata,
        }

    def save(self, filepath: Path | str) -> None:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        logger.info("Saved investigation trace to %s", path)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InvestigationTrace:
        steps = [
            TraceStep(
                step_number=s.get("step_number", i + 1),
                objective=s.get("objective", ""),
                tool_name=s.get("tool_name", ""),
                tool_args=dict(s.get("tool_args", {})),
                result_summary=s.get("result_summary", ""),
                evidence_graph_nodes=s.get("evidence_graph_nodes", 0),
                evidence_graph_edges=s.get("evidence_graph_edges", 0),
                hypothesis_addressed=s.get("hypothesis_addressed"),
            )
            for i, s in enumerate(data.get("steps", []))
        ]
        return cls(
            initial_alert=data.get("initial_alert", ""),
            model_config=dict(data.get("model_config", {})),
            hypotheses=list(data.get("hypotheses", [])),
            steps=steps,
            final_verdict=data.get("final_verdict"),
            final_boundary=data.get("final_boundary"),
            final_report=data.get("final_report"),
            validation_results=data.get("validation_results"),
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def load(cls, filepath: Path | str) -> InvestigationTrace:
        path = Path(filepath)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

    def replay(self) -> Dict[str, Any]:
        """Deterministically replay the trace without invoking the LLM."""
        timeline_reconstructed = []

        for step in self.steps:
            timeline_reconstructed.append({
                "step": step.step_number,
                "tool": step.tool_name,
                "objective": step.objective,
                "hypothesis": step.hypothesis_addressed,
            })

        return {
            "status": "replayed_successfully",
            "total_steps": len(self.steps),
            "replayed_verdict": self.final_verdict,
            "replayed_boundary": self.final_boundary,
            "validation_results": self.validation_results,
            "steps_summary": timeline_reconstructed,
        }
