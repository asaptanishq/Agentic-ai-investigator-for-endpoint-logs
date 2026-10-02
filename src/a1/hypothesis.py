"""Hypothesis lifecycle management for DFIR investigation."""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

MAX_ACTIVE_HYPOTHESES = 8
HYPOTHESIS_SIMILARITY_THRESHOLD = 0.6


class HypothesisStatus(str, Enum):
    ACTIVE = "active"
    SUPPORTED = "supported"
    WEAKLY_SUPPORTED = "weakly_supported"
    CONTRADICTED = "contradicted"
    UNRESOLVED = "unresolved"


@dataclass
class Hypothesis:
    id: str
    description: str
    status: HypothesisStatus = HypothesisStatus.ACTIVE
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    unresolved_questions: List[str] = field(default_factory=list)
    confidence: float = 0.5
    notes: List[str] = field(default_factory=list)
    provenance: str = ""
    triggering_evidence: List[str] = field(default_factory=list)
    source: str = "triage"
    created_at_iteration: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "status": self.status.value if isinstance(self.status, HypothesisStatus) else str(self.status),
            "supporting_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "missing_evidence": list(self.missing_evidence),
            "unresolved_questions": list(self.unresolved_questions),
            "confidence": self.confidence,
            "notes": list(self.notes),
            "provenance": self.provenance,
            "triggering_evidence": list(self.triggering_evidence),
            "source": self.source,
            "created_at_iteration": self.created_at_iteration,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Hypothesis:
        status_val = data.get("status", "active")
        try:
            status = HypothesisStatus(status_val)
        except ValueError:
            status = HypothesisStatus.ACTIVE

        return cls(
            id=str(data.get("id", str(uuid.uuid4())[:8])),
            description=str(data.get("description", "")),
            status=status,
            supporting_evidence=list(data.get("supporting_evidence", [])),
            contradicting_evidence=list(data.get("contradicting_evidence", [])),
            missing_evidence=list(data.get("missing_evidence", [])),
            unresolved_questions=list(data.get("unresolved_questions", [])),
            confidence=float(data.get("confidence", 0.5)),
            notes=list(data.get("notes", [])),
            provenance=str(data.get("provenance", "")),
            triggering_evidence=list(data.get("triggering_evidence", [])),
            source=str(data.get("source", "triage")),
            created_at_iteration=int(data.get("created_at_iteration", 0)),
        )


class HypothesisTracker:
    """Tracks and updates hypotheses across the investigation lifecycle."""

    def __init__(self):
        self.hypotheses: Dict[str, Hypothesis] = {}

    def add_hypothesis(self, description: str, hypothesis_id: Optional[str] = None) -> Hypothesis:
        if not hypothesis_id:
            idx = len(self.hypotheses) + 1
            hypothesis_id = f"H{idx}"
        
        hypo = Hypothesis(
            id=hypothesis_id,
            description=description,
            status=HypothesisStatus.ACTIVE,
            source="triage",
        )
        self.hypotheses[hypothesis_id] = hypo
        return hypo

    def add_dynamic_hypothesis(
        self,
        description: str,
        triggering_evidence: List[str],
        provenance: str,
        iteration: int,
    ) -> Optional[Hypothesis]:
        """Create a new hypothesis if:
        1. Concrete triggering evidence is provided
        2. Active count < MAX_ACTIVE_HYPOTHESES
        3. Not semantically duplicate of existing hypotheses
        Returns None if creation was suppressed."""
        if not triggering_evidence:
            return None
        if len(self.get_active()) >= MAX_ACTIVE_HYPOTHESES:
            return None
        if self._is_duplicate(description):
            return None

        idx = len(self.hypotheses) + 1
        hypo = Hypothesis(
            id=f"HD{idx}",
            description=description,
            status=HypothesisStatus.ACTIVE,
            provenance=provenance,
            triggering_evidence=list(triggering_evidence),
            source="dynamic",
            created_at_iteration=iteration,
        )
        self.hypotheses[hypo.id] = hypo
        return hypo

    def get_active(self) -> List[Hypothesis]:
        return [
            h for h in self.hypotheses.values()
            if h.status == HypothesisStatus.ACTIVE
        ]

    def _is_duplicate(self, description: str) -> bool:
        """Keyword-based deduplication. Compare normalized keyword sets."""
        new_kws = self._extract_keywords(description)
        if not new_kws:
            return False
        for h in self.hypotheses.values():
            existing_kws = self._extract_keywords(h.description)
            if not existing_kws:
                continue
            overlap = len(new_kws & existing_kws) / max(len(new_kws), len(existing_kws))
            if overlap >= HYPOTHESIS_SIMILARITY_THRESHOLD:
                return True
        return False

    @staticmethod
    def _extract_keywords(text: str) -> Set[str]:
        stop = {
            "the", "and", "for", "with", "from", "that", "this", "via", "into",
            "over", "under", "between", "through", "during", "before", "after",
            "above", "below", "to", "in", "on", "at", "by", "an", "a", "of"
        }
        words = set(re.findall(r"\b[a-z]{3,}\b", text.lower()))
        return words - stop

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        return self.hypotheses.get(hypothesis_id)

    def update_status(
        self,
        hypothesis_id: str,
        status: HypothesisStatus,
        evidence_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> None:
        hypo = self.hypotheses.get(hypothesis_id)
        if not hypo:
            return
        hypo.status = status
        if evidence_id:
            if status in (HypothesisStatus.SUPPORTED, HypothesisStatus.WEAKLY_SUPPORTED):
                if evidence_id not in hypo.supporting_evidence:
                    hypo.supporting_evidence.append(evidence_id)
            elif status == HypothesisStatus.CONTRADICTED:
                if evidence_id not in hypo.contradicting_evidence:
                    hypo.contradicting_evidence.append(evidence_id)
        if reason:
            hypo.notes.append(f"[{status.value}] {reason}")

    def add_supporting_evidence(self, hypothesis_id: str, evidence_id: str) -> None:
        hypo = self.hypotheses.get(hypothesis_id)
        if hypo and evidence_id not in hypo.supporting_evidence:
            hypo.supporting_evidence.append(evidence_id)

    def add_contradicting_evidence(self, hypothesis_id: str, evidence_id: str) -> None:
        hypo = self.hypotheses.get(hypothesis_id)
        if hypo and evidence_id not in hypo.contradicting_evidence:
            hypo.contradicting_evidence.append(evidence_id)

    def add_missing_evidence(self, hypothesis_id: str, missing_item: str) -> None:
        hypo = self.hypotheses.get(hypothesis_id)
        if hypo and missing_item not in hypo.missing_evidence:
            hypo.missing_evidence.append(missing_item)

    def get_unresolved(self) -> List[Hypothesis]:
        return [
            h for h in self.hypotheses.values()
            if h.status in (HypothesisStatus.ACTIVE, HypothesisStatus.UNRESOLVED)
        ]

    def get_evidence_gaps(self) -> List[Dict[str, Any]]:
        """Return gaps: missing evidence or unresolved questions across hypotheses."""
        gaps: List[Dict[str, Any]] = []
        for h in self.hypotheses.values():
            for m in h.missing_evidence:
                gaps.append({
                    "hypothesis_id": h.id,
                    "type": "missing_evidence",
                    "description": m,
                })
            for q in h.unresolved_questions:
                gaps.append({
                    "hypothesis_id": h.id,
                    "type": "unresolved_question",
                    "description": q,
                })
            if h.status in (HypothesisStatus.ACTIVE, HypothesisStatus.UNRESOLVED):
                gaps.append({
                    "hypothesis_id": h.id,
                    "type": "untested_hypothesis",
                    "description": f"Hypothesis '{h.description}' has no definitive supporting or contradicting evidence.",
                })
        return gaps

    def get_all(self) -> List[Hypothesis]:
        return list(self.hypotheses.values())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypotheses": {k: v.to_dict() for k, v in self.hypotheses.items()}
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HypothesisTracker:
        tracker = cls()
        if not data:
            return tracker
        hypo_dict = data.get("hypotheses", {})
        for hid, hdata in hypo_dict.items():
            tracker.hypotheses[hid] = Hypothesis.from_dict(hdata)
        return tracker
