"""Adaptive investigation planning helpers.

Provides generate_candidate_actions/score_actions, consumed directly by
investigator_node for goal-backward planning and budget allocation.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from a1.evidence_graph import EvidenceGraph
from a1.hypothesis import HypothesisTracker, HypothesisStatus

logger = logging.getLogger(__name__)


def generate_candidate_actions(
    evidence_graph: EvidenceGraph,
    tracker: HypothesisTracker,
    budget_remaining: int,
    recent_tools: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Generate potential investigative actions based on gaps in hypotheses and graph boundaries."""
    candidates: List[Dict[str, Any]] = []
    recent = recent_tools or []

    # 1. Look for unresolved hypotheses
    unresolved = tracker.get_unresolved()
    for h in unresolved:
        # Check missing evidence
        for missing in h.missing_evidence:
            candidates.append({
                "hypothesis_id": h.id,
                "objective": f"Resolve missing evidence for hypothesis {h.id}: {missing}",
                "tool": "query_telemetry",
                "evidence_sought": missing,
                "reason": f"Hypothesis {h.id} status is {h.status.value}; missing verification for {missing}",
                "expected_gain": 0.85,
            })

    # 2. Look for entities in evidence graph that lack child/parent or network pivots
    # e.g., processes with no network activity checked, or hosts with no auth checked
    untraced_procs = [
        eid for eid, ent in evidence_graph.entities.items()
        if ent.entity_type.value == "process" and not evidence_graph.get_entity_edges(eid)
    ]
    for pid in untraced_procs[:3]:
        candidates.append({
            "hypothesis_id": unresolved[0].id if unresolved else "General",
            "objective": f"Trace process relationships for {pid}",
            "tool": "find_process_relationships",
            "evidence_sought": f"Parent and child processes of {pid}",
            "reason": f"Entity {pid} has no explored graph edges",
            "expected_gain": 0.75,
        })

    # 3. If timeline has gaps or temporal anomalies
    anomalies = evidence_graph.detect_temporal_anomalies()
    for anom in anomalies[:2]:
        candidates.append({
            "hypothesis_id": unresolved[0].id if unresolved else "General",
            "objective": f"Investigate temporal anomaly: {anom.get('type')}",
            "tool": "search_timeline",
            "evidence_sought": f"Events around anomaly entities: {anom.get('entities')}",
            "reason": f"Detected temporal ordering conflict: {anom.get('description')}",
            "expected_gain": 0.90,
        })

    # 4. Fallback candidate if no specific gaps
    if not candidates:
        candidates.append({
            "hypothesis_id": unresolved[0].id if unresolved else "General",
            "objective": "Broad correlation and timeline exploration",
            "tool": "search_timeline",
            "evidence_sought": "Sequence of events across all identified hosts",
            "reason": "Ensure complete timeline coverage before reaching verdict",
            "expected_gain": 0.50,
        })

    # Deduplicate against very recent identical tool calls if budget is tight
    for cand in candidates:
        penalty = 0.2 if cand["tool"] in recent[-2:] else 0.0
        cand["score"] = max(0.1, cand["expected_gain"] - penalty)

    candidates.sort(key=lambda x: x["score"], reverse=True)
    return candidates


def score_actions(candidates: List[Dict[str, Any]], budget_remaining: int) -> List[Dict[str, Any]]:
    """Score candidate actions taking budget remaining into account."""
    for cand in candidates:
        base_score = cand.get("score", 0.5)
        # When budget is low (<= 3 steps left), prioritize high-yield verification over broad searches
        if budget_remaining <= 3:
            if cand.get("tool") in ("find_process_relationships", "get_entity_context"):
                cand["budget_adjusted_score"] = base_score * 1.2
            else:
                cand["budget_adjusted_score"] = base_score * 0.9
        else:
            cand["budget_adjusted_score"] = base_score
    candidates.sort(key=lambda x: x.get("budget_adjusted_score", 0), reverse=True)
    return candidates
