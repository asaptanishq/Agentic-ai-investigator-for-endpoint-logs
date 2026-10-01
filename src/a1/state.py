from typing import TypedDict, List, Optional, Dict, Annotated, Any
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage

class InvestigationState(TypedDict):
    messages: Annotated[List[BaseMessage], add_messages]
    hypotheses: List[str]
    active_hypothesis: Optional[str]
    hypothesis_status: Optional[Dict[str, str]]
    iteration_count: int
    alert_context: str
    confirmed_correlations: Optional[List[dict]]
    inconsistencies_or_benign_explanations: Optional[List[str]]
    evidence_gaps: Optional[List[str]]
    verdict: Optional[str]
    verdict_boundary: Optional[str]
    confidence: Optional[float]
    report: Optional[str]
    # FIX: tracks whether report_node fell back to its hardcoded verdict after a
    # structured-output failure. benchmark.py counts fallback runs as automatic
    # FAILs so a lucky fallback can never score points.
    report_fallback_used: Optional[bool]
    triage_fallback_used: Optional[bool]
    triage_retry_used: Optional[bool]
    correlation_fallback_used: Optional[bool]
    correlation_retry_used: Optional[bool]
    report_retry_used: Optional[bool]
    # FIX: counts "you already tried that" nudges injected by the investigator
    # repetition guard. should_continue uses it as a circuit breaker so a model
    # stuck re-issuing identical tool calls is forced to correlation instead of
    # looping until MAX_INVESTIGATION_STEPS.
    repeat_nudges: int
    lateral_network_nudge_sent: Optional[bool]
    requested_auth_nudge_sent: Optional[bool]
    requested_archive_nudge_sent: Optional[bool]
    evidence: Optional[List[dict]]
    enriched_alert: Optional[Dict[str, Any]]
    evidence_pack: Optional[Dict[str, Any]]
    input_reflection_status: Optional[Dict[str, Any]]
    # Accumulated investigation working memory persisting extracted entities across iterations
    investigation_memory: Optional[Dict[str, Any]]

