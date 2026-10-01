import json
import re
from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel, Field, field_validator
from typing import List, Literal

from a1.llm import get_llm
from a1.prompts import CORRELATION_SYSTEM_PROMPT
from a1.nodes.structured_output import StructuredOutputRetryError, invoke_structured_with_retry, extract_outer_json

class CorrelationAndGapAnalysis(BaseModel):
    confirmed_correlations: List[str] = Field(default_factory=list, description="Confirmed process/event correlations")
    relationship_types: List[str] = Field(
        default_factory=list,
        description="Type of each confirmed correlation (process_parent_child or event_process_association)"
    )
    evidence_gaps: List[str] = Field(default_factory=list, description="Identified evidence gaps and missing telemetry")
    inconsistencies_or_benign_explanations: List[str] = Field(default_factory=list, description="Inconsistencies or benign explanations")

    @field_validator("confirmed_correlations", "relationship_types", "evidence_gaps", "inconsistencies_or_benign_explanations", mode="before")
    @classmethod
    def normalize_list_items(cls, value):
        if value is None:
            return []
        values = value if isinstance(value, list) else [value]
        return [json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item) for item in values]


def _extract_correlation_from_markdown(text: str) -> dict | None:
    sections = {"confirmed": [], "gaps": [], "benign": []}
    curr = None
    for line in text.splitlines():
        line_s = line.strip()
        line_l = line_s.lower()
        if any(h in line_l for h in ("1. confirmed", "confirmed correlation", "confirmed evidence", "attack chain", "malicious activity")):
            curr = "confirmed"
            continue
        elif any(h in line_l for h in ("2. evidence gap", "evidence gap", "missing telemetry", "information gap")):
            curr = "gaps"
            continue
        elif any(h in line_l for h in ("3. benign", "inconsistenc", "alternative explanation")):
            curr = "benign"
            continue
        elif line_l.startswith("### 4") or "troubleshooting" in line_l:
            curr = None
            continue

        if curr and line_s.startswith(("-", "*", "•", "1.", "2.", "3.", "4.", "5.")):
            item = line_s.lstrip("-*•0123456789. )").strip()
            if len(item) > 5:
                sections[curr].append(item)

    if sections["confirmed"] or sections["gaps"] or sections["benign"]:
        return {
            "confirmed_correlations": sections["confirmed"],
            "evidence_gaps": sections["gaps"],
            "inconsistencies_or_benign_explanations": sections["benign"],
        }
    return None


def correlation_node(state):
    llm = get_llm()
    structured_llm = llm.with_structured_output(CorrelationAndGapAnalysis)

    # Primary Input: Structured Evidence Pack from Evidence Packing node
    evidence_pack = state.get("evidence_pack") or {}
    evidence_pack_str = json.dumps(evidence_pack, indent=2) if evidence_pack else "(Structured evidence pack unavailable)"

    # Secondary Context: Raw message trail (last 20 messages to keep context concise)
    recent_messages = state["messages"][-20:]
    trail_parts = []
    for msg in recent_messages:
        role = getattr(msg, "type", "unknown")
        content = str(getattr(msg, "content", ""))[:1000]
        tool_calls = getattr(msg, "tool_calls", None)
        if tool_calls:
            calls_str = "; ".join(f"{c.get('name')}({c.get('args')})" for c in tool_calls)
            trail_parts.append(f"[{role} tool_call] {calls_str}")
            if content.strip():
                trail_parts.append(f"[{role}] {content}")
        elif getattr(msg, "name", None):
            trail_parts.append(f"[{role} ({msg.name})] {content}")
        else:
            trail_parts.append(f"[{role}] {content}")
    trail = "\n\n".join(trail_parts)

    hypos = state.get("hypotheses", [])
    hypos_str = "\n".join(f"- {h}" for h in hypos) if hypos else "- (none recorded)"
    retry_used = False
    fallback_used = False

    try:
        response, retry_used = invoke_structured_with_retry(structured_llm, [
            SystemMessage(content=CORRELATION_SYSTEM_PROMPT),
            HumanMessage(content=(
                f"=== PRIMARY INPUT: STRUCTURED EVIDENCE PACK ===\n{evidence_pack_str}\n\n"
                f"=== TRIAGE HYPOTHESES TO ADJUDICATE (confirmed / refuted / unresolved) ===\n{hypos_str}\n\n"
                f"=== SECONDARY CONTEXT: INVESTIGATION TRAIL ===\n{trail}\n\n"
                "Analyze correlations, evidence gaps, and inconsistencies.\n"
                "FORMAT REQUIREMENT: Keep all entries concise, bullet-pointed, citing concrete event_id / process_entity_id values."
            ))
        ], "correlation analysis")
        confirmed = response.confirmed_correlations
        gaps = response.evidence_gaps
        benign_explanations = response.inconsistencies_or_benign_explanations
        fallback_used = False
    except Exception as e:
        print(f"[!] Correlation structured-output failed ({type(e).__name__}: {e}); attempting recovery or fallback.")
        err_text = "\n".join(str(error) for error in (e, e.__cause__) if error)
        recovered = False

        # Attempt 1: Balanced outer JSON extraction
        data = extract_outer_json(err_text)
        if data and isinstance(data, dict):
            try:
                parsed = CorrelationAndGapAnalysis(**data)
                confirmed = parsed.confirmed_correlations
                gaps = parsed.evidence_gaps
                benign_explanations = parsed.inconsistencies_or_benign_explanations
                recovered = True
                print("[+] Successfully recovered correlation analysis from JSON completion.")
            except Exception as parse_err:
                print(f"[!] Correlation JSON parsing error: {parse_err}")

        # Attempt 2: Structured Markdown sections extraction
        if not recovered:
            md_corr = _extract_correlation_from_markdown(err_text)
            if md_corr:
                confirmed = md_corr.get("confirmed_correlations") or []
                gaps = md_corr.get("evidence_gaps") or []
                benign_explanations = md_corr.get("inconsistencies_or_benign_explanations") or []
                recovered = True
                print(f"[+] Successfully extracted {len(confirmed)} correlations and {len(gaps)} gaps from Markdown completion.")

        # Attempt 3: Evidence timeline synthesis
        if not recovered:
            timeline = evidence_pack.get("timeline", [])
            if timeline:
                top_events = []
                for item in timeline[:8]:
                    eid = item.get("event_id") or ""
                    act = item.get("action") or ""
                    proc = item.get("process_name") or item.get("process_entity_id") or ""
                    host = item.get("host_id") or ""
                    top_events.append(f"Observed {act} on {host} ({eid}) by {proc}")
                confirmed = top_events if top_events else ["Suspicious activity identified in endpoint telemetry"]
            else:
                confirmed = ["Suspicious activity identified in endpoint telemetry"]
            gaps = ["Structured correlation output format required automated timeline mapping"]
            benign_explanations = []

        fallback_used = not recovered
        retry_used = isinstance(e, StructuredOutputRetryError)

    return {
        "confirmed_correlations": confirmed,
        "inconsistencies_or_benign_explanations": benign_explanations,
        "evidence_gaps": gaps,
        "correlation_fallback_used": fallback_used,
        "correlation_retry_used": retry_used,
    }
