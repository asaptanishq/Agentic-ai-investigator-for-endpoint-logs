import json
from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel, Field, field_validator
from typing import List

from a1.llm import get_llm
from a1.prompts import TRIAGE_SYSTEM_PROMPT
from a1.nodes.structured_output import StructuredOutputRetryError, invoke_structured_with_retry

class TriagePlan(BaseModel):
    hypotheses: List[str] = Field(default_factory=list, description="2-4 concrete investigation hypotheses")
    initial_entities: List[str] = Field(default_factory=list, description="Specific entities (host IDs, process names, etc.) to investigate first")
    investigation_plan: str = Field(default="", description="Step-by-step investigation approach")

    @field_validator("hypotheses", mode="before")
    @classmethod
    def normalize_hypotheses(cls, value):
        if value is None:
            return []
        values = value if isinstance(value, list) else [value]
        return [
            item if isinstance(item, str) else str(item.get("description") or item.get("hypothesis") or json.dumps(item))
            if isinstance(item, dict) else str(item)
            for item in values
        ]

    @field_validator("initial_entities", mode="before")
    @classmethod
    def normalize_entities(cls, value):
        if isinstance(value, dict):
            flattened = []
            for entities in value.values():
                flattened.extend(entities if isinstance(entities, list) else [entities])
            value = flattened
        if value is None:
            return []
        values = value if isinstance(value, list) else [value]
        return [str(item) for item in values if item]

    @field_validator("investigation_plan", mode="before")
    @classmethod
    def normalize_plan(cls, value):
        if isinstance(value, list):
            lines = []
            for index, step in enumerate(value, 1):
                if isinstance(step, dict):
                    parts = [str(step[key]) for key in ("step", "target", "action", "query_logic") if step.get(key)]
                    lines.append(" - ".join(parts) if parts else json.dumps(step))
                else:
                    lines.append(str(step))
            return "\n".join(lines)
        if isinstance(value, dict):
            return json.dumps(value)
        return value or ""

def triage_node(state):
    llm = get_llm()
    structured_llm = llm.with_structured_output(TriagePlan)

    alert_context = state.get("alert_context", "")
    enriched_alert = state.get("enriched_alert")
    hypotheses = ["Investigate suspicious endpoint activity"]
    retry_used = False
    fallback_used = False

    if enriched_alert:
        enriched_json = json.dumps(enriched_alert, indent=2)
        content_prompt = (
            f"Analyze this security alert using the pre-extracted and resolved input-reflection struct:\n\n"
            f"=== ENRICHED ALERT STRUCT ===\n{enriched_json}\n\n"
            f"Create a triage plan with 2-4 concrete testable hypotheses (covering both malicious and benign explanations), "
            f"initial entities to target (using the canonical resolved host IDs and process/file artifacts), and a concise step-by-step investigation plan."
        )
    else:
        content_prompt = f"Analyze this security alert and create a triage plan:\n\n{alert_context}"

    try:
        print("[TRIAGE] Requesting structured triage plan from the LLM...", flush=True)
        response, retry_used = invoke_structured_with_retry(structured_llm, [
            SystemMessage(content=TRIAGE_SYSTEM_PROMPT),
            HumanMessage(content=content_prompt)
        ], "triage plan")

        hypotheses = response.hypotheses or hypotheses
        entities = response.initial_entities
        if not entities and enriched_alert and enriched_alert.get("entities", {}).get("host_ids"):
            entities = enriched_alert["entities"]["host_ids"]
        plan_text = (
            f"Triage complete.\nHypotheses: {'; '.join(hypotheses)}\n"
            f"Initial entities: {', '.join(entities)}\n"
            f"Plan: {response.investigation_plan}"
        )
    except Exception as e:
        print(f"[!] Triage structured-output failed ({type(e).__name__}: {e}); using fallback plan.")
        fallback_used = True
        retry_used = isinstance(e, StructuredOutputRetryError)
        plan_text = f"Triage fallback: {'; '.join(hypotheses)}"

    return {
        "messages": [HumanMessage(content=plan_text)],
        "hypotheses": hypotheses,
        "iteration_count": 0,
        "triage_fallback_used": fallback_used,
        "triage_retry_used": retry_used,
    }
