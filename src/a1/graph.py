from typing import Literal
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import AIMessage

from a1.state import InvestigationState
from a1.tools import ALL_INVESTIGATION_TOOLS
from a1.config import MAX_INVESTIGATION_STEPS
from a1.nodes.alert_prep_node import alert_prep_node
from a1.nodes.triage_node import triage_node
from a1.nodes.investigator_node import investigator_node, should_continue
from a1.nodes.evidence_packing_node import evidence_packing_node
from a1.nodes.correlation_node import correlation_node
from a1.nodes.validator_node import validator_node
from a1.nodes.report_node import report_node

def create_investigation_graph():
    workflow = StateGraph(InvestigationState)

    # Input-reflection Stage 1: Alert Prep (runs before triage)
    workflow.add_node("alert_prep", alert_prep_node)
    workflow.add_node("triage", triage_node)
    workflow.add_node("investigator", investigator_node)
    workflow.add_node("tools", ToolNode(ALL_INVESTIGATION_TOOLS))
    # Input-reflection Stage 2: Evidence Packing (runs after review gate, before correlation)
    workflow.add_node("evidence_packing", evidence_packing_node)
    workflow.add_node("correlate", correlation_node)
    # Stage 3: Deterministic Evidence Validation (Issue #6)
    workflow.add_node("validate", validator_node)
    workflow.add_node("report", report_node)

    workflow.set_entry_point("alert_prep")
    workflow.add_edge("alert_prep", "triage")
    workflow.add_edge("triage", "investigator")
    workflow.add_conditional_edges(
        "investigator",
        should_continue,
        {
            "tools": "tools",
            "correlate": "evidence_packing",
            # Minimum-steps self-loop so it cannot conclude with zero tool calls on its first pass
            "investigator": "investigator",
        }
    )
    workflow.add_edge("tools", "investigator")
    workflow.add_edge("evidence_packing", "correlate")
    workflow.add_edge("correlate", "validate")
    workflow.add_edge("validate", "report")
    workflow.add_edge("report", END)

    return workflow.compile()
