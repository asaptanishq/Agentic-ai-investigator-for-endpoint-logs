from a1.tools.query import get_database_schema, query_telemetry
from a1.tools.process import find_process_relationships, trace_process_tree
from a1.tools.association import find_process_associations
from a1.tools.timeline import search_timeline
from a1.tools.entity import get_entity_context
# FIX: register the new indicator-pivot tool.
from a1.tools.pivot import pivot_on_indicator

ALL_INVESTIGATION_TOOLS = [
    get_database_schema,
    query_telemetry,
    find_process_relationships,
    trace_process_tree,
    find_process_associations,
    search_timeline,
    get_entity_context,
    pivot_on_indicator,
]

__all__ = [
    "get_database_schema",
    "query_telemetry",
    "find_process_relationships",
    "trace_process_tree",
    "find_process_associations",
    "search_timeline",
    "get_entity_context",
    "pivot_on_indicator",
    "ALL_INVESTIGATION_TOOLS",
]
