import json
import re
from langchain_core.tools import tool
from a1.db import EndpointDatabase
from a1.config import get_db_path

_db = None

def _get_db() -> EndpointDatabase:
    global _db
    current_path = get_db_path()
    if _db is None or _db.db_path != current_path:
        _db = EndpointDatabase(current_path)
    return _db



# High-value DFIR keys to preserve when projecting large raw_json payloads.
# Retains process details, network destinations/domains, files/hashes, registry keys, and authentication info.
_RAW_JSON_KEEP_SUBSTRINGS = (
    "command_line", "args", "hash", "parent", "code_signature",
    "destination", "source", "ip", "port", "domain", "protocol", "direction",
    "file", "path", "extension", "size",
    "registry", "key", "value",
    "user", "logon", "authentication", "process", "action", "outcome"
)
_RAW_JSON_KEEP_FULL_UPTO = 1000


def _project_raw_json(raw: str) -> dict:
    """Keep only high-value forensic fields from a large raw_json payload."""
    try:
        payload = json.loads(raw)
    except Exception:
        return {"unparseable": True}
    if not isinstance(payload, dict):
        return {"unparseable": True}
    # Keep metadata keys that match any DFIR indicator
    projected = {
        k: v for k, v in payload.items()
        if any(sub in k.lower() for sub in _RAW_JSON_KEEP_SUBSTRINGS)
    }
    return projected if projected else payload


@tool
def get_database_schema() -> str:
    """Returns the database schema (tables, views, and column names) available in the endpoint security telemetry database.
    Use this to inspect available fields before querying."""
    schema = _get_db().get_schema()
    return json.dumps(schema, indent=2)

@tool
def query_telemetry(sql_query: str, max_rows: int = 25) -> str:
    """Execute a read-only SQL query against the endpoint security database.
    Available tables: events, processes, files, network_connections, registry_events, hosts, users, and agent_events view.
    Only SELECT queries are allowed.
    Returns JSON formatted matching rows.
    """
    clean_query = sql_query.strip()
    
    # Auto-normalize exact category/event_type matches to LIKE because the events table
    # stores category as JSON array strings like '["process"]' or '["authentication"]'.
    clean_query = re.sub(
        r"(?i)\b(category|event_type)\s*=\s*'([^']+)'",
        r"\1 LIKE '%\2%'",
        clean_query
    )
    
    try:
        results = _get_db().execute_query(clean_query, max_rows=max_rows)
        cleaned = []
        for r in results:
            item = dict(r)
            if "raw_json" in item:
                raw = str(item["raw_json"])
                if len(raw) > _RAW_JSON_KEEP_FULL_UPTO:
                    item["raw_json_projected"] = _project_raw_json(raw)
                    del item["raw_json"]
            cleaned.append(item)
        return json.dumps(cleaned, indent=2, default=str)
    except Exception as e:
        return f"Database query error: {str(e)}"

