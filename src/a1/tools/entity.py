import json
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



@tool
def get_entity_context(entity_type: str, entity_id: str) -> str:
    """Retrieve identity and context for a host or user.
    - entity_type: 'host' or 'user'
    - entity_id: host_id (e.g. 'host-001') or user_id (e.g. 'u-001')
    """
    # FIX: docstring example was 'usr-001'; the dataset uses 'u-001'. The model
    # copies examples, so a wrong example costs a wasted lookup.
    try:
        clean_type = entity_type.strip().lower()
        if clean_type == "host":
            rows = _get_db().execute_query(
                "SELECT * FROM hosts WHERE host_id = ? OR lower(hostname) = lower(?) OR lower(host_name) = lower(?)",
                (entity_id, entity_id, entity_id),
                max_rows=1,
            )
            if not rows:
                return f"Host '{entity_id}' not found."
            host_info = dict(rows[0])
            h_id = host_info.get("host_id", entity_id)
            h_name = host_info.get("hostname") or host_info.get("host_name") or entity_id
            counts = _get_db().execute_query(
                "SELECT COUNT(*) as event_count FROM events WHERE host_id = ? OR host_id = ?",
                (h_id, h_name),
                max_rows=1,
            )
            host_info["total_events"] = counts[0]["event_count"] if counts else 0
            return json.dumps(host_info, indent=2)
        elif clean_type == "user":
            rows = _get_db().execute_query(
                "SELECT * FROM users WHERE user_id = ? OR lower(username) = lower(?) OR lower(user_name) = lower(?)",
                (entity_id, entity_id, entity_id),
                max_rows=1,
            )
            if not rows:
                return f"User '{entity_id}' not found."
            user_info = dict(rows[0])
            u_id = user_info.get("user_id", entity_id)
            u_name = user_info.get("username") or user_info.get("user_name") or entity_id
            counts = _get_db().execute_query(
                "SELECT COUNT(*) as event_count FROM events WHERE user_id = ? OR user_id = ?",
                (u_id, u_name),
                max_rows=1,
            )
            user_info["total_events"] = counts[0]["event_count"] if counts else 0
            return json.dumps(user_info, indent=2)
        else:
            return f"Invalid entity_type: '{entity_type}'. Must be 'host' or 'user'."
    except Exception as e:
        return f"Error getting entity context: {str(e)}"
