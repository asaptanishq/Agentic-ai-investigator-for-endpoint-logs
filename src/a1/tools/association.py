import json
from typing import Dict, Any
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
def find_process_associations(process_entity_id: str) -> str:
    """Retrieve all observable telemetry associated with a process_entity_id (or process name):
    - Network connections initiated by this process
    - Files created or accessed by this process
    - Registry keys created or modified by this process
    - Correlated security events
    """
    try:
        target_id = process_entity_id.strip()
        associations: Dict[str, Any] = {"process_entity_id": target_id}

        # If the input is not formatted like proc-..., resolve it from the processes table
        resolved_ids = [target_id]
        if not target_id.startswith("proc-"):
            clean_name = target_id[:-4] if target_id.lower().endswith(".exe") else target_id
            p_rows = _get_db().execute_query(
                "SELECT DISTINCT process_entity_id, host_id, process_name, executable FROM processes "
                "WHERE lower(process_name) = lower(?) OR lower(process_name) = lower(?) || '.exe' "
                "OR lower(executable) LIKE '%' || lower(?) || '%' LIMIT 10",
                (clean_name, clean_name, clean_name),
            )
            if p_rows:
                resolved_ids = [r["process_entity_id"] for r in p_rows]
                associations["resolved_entities"] = p_rows
            else:
                return json.dumps({
                    "error": f"Process entity or name '{target_id}' not found in telemetry. "
                             f"Use find_process_relationships(host_id=...) to discover valid process_entity_id values."
                }, indent=2)

        placeholders = ",".join(["?"] * len(resolved_ids))

        # Network connections
        net_rows = _get_db().execute_query(
            f"SELECT network_id, event_id, source_ip, source_port, destination_ip, destination_port, protocol "
            f"FROM network_connections WHERE process_entity_id IN ({placeholders})",
            tuple(resolved_ids),
            max_rows=50
        )
        associations["network_connections"] = net_rows

        # File events
        file_rows = _get_db().execute_query(
            f"SELECT file_id, event_id, file_path, file_name, extension, size, sha256 "
            f"FROM files WHERE process_entity_id IN ({placeholders})",
            tuple(resolved_ids),
            max_rows=50
        )
        associations["files"] = file_rows

        # Registry events
        reg_rows = _get_db().execute_query(
            f"SELECT registry_id, event_id, registry_path, registry_key, registry_value, value_type "
            f"FROM registry_events WHERE process_entity_id IN ({placeholders})",
            tuple(resolved_ids),
            max_rows=50
        )
        associations["registry_events"] = reg_rows

        # Correlated events
        event_rows = _get_db().execute_query(
            f"SELECT event_id, timestamp, provider, event_code, category, action, outcome, severity "
            f"FROM events WHERE process_entity_id IN ({placeholders}) ORDER BY timestamp ASC",
            tuple(resolved_ids),
            max_rows=50
        )
        associations["events"] = event_rows

        return json.dumps(associations, indent=2)
    except Exception as e:
        return f"Error finding process associations: {str(e)}"
