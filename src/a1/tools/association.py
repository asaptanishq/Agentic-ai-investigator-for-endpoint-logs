import json
from typing import Dict, Any
from langchain_core.tools import tool
from a1.db import get_active_db




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
            p_rows = get_active_db().execute_query(
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

        # 1. Target process details with full command line and metadata
        target_procs = get_active_db().execute_query(
            f"SELECT process_entity_id, host_id, pid, process_name, command_line, executable, parent_entity_id, parent_process_name, event_id, timestamp "
            f"FROM processes WHERE process_entity_id IN ({placeholders}) "
            f"ORDER BY (command_line IS NOT NULL) DESC, timestamp ASC",
            tuple(resolved_ids),
            max_rows=10,
        )
        if target_procs:
            associations["process_details"] = target_procs

        # 2. Spawned child processes (critical for LOTL/LOLBin execution tracking)
        child_rows = get_active_db().execute_query(
            f"SELECT process_entity_id, host_id, pid, process_name, command_line, executable, parent_entity_id, event_id, timestamp "
            f"FROM processes WHERE parent_entity_id IN ({placeholders}) "
            f"ORDER BY timestamp ASC",
            tuple(resolved_ids),
            max_rows=25,
        )
        if child_rows:
            associations["spawned_processes"] = child_rows

        # 3. Parent process details if available
        parent_rows = get_active_db().execute_query(
            f"SELECT parent.process_entity_id, parent.host_id, parent.pid, parent.process_name, parent.command_line, parent.executable, parent.event_id, parent.timestamp "
            f"FROM processes child JOIN processes parent ON parent.process_entity_id = child.parent_entity_id "
            f"WHERE child.process_entity_id IN ({placeholders}) "
            f"ORDER BY (parent.command_line IS NOT NULL) DESC LIMIT 5",
            tuple(resolved_ids),
            max_rows=5,
        )
        if parent_rows:
            associations["parent_process"] = parent_rows

        # Expand search scope to include spawned child processes for network/file/registry telemetry
        child_ids = [c["process_entity_id"] for c in child_rows if c.get("process_entity_id")]
        all_scope_ids = list(dict.fromkeys(resolved_ids + child_ids))
        all_placeholders = ",".join(["?"] * len(all_scope_ids))

        # 4. Network connections
        net_rows = get_active_db().execute_query(
            f"SELECT network_id, event_id, process_entity_id, host_id, timestamp, source_ip, source_port, destination_ip, destination_port, protocol "
            f"FROM network_connections WHERE process_entity_id IN ({all_placeholders})",
            tuple(all_scope_ids),
            max_rows=50
        )
        associations["network_connections"] = net_rows

        # 5. File events
        file_rows = get_active_db().execute_query(
            f"SELECT file_id, event_id, process_entity_id, host_id, timestamp, file_path, file_name, extension, size, sha256 "
            f"FROM files WHERE process_entity_id IN ({all_placeholders})",
            tuple(all_scope_ids),
            max_rows=50
        )
        associations["files"] = file_rows

        # 6. Registry events
        reg_rows = get_active_db().execute_query(
            f"SELECT registry_id, event_id, process_entity_id, host_id, timestamp, registry_path, registry_key, registry_value, value_type "
            f"FROM registry_events WHERE process_entity_id IN ({all_placeholders})",
            tuple(all_scope_ids),
            max_rows=50
        )
        associations["registry_events"] = reg_rows

        # 7. Correlated events
        event_rows = get_active_db().execute_query(
            f"SELECT event_id, timestamp, host_id, process_entity_id, provider, event_code, category, action, outcome, severity "
            f"FROM events WHERE process_entity_id IN ({all_placeholders}) ORDER BY timestamp ASC",
            tuple(all_scope_ids),
            max_rows=50
        )
        associations["events"] = event_rows

        return json.dumps(associations, indent=2)
    except Exception as e:
        return f"Error finding process associations: {str(e)}"
