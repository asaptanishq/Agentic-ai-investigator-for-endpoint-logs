import json
from typing import Dict, Any, Optional
from langchain_core.tools import tool
from a1.db import get_active_db




@tool
def find_process_relationships(
    host_id: str,
    child_process_name: Optional[str] = None,
    parent_process_name: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> str:
    """Find observed child processes and their parent processes on a host.
    - host_id: Target host identifier (e.g. 'host-001')
    - child_process_name: Optional child process name (e.g. 'powershell.exe')
    - parent_process_name: Optional parent process name (e.g. 'winword.exe')
    - start_time: Optional start timestamp (ISO 8601 UTC)
    - end_time: Optional end timestamp (ISO 8601 UTC)
    If neither child_process_name nor parent_process_name is provided, returns
    observed processes and their parents on the host.

    Use this before trace_process_tree when an alert does not provide a process entity ID.
    """
    try:
        where_clauses = [
            "(child.host_id = ? "
            "OR child.host_id IN (SELECT host_id FROM hosts WHERE lower(hostname) = lower(?) OR lower(host_name) = lower(?)) "
            "OR child.host_id IN (SELECT hostname FROM hosts WHERE host_id = ?) "
            "OR child.host_id IN (SELECT host_name FROM hosts WHERE host_id = ?))"
        ]
        params = [host_id, host_id, host_id, host_id, host_id]

        if child_process_name:
            c_name = child_process_name.strip()
            c_no_ext = c_name[:-4] if c_name.lower().endswith(".exe") else c_name
            c_with_ext = c_name if c_name.lower().endswith(".exe") else f"{c_name}.exe"
            where_clauses.append(
                "(lower(child.process_name) = lower(?) OR lower(child.process_name) = lower(?) OR lower(child.executable) LIKE '%' || lower(?) || '%')"
            )
            params.extend([c_no_ext, c_with_ext, c_name])

        if parent_process_name:
            p_name = parent_process_name.strip()
            p_no_ext = p_name[:-4] if p_name.lower().endswith(".exe") else p_name
            p_with_ext = p_name if p_name.lower().endswith(".exe") else f"{p_name}.exe"
            where_clauses.append(
                "(lower(COALESCE(parent.process_name, '')) = lower(?) OR lower(COALESCE(parent.process_name, '')) = lower(?) OR lower(COALESCE(parent.executable, '')) LIKE '%' || lower(?) || '%')"
            )
            params.extend([p_no_ext, p_with_ext, p_name])

        if start_time:
            where_clauses.append("event.timestamp >= ?")
            params.append(start_time)

        if end_time:
            where_clauses.append("event.timestamp <= ?")
            params.append(end_time)

        where_sql = " AND ".join(where_clauses)
        sql = f"""
            SELECT
                child.process_entity_id AS child_process_entity_id,
                child.event_id AS child_event_id,
                child.event_id AS event_id,
                event.timestamp AS child_timestamp,
                event.timestamp AS timestamp,
                child.host_id,
                child.pid AS child_pid,
                child.process_name AS child_process_name,
                child.process_name AS process_name,
                child.executable AS child_executable,
                child.command_line AS child_command_line,
                child.command_line AS command_line,
                child.parent_entity_id,
                child.parent_pid,
                parent.process_entity_id AS parent_process_entity_id,
                parent.process_name AS parent_process_name,
                parent.executable AS parent_executable,
                parent.command_line AS parent_command_line
            FROM processes AS child
            JOIN events AS event
                ON event.event_id = child.event_id
            LEFT JOIN processes AS parent
                ON parent.process_entity_id = child.parent_entity_id
            WHERE {where_sql}
            ORDER BY event.timestamp ASC
        """
        rows = get_active_db().execute_query(sql, tuple(params), max_rows=50)
        return json.dumps(
            {
                "host_id": host_id,
                "child_process_name": child_process_name,
                "parent_process_name": parent_process_name,
                "matches": rows,
            },
            indent=2,
        )
    except Exception as e:
        return f"Error finding process relationships: {str(e)}"


@tool
def trace_process_tree(process_entity_id: str, direction: str = "both") -> str:
    """Reconstruct the process execution hierarchy for a given process_entity_id.
    - direction: 'ancestors' (parents/grandparents), 'descendants' (spawned children), or 'both' (default).
    Returns parent-child relationship details (PID, process_name, executable, command_line, event_id, parent_entity_id, etc.).
    """
    tree_data: Dict[str, Any] = {"process_entity_id": process_entity_id, "ancestors": [], "descendants": []}
    try:
        target_rows = get_active_db().execute_query(
            "SELECT * FROM processes WHERE process_entity_id = ? ORDER BY (command_line IS NOT NULL) DESC, timestamp ASC",
            (process_entity_id,),
            max_rows=1
        )
        if not target_rows:
            return json.dumps({"error": f"Process entity '{process_entity_id}' not found in telemetry."}, indent=2)

        target = dict(target_rows[0])
        tree_data["target_process"] = {
            "process_entity_id": target.get("process_entity_id"),
            "pid": target.get("pid"),
            "process_name": target.get("process_name"),
            "executable": target.get("executable"),
            "command_line": target.get("command_line"),
            "parent_entity_id": target.get("parent_entity_id"),
            "parent_pid": target.get("parent_pid"),
            "host_id": target.get("host_id"),
            "event_id": target.get("event_id"),
            "timestamp": target.get("timestamp"),
        }

        # Trace ancestors (parents/grandparents)
        if direction in ("ancestors", "both"):
            current_parent_id = target.get("parent_entity_id")
            depth = 0
            while current_parent_id and depth < 5:
                p_rows = get_active_db().execute_query(
                    "SELECT * FROM processes WHERE process_entity_id = ? ORDER BY (command_line IS NOT NULL) DESC, timestamp ASC",
                    (current_parent_id,),
                    max_rows=1
                )
                if not p_rows:
                    tree_data["ancestors"].append({
                        "process_entity_id": current_parent_id,
                        "note": "Parent process record not found in telemetry (potential evidence gap or pre-existing process)"
                    })
                    break
                p = dict(p_rows[0])
                tree_data["ancestors"].append({
                    "process_entity_id": p.get("process_entity_id"),
                    "pid": p.get("pid"),
                    "process_name": p.get("process_name"),
                    "executable": p.get("executable"),
                    "command_line": p.get("command_line"),
                    "parent_entity_id": p.get("parent_entity_id"),
                    "host_id": p.get("host_id"),
                    "event_id": p.get("event_id"),
                    "timestamp": p.get("timestamp"),
                })
                current_parent_id = p.get("parent_entity_id")
                depth += 1

        # Trace descendants (spawned children)
        if direction in ("descendants", "both"):
            c_rows = get_active_db().execute_query(
                "SELECT * FROM processes WHERE parent_entity_id = ? ORDER BY timestamp ASC",
                (process_entity_id,),
                max_rows=25
            )
            for c in c_rows:
                tree_data["descendants"].append({
                    "process_entity_id": c.get("process_entity_id"),
                    "pid": c.get("pid"),
                    "process_name": c.get("process_name"),
                    "executable": c.get("executable"),
                    "command_line": c.get("command_line"),
                    "parent_entity_id": c.get("parent_entity_id"),
                    "host_id": c.get("host_id"),
                    "event_id": c.get("event_id"),
                    "timestamp": c.get("timestamp"),
                })

        # FIX: instructive empty-result note. In this dataset 251/275 processes
        # have no recorded parent_entity_id, so an empty tree is the CORRECT
        # answer -- not a reason to retry. A real run had the model call this
        # tool 17x with identical args. The note tells the model to move on;
        # the investigator node's repetition guard enforces it.
        if not tree_data["ancestors"] and not tree_data["descendants"]:
            tree_data["note"] = (
                "No parent/child links are recorded for this process in the "
                "processes table (parent_entity_id is empty for most processes in "
                "this dataset). This is a data limitation, not an error -- repeating "
                "this query will return the same result. Continue the investigation "
                "with find_process_associations, pivot_on_indicator, search_timeline, "
                "or get_entity_context instead."
            )

        return json.dumps(tree_data, indent=2)
    except Exception as e:
        return f"Error tracing process tree: {str(e)}"
