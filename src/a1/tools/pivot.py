import json
from langchain_core.tools import tool
from a1.db import get_active_db

def _get_db():
    return get_active_db()



@tool
def pivot_on_indicator(indicator_type: str, indicator_value: str, max_rows: int = 25) -> str:
    """Pivot from a single indicator of interest to every other place it appears.
    - indicator_type: 'sha256' | 'destination_ip' | 'executable' | 'file_name'
    - indicator_value: the indicator, e.g. a SHA-256 hash, '203.0.113.45', 'powershell.exe'
    Use this to check lateral spread: the same hash on other hosts, the same
    destination IP contacted by other processes, the same executable running elsewhere.
    Returns matches with their host_id values so cross-host spread is visible.
    """
    try:
        raw_t = indicator_type.strip().lower().replace("-", "").replace("_", "")
        alias_map = {
            "sha256": "sha256",
            "hash": "sha256",
            "filehash": "sha256",
            "destinationip": "destination_ip",
            "destip": "destination_ip",
            "dstip": "destination_ip",
            "sourceip": "destination_ip",
            "srcip": "destination_ip",
            "ip": "destination_ip",
            "ipaddress": "destination_ip",
            "hostip": "destination_ip",
            "executable": "executable",
            "exe": "executable",
            "process": "executable",
            "processname": "executable",
            "filename": "file_name",
            "file": "file_name",
            "username": "user",
            "user_name": "user",
            "user": "user",
            "userid": "user",
            "user_id": "user",
            "account": "user",
        }
        t = alias_map.get(raw_t, indicator_type.strip().lower())

        if t == "sha256":
            rows = _get_db().execute_query(
                "SELECT COALESCE(f.host_id, e.host_id, 'unknown') AS host_id, f.process_entity_id, f.file_path, f.file_name, f.sha256, f.event_id "
                "FROM files AS f LEFT JOIN events AS e ON e.event_id = f.event_id "
                "WHERE lower(f.sha256) = lower(?)",
                (indicator_value,),
                max_rows=max_rows,
            )
        elif t == "destination_ip":
            rows = _get_db().execute_query(
                "SELECT COALESCE(n.host_id, e.host_id, n.source_host_id, 'unknown') AS host_id, n.process_entity_id, n.source_ip, n.source_port, n.destination_ip, n.destination_port, n.protocol, n.event_id "
                "FROM network_connections AS n LEFT JOIN events AS e ON e.event_id = n.event_id "
                "WHERE n.destination_ip = ? OR n.source_ip = ?",
                (indicator_value, indicator_value),
                max_rows=max_rows,
            )
        elif t == "executable":
            val = indicator_value.strip()
            val_no_ext = val[:-4] if val.lower().endswith(".exe") else val
            val_ext = val if val.lower().endswith(".exe") else f"{val}.exe"
            rows = _get_db().execute_query(
                "SELECT host_id, process_entity_id, pid, process_name, executable, command_line, event_id "
                "FROM processes WHERE lower(executable) LIKE '%' || lower(?) || '%' "
                "OR lower(process_name) = lower(?) OR lower(process_name) = lower(?) "
                "OR lower(COALESCE(command_line, '')) LIKE '%' || lower(?) || '%'",
                (val, val_no_ext, val_ext, val),
                max_rows=max_rows,
            )
        elif t == "file_name":
            val = indicator_value.strip()
            clean_val = val.lstrip("*").lower()
            rows = _get_db().execute_query(
                "SELECT COALESCE(f.host_id, e.host_id, 'unknown') AS host_id, f.process_entity_id, f.file_path, f.file_name, f.sha256, f.event_id "
                "FROM files AS f LEFT JOIN events AS e ON e.event_id = f.event_id "
                "WHERE lower(f.file_name) = lower(?) OR lower(f.file_name) LIKE '%' || lower(?) "
                "OR lower(COALESCE(f.extension, '')) = lower(?) OR lower(COALESCE(f.file_path, '')) LIKE '%' || lower(?)",
                (val, clean_val, clean_val, clean_val),
                max_rows=max_rows,
            )
        elif t == "user":
            rows = _get_db().execute_query(
                "SELECT e.host_id, e.event_id, e.timestamp, e.action, e.event_code, e.outcome, e.user_id, e.process_entity_id "
                "FROM events AS e LEFT JOIN users AS u ON u.user_id = e.user_id "
                "WHERE lower(e.user_id) = lower(?) OR lower(COALESCE(u.user_name, '')) = lower(?) "
                "ORDER BY e.timestamp ASC",
                (indicator_value, indicator_value),
                max_rows=max_rows,
            )
        else:
            return f"Invalid indicator_type: '{indicator_type}'. Supported types: sha256 (hash), destination_ip / ip, executable (process name), file_name, user (user_name or user_id)."
        hosts = sorted({r["host_id"] for r in rows if r.get("host_id")})
        return json.dumps(
            {
                "indicator_type": t,
                "indicator_value": indicator_value,
                "match_count": len(rows),
                "hosts_seen_on": hosts,
                "matches": rows,
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        return f"Error pivoting on indicator: {str(e)}"
