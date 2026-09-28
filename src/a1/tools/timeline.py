import json
from typing import Optional, List, Any
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



def _extract_event_details(raw: Optional[str]) -> dict:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        details = {}
        for k in ("process.name", "process.command_line", "process.executable", "process.pid"):
            if k in data:
                details[k.split(".")[-1]] = data[k]
        for source, target in (
            ("process.parent.entity_id", "parent_process_entity_id"),
            ("process.parent.name", "parent_process_name"),
            ("process.code_signature.status", "code_signature_status"),
            ("process.integrity_level", "integrity_level"),
            ("process.target.name", "target_process_name"),
            ("process.target.pid", "target_process_pid"),
            ("user.domain", "user_domain"),
        ):
            if source in data:
                details[target] = data[source]
        for k in ("destination.ip", "destination.port", "destination.domain", "network.direction"):
            if k in data:
                details[k.replace(".", "_")] = data[k]
        for k in ("file.name", "file.path", "file.hash.sha256", "file.size", "file.extension", "file.type"):
            if k in data:
                details[k.replace(".", "_")] = data[k]
        for k in ("registry.key", "registry.path", "registry.value"):
            if k in data:
                details[k.replace(".", "_")] = data[k]
        for k in ("authentication.package", "logon.type", "user.name", "source.ip"):
            if k in data:
                details[k.replace(".", "_")] = data[k]
        return details
    except Exception:
        return {}


@tool
def search_timeline(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    host_id: Optional[str] = None,
    category: Optional[str] = None,
    user_id: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = 50,
) -> str:
    """Search telemetry events ordered chronologically with key forensic details.
    - start_time: Optional ISO 8601 start timestamp (e.g. '2026-09-10T07:00:00Z'). Avoid narrow <30m windows.
    - end_time: Optional ISO 8601 end timestamp (e.g. '2026-09-10T12:00:00Z').
    - host_id: Optional target host identifier or comma-separated hosts (e.g. 'host-a01', 'host-a02')
    - category: Optional category filter: 'process', 'network', 'file', 'registry', 'authentication', or comma-separated list like 'process,file' (or 'all')
    - user_id: Optional user identifier or user name (e.g. 'u-a01', 'jdoe')
    - keyword: Optional forensic keyword to search in actions and raw telemetry (e.g. 'lsass', 'procdump', 'powershell', 'sc.exe', 'UpdaterSvc')
    - limit: Maximum events to return (default 50)
    Returns chronologically ordered events enriched with key forensic details (IPs, process names, files, registry keys).
    """
    try:
        where_clauses = []
        params: List[Any] = []

        if start_time:
            where_clauses.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            where_clauses.append("timestamp <= ?")
            params.append(end_time)
        if host_id:
            raw_hosts = [h.strip() for h in host_id.split(",") if h.strip()]
            if len(raw_hosts) == 1:
                where_clauses.append("host_id = ?")
                params.append(raw_hosts[0])
            elif len(raw_hosts) > 1:
                placeholders = ",".join("?" * len(raw_hosts))
                where_clauses.append(f"host_id IN ({placeholders})")
                params.extend(raw_hosts)
        if user_id:
            u_clean = user_id.strip()
            where_clauses.append("(user_id = ? OR user_id IN (SELECT user_id FROM users WHERE lower(user_name) = lower(?)))")
            params.extend([u_clean, u_clean])
        if keyword:
            keywords = [term.strip().lower() for term in keyword.split(",") if term.strip()]
            keyword_clauses = []
            for term in keywords:
                keyword_clauses.append(
                    "(lower(action) LIKE ? OR lower(raw_json) LIKE ? OR lower(event_type) LIKE ? OR lower(category) LIKE ?)"
                )
                params.extend([f"%{term}%"] * 4)
            if keyword_clauses:
                where_clauses.append("(" + " OR ".join(keyword_clauses) + ")")
        if category and category.strip().lower() != "all":
            cat_tokens = [c.strip().lower() for c in category.split(",") if c.strip()]
            sub_clauses = []
            for cat_lower in cat_tokens:
                if cat_lower in ("logon", "login", "auth", "authentication"):
                    sub_clauses.append("(category LIKE '%authentication%' OR action LIKE '%logon%' OR event_code IN ('4624', '4625'))")
                elif cat_lower in ("net", "network", "conn", "connection"):
                    sub_clauses.append("(category LIKE '%network%' OR event_type LIKE '%connection%' OR action LIKE '%network%')")
                elif cat_lower in ("proc", "process", "exec", "execution"):
                    sub_clauses.append("(category LIKE '%process%' OR event_type LIKE '%start%' OR action LIKE '%process%')")
                elif cat_lower in ("reg", "registry"):
                    sub_clauses.append("(category LIKE '%registry%' OR action LIKE '%registry%')")
                elif cat_lower in ("file", "files"):
                    sub_clauses.append("(category LIKE '%file%' OR action LIKE '%file%')")
                else:
                    sub_clauses.append("(category LIKE ? OR event_type LIKE ? OR action LIKE ? OR event_code = ?)")
                    params.extend([f"%{cat_lower}%", f"%{cat_lower}%", f"%{cat_lower}%", cat_lower])
            if sub_clauses:
                where_clauses.append("(" + " OR ".join(sub_clauses) + ")")

        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        query = (
            f"SELECT event_id, timestamp, provider, event_code, category, event_type, action, outcome, host_id, user_id, process_entity_id, raw_json "
            f"FROM events{where_sql} ORDER BY timestamp ASC"
        )

        rows = _get_db().execute_query(query, tuple(params), max_rows=limit)
        results = []
        for r in rows:
            item = dict(r)
            raw = item.pop("raw_json", None)
            item["details"] = _extract_event_details(raw)
            results.append(item)
        return json.dumps(results, indent=2)
    except Exception as e:
        return f"Error searching timeline: {str(e)}"
