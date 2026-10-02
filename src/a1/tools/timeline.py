import json
from typing import Optional, List, Any, Tuple
from langchain_core.tools import tool
from a1.db import get_active_db


def _get_field_val(d: dict, *paths: str) -> Any:
    for path in paths:
        if path in d and d[path] is not None:
            return d[path]
        cur = d
        parts = path.split(".")
        found = True
        for part in parts:
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                found = False
                break
        if found and cur is not None:
            return cur
    return None


_FIELD_MAPPINGS = (
    # Process Parent & Target
    (("process.parent.entity_id", "data.win.eventdata.parentProcessId"), "parent_process_entity_id"),
    (("process.parent.name", "data.win.eventdata.parentImage", "process_parent_name"), "parent_process_name"),
    (("process.code_signature.status",), "code_signature_status"),
    (("process.integrity_level",), "integrity_level"),
    (("process.target.name",), "target_process_name"),
    (("process.target.pid",), "target_process_pid"),
    (("user.domain", "data.win.eventdata.userDomain"), "user_domain"),
    # Network & NIDS
    (("destination.ip", "network_dst", "dest_ip", "dst_ip"), "destination_ip"),
    (("destination.port", "network_dst_port", "dest_port", "dst_port"), "destination_port"),
    (("destination.domain", "dns_query", "dns.rrname", "dns.query", "tls.sni", "http.hostname"), "destination_domain"),
    (("network.direction",), "network_direction"),
    (("source.ip", "source_ip", "src_ip"), "source_ip"),
    (("source.port", "source_port", "src_port"), "source_port"),
    (("network.protocol", "proto", "app_proto"), "protocol"),
    (("alert.signature", "alert_signature", "signature"), "alert_signature"),
    (("alert.category", "alert_category"), "alert_category"),
    (("alert.severity", "alert_severity"), "alert_severity"),
    (("http.http_method", "http.method"), "http_method"),
    (("http.url",), "http_url"),
    # Files
    (("file.name", "data.win.eventdata.targetFilename", "file_name"), "file_name"),
    (("file.path", "data.win.eventdata.targetFilename", "file_path"), "file_path"),
    (("file.hash.sha256", "file_hash", "sha256", "hash"), "file_hash_sha256"),
    (("file.size",), "file_size"),
    (("file.extension",), "file_extension"),
    (("file.type",), "file_type"),
    # Registry
    (("registry.key", "data.win.eventdata.targetObject", "registry_key"), "registry_key"),
    (("registry.path", "data.win.eventdata.targetObject", "registry_path"), "registry_path"),
    (("registry.value", "data.win.eventdata.details", "registry_value"), "registry_value"),
    # Auth & Users
    (("authentication.package",), "authentication_package"),
    (("logon.type",), "logon_type"),
    (("user.name", "data.win.eventdata.user", "source_user"), "user_name"),
)


def _extract_primary_process_fields(data: dict, details: dict) -> None:
    primary_mappings = (
        (("process.name", "data.win.eventdata.processName", "data.win.eventdata.image", "process_name"), "name"),
        (("process.command_line", "data.win.eventdata.commandLine", "process_cmdline"), "command_line"),
        (("process.executable", "data.win.eventdata.image", "process_path"), "executable"),
        (("process.pid", "data.win.eventdata.processId", "process_id"), "pid"),
    )
    for sources, target in primary_mappings:
        val = _get_field_val(data, *sources)
        if val is not None:
            details[target] = val


def _extract_event_details(raw: Optional[str]) -> dict:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {}
        details = {}
        _extract_primary_process_fields(data, details)
        for sources, target in _FIELD_MAPPINGS:
            val = _get_field_val(data, *sources)
            if val is not None:
                details[target] = val
        return details
    except Exception:
        return {}


def _build_host_filter(host_id: Optional[str]) -> Tuple[Optional[str], list]:
    if not host_id:
        return None, []
    raw_hosts = [h.strip() for h in host_id.split(",") if h.strip()]
    host_subclauses = []
    params = []
    for h in raw_hosts:
        host_subclauses.append(
            "(host_id = ? "
            "OR host_id IN (SELECT host_id FROM hosts WHERE lower(hostname) = lower(?) OR lower(host_name) = lower(?)) "
            "OR host_id IN (SELECT hostname FROM hosts WHERE host_id = ?) "
            "OR host_id IN (SELECT host_name FROM hosts WHERE host_id = ?) "
            "OR host_id IN (SELECT ip_address FROM hosts WHERE host_id = ? OR lower(hostname) = lower(?) OR lower(host_name) = lower(?)))"
        )
        params.extend([h, h, h, h, h, h, h, h])
    if not host_subclauses:
        return None, []
    return "(" + " OR ".join(host_subclauses) + ")", params


def _build_keyword_filter(keyword: Optional[str]) -> Tuple[Optional[str], list]:
    if not keyword:
        return None, []
    keywords = [term.strip().lower() for term in keyword.split(",") if term.strip()]
    keyword_clauses = []
    params = []
    for term in keywords:
        keyword_clauses.append(
            "(lower(action) LIKE ? OR lower(raw_json) LIKE ? OR lower(event_type) LIKE ? OR lower(category) LIKE ?)"
        )
        params.extend([f"%{term}%"] * 4)
    if not keyword_clauses:
        return None, []
    return "(" + " OR ".join(keyword_clauses) + ")", params


def _build_category_filter(category: Optional[str]) -> Tuple[Optional[str], list]:
    if not category or category.strip().lower() == "all":
        return None, []
    cat_tokens = [c.strip().lower() for c in category.split(",") if c.strip()]
    sub_clauses = []
    params = []
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
    if not sub_clauses:
        return None, []
    return "(" + " OR ".join(sub_clauses) + ")", params


def _build_user_filter(user_id: Optional[str]) -> Tuple[Optional[str], list]:
    if not user_id:
        return None, []
    u_clean = user_id.strip()
    return "(user_id = ? OR user_id IN (SELECT user_id FROM users WHERE lower(user_name) = lower(?)))", [u_clean, u_clean]


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

        for builder, arg in (
            (_build_host_filter, host_id),
            (_build_user_filter, user_id),
            (_build_keyword_filter, keyword),
            (_build_category_filter, category),
        ):
            clause, c_params = builder(arg)
            if clause:
                where_clauses.append(clause)
                params.extend(c_params)

        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        query = (
            f"SELECT event_id, timestamp, provider, event_code, category, event_type, action, outcome, host_id, user_id, process_entity_id, raw_json "
            f"FROM events{where_sql} ORDER BY timestamp ASC"
        )

        rows = get_active_db().execute_query(query, tuple(params), max_rows=limit)
        results = []
        for r in rows:
            item = dict(r)
            raw = item.pop("raw_json", None)
            item["details"] = _extract_event_details(raw)
            results.append(item)
        return json.dumps(results, indent=2)
    except Exception as e:
        return f"Error searching timeline: {str(e)}"

