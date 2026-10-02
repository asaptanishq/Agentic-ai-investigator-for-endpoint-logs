import sqlite3
from typing import Any, Dict, List, Optional
from pathlib import Path
from a1.config import get_db_path

class DatabaseAccessError(Exception):
    pass

_NULL_EVENT_ID = "NULL AS event_id"
_NULL_PROCESS_ENTITY_ID = "NULL AS process_entity_id"
_EMPTY_RAW_JSON = "'{}' AS raw_json"
_E_HOST_ID = "e.host_id"
_E_TIMESTAMP = "e.timestamp"
_E_USER_ID = "e.user_id"


def _safe_coalesce(*items: str) -> str:
    """Combine non-empty expressions into a single valid COALESCE."""
    clean = [it.strip() for it in items if it and it.strip() != "NULL"]
    if not clean:
        return "NULL"
    if len(clean) == 1:
        return clean[0]
    return f"COALESCE({', '.join(clean)})"


def _jextract(has_raw: bool, *paths: str) -> List[str]:
    """Return list of json_extract expressions for raw_json."""
    if not has_raw:
        return []
    return [f"json_extract(raw_json, '{p}')" for p in paths]


def _get_field(event_cols: set, has_raw: bool, cols: Any, *raw_paths: str, default: Optional[str] = None) -> str:
    """Extract field from matching event column(s), raw_json paths, or fallback default."""
    parts = []
    if isinstance(cols, str):
        cols = [cols]
    for c in cols:
        if c in event_cols:
            parts.append(c)
    parts.extend(_jextract(has_raw, *raw_paths))
    if default is not None:
        parts.append(default)
    return _safe_coalesce(*parts)


def _resolve_joined_ts(prefix: str, table_cols: set, join_clause: str, event_cols: set) -> str:
    if join_clause and "timestamp" in event_cols:
        return _E_TIMESTAMP
    if "timestamp" in table_cols:
        return f"{prefix}.timestamp"
    return f"COALESCE(json_extract({prefix}.raw_json, '$.\"@timestamp\"'), json_extract({prefix}.raw_json, '$.@timestamp'), json_extract({prefix}.raw_json, '$.timestamp')) AS timestamp"


def _resolve_joined_host_id(prefix: str, table_cols: set, join_clause: str, event_cols: set) -> str:
    if join_clause and "host_id" in event_cols:
        return _E_HOST_ID
    if "host_id" in table_cols:
        return f"{prefix}.host_id"
    return f"COALESCE(json_extract({prefix}.raw_json, '$.\"host.id\"'), json_extract({prefix}.raw_json, '$.host.id'), json_extract({prefix}.raw_json, '$.host_id'), 'unknown') AS host_id"


def _resolve_joined_user_id(prefix: str, table_cols: set, join_clause: str, event_cols: set) -> str:
    if join_clause and "user_id" in event_cols:
        return _E_USER_ID
    if "user_id" in table_cols:
        return f"{prefix}.user_id"
    return f"COALESCE(json_extract({prefix}.raw_json, '$.\"user.id\"'), json_extract({prefix}.raw_json, '$.user.id'), json_extract({prefix}.raw_json, '$.user_id')) AS user_id"


def _col_or_fallback(alias: str, col: str, cols: set, fallback: str) -> str:
    if col in cols:
        return f"{alias}.{col}"
    return fallback


def _coalesce_col_or_json(alias: str, col: str, cols: set, *json_paths: str, cast: Optional[str] = None) -> str:
    parts = []
    if col in cols:
        parts.append(f"{alias}.{col}")
    for p in json_paths:
        expr = f"json_extract({alias}.raw_json, '{p}')"
        if cast:
            expr = f"CAST({expr} AS {cast})"
        parts.append(expr)
    return f"COALESCE({', '.join(parts)}) AS {col}"


def _build_events_join(alias: str, cols: set, main_objects: set, event_cols: set) -> str:
    if "events" in main_objects and "event_id" in cols and "event_id" in event_cols:
        return f"LEFT JOIN main.events e ON {alias}.event_id = e.event_id"
    return ""


def _resolve_process_host_id(proc_cols: set, main_objects: set, event_cols: set) -> str:
    if "host_id" in proc_cols:
        return "p.host_id"
    if "events" in main_objects and "host_id" in event_cols:
        return _E_HOST_ID
    return "NULL AS host_id"


def _find_host_table(main_objects: set) -> Optional[str]:
    for tbl in ("hosts", "network_assets", "endpoints"):
        if tbl in main_objects:
            return tbl
    return None


def _resolve_host_cols(host_cols: set):
    if "host_id" in host_cols:
        hid = "host_id"
    elif "asset_id" in host_cols:
        hid = "asset_id"
    elif "endpoint_id" in host_cols:
        hid = "endpoint_id"
    else:
        hid = "rowid"

    if "host_name" in host_cols:
        hname = "host_name"
    elif "hostname" in host_cols:
        hname = "hostname"
    else:
        hname = hid

    if "hostname" in host_cols:
        hname_alias = "hostname"
    elif "host_name" in host_cols:
        hname_alias = "host_name"
    else:
        hname_alias = hid

    return hid, hname, hname_alias


def _resolve_user_cols(user_cols: set):
    if "user_name" in user_cols:
        uname = "user_name"
    elif "username" in user_cols:
        uname = "username"
    else:
        uname = "user_id"

    if "username" in user_cols:
        alias = "username"
    elif "user_name" in user_cols:
        alias = "user_name"
    else:
        alias = "user_id"

    return uname, alias


def _build_events_view(source_table: str, event_cols: set, has_raw: bool) -> Optional[str]:
    required = {
        "event_id", "timestamp", "provider", "event_code", "category",
        "event_type", "action", "outcome", "severity", "host_id",
        "user_id", "process_entity_id", "raw_json"
    }
    if source_table == "events" and required.issubset(event_cols):
        return None
    return f"""
        CREATE TEMP VIEW IF NOT EXISTS events AS
        SELECT 
            {_get_field(event_cols, has_raw, ["event_id", "id"], '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
            {_get_field(event_cols, has_raw, ["timestamp", "@timestamp", "time", "event_time"], '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
            {_get_field(event_cols, has_raw, ["provider", "manager", "sensor"], '$."event.provider"', '$.event.provider', '$.provider', default="'Suricata'")} AS provider,
            {_get_field(event_cols, has_raw, ["event_code", "rule_id", "code", "alert_signature_id", "signature_id"], '$."event.code"', '$.event.code', '$.event_code', '$."rule.id"', default="'1'")} AS event_code,
            {_get_field(event_cols, has_raw, ["category", "rule_groups", "alert_category"], '$."event.category"', '$.event.category', '$.category', default="'network'")} AS category,
            {_get_field(event_cols, has_raw, ["event_type", "subcategory", "app_proto"], '$."event.type"', '$.event.type', '$.type', default="'alert'")} AS event_type,
            {_get_field(event_cols, has_raw, ["action", "event_action", "rule_description", "alert_signature", "signature"], '$."event.action"', '$.event.action', '$.action', default=_get_field(event_cols, has_raw, ["event_type", "app_proto"], default="'alert'"))} AS action,
            {_get_field(event_cols, has_raw, ["outcome", "status"], '$."event.outcome"', '$.event.outcome', '$.outcome', default="'success'")} AS outcome,
            {_get_field(event_cols, has_raw, ["severity", "rule_level", "alert_severity"], '$."event.severity"', '$.event.severity', '$.severity', default="0")} AS severity,
            {_get_field(event_cols, has_raw, ["host_id", "agent_id", "agent_name", "hostname", "asset_id", "src_ip"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', '$.src_ip', default="'unknown'")} AS host_id,
            {_get_field(event_cols, has_raw, ["user_id", "source_user", "username"], '$."user.id"', '$.user.id', '$.user_id', '$."user.name"', '$.user.name', default="'unknown'")} AS user_id,
            {_get_field(event_cols, has_raw, ["process_entity_id", "entity_id"], '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id', default="'proc-' || rowid")} AS process_entity_id,
            {_get_field(event_cols, has_raw, ["raw_json"], default="'{}'")} AS raw_json
        FROM main.{source_table};
    """


def _build_processes_from_table(proc_cols: set, main_objects: set, event_cols: set) -> str:
    eid_expr = _col_or_fallback("p", "event_id", proc_cols, _NULL_EVENT_ID)
    hid_expr = _resolve_process_host_id(proc_cols, main_objects, event_cols)
    exe_expr = _col_or_fallback("p", "executable", proc_cols, "NULL AS executable")
    peid_expr = _coalesce_col_or_json("p", "parent_entity_id", proc_cols, '$."process.parent.entity_id"', '$.process.parent.entity_id', '$.parent_entity_id')
    ppid_expr = _coalesce_col_or_json("p", "parent_pid", proc_cols, '$."process.parent.pid"', '$.process.parent.pid', '$.parent_pid', cast="INTEGER")
    p_pname_expr = _coalesce_col_or_json("p", "parent_process_name", proc_cols, '$."process.parent.name"', '$.process.parent.name', '$.process_parent_name')
    cmd_expr = _coalesce_col_or_json("p", "command_line", proc_cols, '$."process.command_line"', '$.process.command_line', '$.process_cmdline')
    raw_expr = _col_or_fallback("p", "raw_json", proc_cols, _EMPTY_RAW_JSON)
    join_clause = _build_events_join("p", proc_cols, main_objects, event_cols)
    ts_expr = _resolve_joined_ts("p", proc_cols, join_clause, event_cols)
    uid_expr = _resolve_joined_user_id("p", proc_cols, join_clause, event_cols)

    return f"""
        CREATE TEMP VIEW IF NOT EXISTS processes AS
        SELECT p.process_entity_id, {eid_expr}, {hid_expr}, p.pid, p.process_name,
               {exe_expr}, {cmd_expr}, {peid_expr}, {ppid_expr}, {p_pname_expr}, {raw_expr},
               {ts_expr}, {uid_expr}
        FROM main.processes p
        {join_clause};
    """


def _synthesize_processes_from_events(source_table: str, event_cols: set, has_raw: bool) -> str:
    cmd_chk = [c for c in ["command_line", "process_cmdline"] if c in event_cols]
    exe_chk = [c for c in ["executable", "process_path"] if c in event_cols]
    pname_chk = [c for c in ["process_name", "name"] if c in event_cols]

    return f"""
        CREATE TEMP VIEW IF NOT EXISTS processes AS
        SELECT 
            {_get_field(event_cols, has_raw, ["process_entity_id", "entity_id"], '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id', '$.entity_id', default="'proc-' || rowid")} AS process_entity_id,
            {_get_field(event_cols, has_raw, ["event_id", "id"], '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
            {_get_field(event_cols, has_raw, ["host_id", "agent_id", "agent_name", "hostname"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', default="'unknown'")} AS host_id,
            CAST({_get_field(event_cols, has_raw, ["pid", "process_id"], '$."process.pid"', '$.process.pid', '$.process_pid', '$."data.win.eventdata.processId"', default="0")} AS INTEGER) AS pid,
            {_get_field(event_cols, has_raw, ["process_name", "name"], '$."process.name"', '$.process.name', '$.process_name', '$."data.win.eventdata.image"', default="'unknown'")} AS process_name,
            {_get_field(event_cols, has_raw, ["executable", "process_path"], '$."process.executable"', '$.process.executable', '$.executable', '$."data.win.eventdata.image"')} AS executable,
            {_get_field(event_cols, has_raw, ["command_line", "process_cmdline"], '$."process.command_line"', '$.process.command_line', '$.command_line', '$."data.win.eventdata.commandLine"')} AS command_line,
            {_get_field(event_cols, has_raw, ["parent_entity_id"], '$."process.parent.entity_id"', '$.process.parent.entity_id', '$.parent_entity_id', '$.parent.process_entity_id')} AS parent_entity_id,
            CAST({_get_field(event_cols, has_raw, ["parent_pid", "process_parent_id"], '$."process.parent.pid"', '$.process.parent.pid', '$.parent_pid', '$."data.win.eventdata.parentProcessId"')} AS INTEGER) AS parent_pid,
            {_get_field(event_cols, has_raw, ["parent_process_name", "process_parent_name"], '$."process.parent.name"', '$.process.parent.name', '$.parent_process_name', '$."data.win.eventdata.parentImage"')} AS parent_process_name,
            {_get_field(event_cols, has_raw, ["raw_json"], default="'{}'")} AS raw_json,
            {_get_field(event_cols, has_raw, ["timestamp", "@timestamp", "time"], '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
            {_get_field(event_cols, has_raw, ["user_id", "source_user", "username"], '$."user.id"', '$.user.id', '$.user_id')} AS user_id
        FROM main.{source_table}
        WHERE {_safe_coalesce(*cmd_chk, *_jextract(has_raw, '$."process.command_line"', '$.process.command_line', '$.command_line', '$."data.win.eventdata.commandLine"'))} IS NOT NULL
           OR {_safe_coalesce(*exe_chk, *_jextract(has_raw, '$."process.executable"', '$.process.executable', '$.executable'))} IS NOT NULL
           OR {_get_field(event_cols, has_raw, ["event_code", "rule_id", "code"], '$."event.code"', '$.event.code', '$.event_code', '$."rule.id"')} IN ('1', '4688')
           OR {_get_field(event_cols, has_raw, ["action", "event_action"], '$."event.action"', '$.action')} LIKE '%process%'
           OR {_get_field(event_cols, has_raw, ["action", "event_action"], '$."event.action"', '$.action')} LIKE '%start%'
           OR {_get_field(event_cols, has_raw, ["action", "event_action"], '$."event.action"', '$.action')} LIKE '%create%'
           OR {_get_field(event_cols, has_raw, ["parent_entity_id"], '$."process.parent.entity_id"', '$.process.parent.entity_id', '$.parent_entity_id')} IS NOT NULL
           OR ({_get_field(event_cols, has_raw, ["category"], '$."event.category"', '$.category')} LIKE '%process%' AND {_safe_coalesce(*pname_chk, *_jextract(has_raw, '$."process.name"', '$.process.name', '$.process_name'))} IS NOT NULL);
    """


def _build_processes_view(source_table: str, event_cols: set, has_raw: bool, main_objects: set, has_rows, get_cols) -> str:
    proc_cols = get_cols("processes")
    if has_rows("processes") and {"process_entity_id", "process_name", "pid"}.issubset(proc_cols):
        return _build_processes_from_table(proc_cols, main_objects, event_cols)
    return _synthesize_processes_from_events(source_table, event_cols, has_raw)


def _build_files_from_table(file_cols: set, main_objects: set, event_cols: set) -> str:
    fid_expr = _col_or_fallback("f", "file_id", file_cols, "f.rowid AS file_id")
    eid_expr = _col_or_fallback("f", "event_id", file_cols, _NULL_EVENT_ID)
    peid_expr = _col_or_fallback("f", "process_entity_id", file_cols, _NULL_PROCESS_ENTITY_ID)
    ext_expr = _coalesce_col_or_json("f", "extension", file_cols, '$."file.extension"', '$.file.extension', '$.extension')
    sz_expr = _coalesce_col_or_json("f", "size", file_cols, '$."file.size"', '$.file.size', '$.size', cast="INTEGER")
    sha_expr = _coalesce_col_or_json("f", "sha256", file_cols, '$."file.hash.sha256"', '$.file.hash.sha256', '$.file.sha256', '$.sha256', '$.file_hash')
    raw_expr = _col_or_fallback("f", "raw_json", file_cols, _EMPTY_RAW_JSON)
    join_clause = _build_events_join("f", file_cols, main_objects, event_cols)
    ts_expr = _resolve_joined_ts("f", file_cols, join_clause, event_cols)
    hid_expr = _resolve_joined_host_id("f", file_cols, join_clause, event_cols)
    uid_expr = _resolve_joined_user_id("f", file_cols, join_clause, event_cols)

    return f"""
        CREATE TEMP VIEW IF NOT EXISTS files AS
        SELECT {fid_expr}, {eid_expr}, {peid_expr}, f.file_path, f.file_name,
               {ext_expr}, {sz_expr}, {sha_expr}, {raw_expr},
               {ts_expr}, {hid_expr}, {uid_expr}
        FROM main.files f
        {join_clause};
    """


def _synthesize_files_from_events(source_table: str, event_cols: set, has_raw: bool) -> str:
    file_chk = [c for c in ["file_path", "file_name", "file_hash"] if c in event_cols]
    return f"""
        CREATE TEMP VIEW IF NOT EXISTS files AS
        SELECT 
            rowid AS file_id,
            {_get_field(event_cols, has_raw, ["event_id", "id"], '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
            {_get_field(event_cols, has_raw, ["process_entity_id", "entity_id"], '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id')} AS process_entity_id,
            {_get_field(event_cols, has_raw, ["file_path", "path"], '$."file.path"', '$.file.path', '$.file_path', '$.path')} AS file_path,
            {_get_field(event_cols, has_raw, ["file_name", "name"], '$."file.name"', '$.file.name', '$.file_name', '$.name')} AS file_name,
            {_get_field(event_cols, has_raw, ["extension"], '$."file.extension"', '$.file.extension', '$.file_extension', '$.extension')} AS extension,
            CAST({_get_field(event_cols, has_raw, ["size"], '$."file.size"', '$.file.size', '$.file_size', '$.size', default="0")} AS INTEGER) AS size,
            {_get_field(event_cols, has_raw, ["sha256", "file_hash"], '$."file.hash.sha256"', '$.file.hash.sha256', '$.file.sha256', '$.sha256')} AS sha256,
            {_get_field(event_cols, has_raw, ["raw_json"], default="'{}'")} AS raw_json,
            {_get_field(event_cols, has_raw, ["timestamp", "@timestamp", "time"], '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
            {_get_field(event_cols, has_raw, ["host_id", "agent_id", "agent_name", "hostname"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', default="'unknown'")} AS host_id,
            {_get_field(event_cols, has_raw, ["user_id", "source_user", "username"], '$."user.id"', '$.user.id', '$.user_id')} AS user_id
        FROM main.{source_table}
        WHERE {_safe_coalesce(*file_chk, *_jextract(has_raw, '$."file.path"', '$.file.path', '$."file.name"', '$.file.name', '$.file_path'))} IS NOT NULL
           OR {_get_field(event_cols, has_raw, ["category"], '$."event.category"', '$.category')} LIKE '%file%'
           OR {_get_field(event_cols, has_raw, ["action", "event_action"], '$."event.action"', '$.action')} LIKE '%file%';
    """


def _build_files_view(source_table: str, event_cols: set, has_raw: bool, main_objects: set, has_rows, get_cols) -> str:
    file_cols = get_cols("files")
    if has_rows("files") and {"file_path", "file_name"}.issubset(file_cols):
        return _build_files_from_table(file_cols, main_objects, event_cols)
    return _synthesize_files_from_events(source_table, event_cols, has_raw)


def _build_network_from_table(net_cols: set, main_objects: set, event_cols: set) -> str:
    nid_expr = _col_or_fallback("nc", "network_id", net_cols, "nc.rowid AS network_id")
    eid_expr = _col_or_fallback("nc", "event_id", net_cols, _NULL_EVENT_ID)
    peid_expr = _col_or_fallback("nc", "process_entity_id", net_cols, _NULL_PROCESS_ENTITY_ID)
    sport_expr = _coalesce_col_or_json("nc", "source_port", net_cols, '$."source.port"', '$.source.port', '$.source_port', '$.src_port', cast="INTEGER")
    dport_expr = _coalesce_col_or_json("nc", "destination_port", net_cols, '$."destination.port"', '$.destination.port', '$.destination_port', '$.dest_port', '$.dst_port', cast="INTEGER")
    proto_expr = _col_or_fallback("nc", "protocol", net_cols, "'tcp' AS protocol")
    raw_expr = _col_or_fallback("nc", "raw_json", net_cols, _EMPTY_RAW_JSON)
    join_clause = _build_events_join("nc", net_cols, main_objects, event_cols)
    ts_expr = _resolve_joined_ts("nc", net_cols, join_clause, event_cols)
    hid_expr = _resolve_joined_host_id("nc", net_cols, join_clause, event_cols)
    uid_expr = _resolve_joined_user_id("nc", net_cols, join_clause, event_cols)

    return f"""
        CREATE TEMP VIEW IF NOT EXISTS network_connections AS
        SELECT {nid_expr}, {eid_expr}, {peid_expr}, nc.source_ip, {sport_expr},
               nc.destination_ip, {dport_expr}, {proto_expr}, {raw_expr},
               {ts_expr}, {hid_expr}, {hid_expr} AS source_host_id, NULL AS destination_host_id, {uid_expr}
        FROM main.network_connections nc
        {join_clause};
    """


def _synthesize_network_from_events(source_table: str, event_cols: set, has_raw: bool) -> str:
    dst_chk = [c for c in ["destination_ip", "dest_ip", "network_dst", "dst_ip"] if c in event_cols]
    src_chk = [c for c in ["source_ip", "src_ip"] if c in event_cols]

    return f"""
        CREATE TEMP VIEW IF NOT EXISTS network_connections AS
        SELECT 
            rowid AS network_id,
            {_get_field(event_cols, has_raw, ["event_id", "id"], '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
            {_get_field(event_cols, has_raw, ["process_entity_id", "entity_id"], '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id')} AS process_entity_id,
            {_get_field(event_cols, has_raw, ["source_ip", "src_ip"], '$."source.ip"', '$.source.ip', '$.source_ip', '$.src_ip')} AS source_ip,
            CAST({_get_field(event_cols, has_raw, ["source_port", "src_port"], '$."source.port"', '$.source.port', '$.source_port', '$.src_port')} AS INTEGER) AS source_port,
            {_get_field(event_cols, has_raw, ["destination_ip", "dest_ip", "network_dst", "dst_ip"], '$."destination.ip"', '$.destination.ip', '$.destination_ip', '$.dst_ip', '$.dest_ip')} AS destination_ip,
            CAST({_get_field(event_cols, has_raw, ["destination_port", "dest_port", "network_dst_port", "dst_port"], '$."destination.port"', '$.destination.port', '$.destination_port', '$.dst_port', '$.dest_port')} AS INTEGER) AS destination_port,
            {_get_field(event_cols, has_raw, ["protocol", "network_protocol", "proto"], '$."network.protocol"', '$.network.protocol', '$.protocol', default="'tcp'")} AS protocol,
            {_get_field(event_cols, has_raw, ["raw_json"], default="'{}'")} AS raw_json,
            {_get_field(event_cols, has_raw, ["timestamp", "@timestamp", "time"], '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
            {_get_field(event_cols, has_raw, ["host_id", "agent_id", "agent_name", "hostname", "asset_id", "src_ip"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', default="'unknown'")} AS host_id,
            {_get_field(event_cols, has_raw, ["host_id", "agent_id", "agent_name", "hostname", "asset_id", "src_ip"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', default="'unknown'")} AS source_host_id,
            NULL AS destination_host_id,
            {_get_field(event_cols, has_raw, ["user_id", "source_user", "username"], '$."user.id"', '$.user.id', '$.user_id')} AS user_id
        FROM main.{source_table}
        WHERE {_safe_coalesce(*dst_chk, *_jextract(has_raw, '$."destination.ip"', '$.destination.ip', '$.dest_ip', '$.dst_ip'))} IS NOT NULL
           OR ({_get_field(event_cols, has_raw, ["category"], '$."event.category"', '$.category')} LIKE '%network%' AND {_safe_coalesce(*src_chk, *_jextract(has_raw, '$."source.ip"', '$.source.ip', '$.src_ip'))} IS NOT NULL)
           OR ({_get_field(event_cols, has_raw, ["action", "event_action"], '$."event.action"', '$.action')} LIKE '%network%' AND {_safe_coalesce(*src_chk, *_jextract(has_raw, '$."source.ip"', '$.source.ip', '$.src_ip'))} IS NOT NULL);
    """


def _build_network_connections_view(source_table: str, event_cols: set, has_raw: bool, main_objects: set, has_rows, get_cols) -> str:
    net_cols = get_cols("network_connections")
    if has_rows("network_connections") and {"destination_ip", "source_ip"}.issubset(net_cols):
        return _build_network_from_table(net_cols, main_objects, event_cols)
    return _synthesize_network_from_events(source_table, event_cols, has_raw)


def _build_registry_from_table(reg_cols: set, main_objects: set, event_cols: set) -> str:
    rid_expr = _col_or_fallback("r", "registry_id", reg_cols, "r.rowid AS registry_id")
    eid_expr = _col_or_fallback("r", "event_id", reg_cols, _NULL_EVENT_ID)
    peid_expr = _col_or_fallback("r", "process_entity_id", reg_cols, _NULL_PROCESS_ENTITY_ID)
    rkey_expr = _coalesce_col_or_json("r", "registry_key", reg_cols, '$."registry.key"', '$.registry.key', '$.registry_key')
    rval_expr = _coalesce_col_or_json("r", "registry_value", reg_cols, '$."registry.value"', '$.registry.value', '$.registry_value')
    vtype_expr = _coalesce_col_or_json("r", "value_type", reg_cols, '$."registry.value_type"', '$.registry.value_type', '$.value_type')
    raw_expr = _col_or_fallback("r", "raw_json", reg_cols, _EMPTY_RAW_JSON)
    join_clause = _build_events_join("r", reg_cols, main_objects, event_cols)
    ts_expr = _resolve_joined_ts("r", reg_cols, join_clause, event_cols)
    hid_expr = _resolve_joined_host_id("r", reg_cols, join_clause, event_cols)
    uid_expr = _resolve_joined_user_id("r", reg_cols, join_clause, event_cols)

    return f"""
        CREATE TEMP VIEW IF NOT EXISTS registry_events AS
        SELECT {rid_expr}, {eid_expr}, {peid_expr}, r.registry_path,
               {rkey_expr}, {rval_expr}, {vtype_expr}, {raw_expr},
               {ts_expr}, {hid_expr}, {uid_expr}
        FROM main.registry_events r
        {join_clause};
    """


def _synthesize_registry_from_events(source_table: str, event_cols: set, has_raw: bool) -> str:
    reg_chk = [c for c in ["registry_path", "registry_key", "registry_value"] if c in event_cols]
    return f"""
        CREATE TEMP VIEW IF NOT EXISTS registry_events AS
        SELECT 
            rowid AS registry_id,
            {_get_field(event_cols, has_raw, ["event_id", "id"], '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
            {_get_field(event_cols, has_raw, ["process_entity_id", "entity_id"], '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id')} AS process_entity_id,
            {_get_field(event_cols, has_raw, ["registry_path"], '$."registry.path"', '$.registry.path', '$.registry_path')} AS registry_path,
            {_get_field(event_cols, has_raw, ["registry_key"], '$."registry.key"', '$.registry.key', '$.registry_key')} AS registry_key,
            {_get_field(event_cols, has_raw, ["registry_value"], '$."registry.value"', '$.registry.value', '$.registry_value')} AS registry_value,
            {_get_field(event_cols, has_raw, ["value_type"], '$."registry.value_type"', '$.registry.value_type', '$.value_type')} AS value_type,
            {_get_field(event_cols, has_raw, ["raw_json"], default="'{}'")} AS raw_json,
            {_get_field(event_cols, has_raw, ["timestamp", "@timestamp", "time"], '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
            {_get_field(event_cols, has_raw, ["host_id", "agent_id", "agent_name", "hostname"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', default="'unknown'")} AS host_id,
            {_get_field(event_cols, has_raw, ["user_id", "source_user", "username"], '$."user.id"', '$.user.id', '$.user_id')} AS user_id
        FROM main.{source_table}
        WHERE {_safe_coalesce(*reg_chk, *_jextract(has_raw, '$."registry.path"', '$.registry.path', '$."registry.key"', '$.registry.key'))} IS NOT NULL
           OR {_get_field(event_cols, has_raw, ["category"], '$."event.category"', '$.category')} LIKE '%registry%'
           OR {_get_field(event_cols, has_raw, ["action", "event_action"], '$."event.action"', '$.action')} LIKE '%registry%';
    """


def _build_registry_events_view(source_table: str, event_cols: set, has_raw: bool, main_objects: set, has_rows, get_cols) -> str:
    reg_cols = get_cols("registry_events")
    if has_rows("registry_events") and {"registry_path"}.issubset(reg_cols):
        return _build_registry_from_table(reg_cols, main_objects, event_cols)
    return _synthesize_registry_from_events(source_table, event_cols, has_raw)


def _build_hosts_view(source_table: str, event_cols: set, has_raw: bool, main_objects: set, has_rows, get_cols) -> str:
    host_tbl = _find_host_table(main_objects)
    if host_tbl and has_rows(host_tbl):
        host_cols = get_cols(host_tbl)
        hid_expr, hname_expr, hname_alias = _resolve_host_cols(host_cols)
        ip_expr = "ip_address" if "ip_address" in host_cols else "NULL AS ip_address"
        raw_expr = "raw_json" if "raw_json" in host_cols else _EMPTY_RAW_JSON
        return f"""
            CREATE TEMP VIEW IF NOT EXISTS hosts AS
            SELECT 
                {hid_expr} AS host_id,
                {hname_expr} AS host_name,
                {hname_alias} AS hostname,
                {ip_expr},
                {raw_expr}
            FROM main.{host_tbl};
        """

    target_hid = _get_field(event_cols, has_raw, ["host_id", "agent_id", "agent_name", "hostname", "asset_id", "src_ip"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', '$.src_ip')
    return f"""
        CREATE TEMP VIEW IF NOT EXISTS hosts AS
        SELECT 
            {target_hid} AS host_id,
            COALESCE(MAX({_safe_coalesce(*[c for c in ["hostname", "agent_name", "src_ip"] if c in event_cols], *_jextract(has_raw, '$."host.name"', '$.host.name', '$.host.hostname', '$.hostname'))}), {target_hid}) AS host_name,
            COALESCE(MAX({_safe_coalesce(*[c for c in ["hostname", "agent_name", "src_ip"] if c in event_cols], *_jextract(has_raw, '$."host.hostname"', '$.host.hostname', '$.hostname'))}), {target_hid}) AS hostname,
            COALESCE(
                MAX({_safe_coalesce(*[c for c in ["ip_address"] if c in event_cols], *_jextract(has_raw, '$."host.ip"', '$.host.ip', '$.ip_address'))}),
                MAX(CASE WHEN {_safe_coalesce(*[c for c in ["source_ip", "src_ip"] if c in event_cols], *_jextract(has_raw, '$."source.ip"', '$.source.ip', '$.src_ip'))} IS NOT NULL THEN {_safe_coalesce(*[c for c in ["source_ip", "src_ip"] if c in event_cols], *_jextract(has_raw, '$."source.ip"', '$.source.ip', '$.src_ip'))} ELSE NULL END)
            ) AS ip_address,
            {_get_field(event_cols, has_raw, ["raw_json"], default="'{}'")} AS raw_json
        FROM main.{source_table}
        WHERE {target_hid} IS NOT NULL AND {target_hid} <> ''
        GROUP BY 1;
    """


def _build_users_view(source_table: str, event_cols: set, has_raw: bool, main_objects: set, has_rows, get_cols) -> str:
    user_cols = get_cols("users")
    if has_rows("users"):
        uname_expr, uname_alias = _resolve_user_cols(user_cols)
        raw_expr = "raw_json" if "raw_json" in user_cols else _EMPTY_RAW_JSON
        return f"""
            CREATE TEMP VIEW IF NOT EXISTS users AS
            SELECT 
                user_id,
                {uname_expr} AS user_name,
                {uname_alias} AS username,
                {raw_expr}
            FROM main.users;
        """

    if "network_assets" in main_objects and has_rows("network_assets"):
        return """
            CREATE TEMP VIEW IF NOT EXISTS users AS
            SELECT 
                COALESCE(json_extract(raw_json, '$.owner'), 'user-' || rowid) AS user_id,
                COALESCE(json_extract(raw_json, '$.owner'), 'Asset Owner ' || rowid) AS user_name,
                COALESCE(json_extract(raw_json, '$.owner'), 'Asset Owner ' || rowid) AS username,
                raw_json
            FROM main.network_assets
            WHERE json_extract(raw_json, '$.owner') IS NOT NULL;
        """

    target_uid = _get_field(event_cols, has_raw, ["user_id", "source_user", "username"], '$."user.id"', '$.user.id', '$.user_id')
    return f"""
        CREATE TEMP VIEW IF NOT EXISTS users AS
        SELECT 
            {target_uid} AS user_id,
            COALESCE({_safe_coalesce(*[c for c in ["username", "source_user"] if c in event_cols], *_jextract(has_raw, '$."user.name"', '$.user.name', '$.user_name', '$.username'))}, {target_uid}) AS user_name,
            COALESCE({_safe_coalesce(*[c for c in ["username", "source_user"] if c in event_cols], *_jextract(has_raw, '$."user.name"', '$.user.name', '$.user_name', '$.username'))}, {target_uid}) AS username,
            {_get_field(event_cols, has_raw, ["raw_json"], default="'{}'")} AS raw_json
        FROM main.{source_table}
        WHERE {target_uid} IS NOT NULL AND {target_uid} <> ''
        GROUP BY 1;
    """


class EndpointDatabase:
    """Safe, read-only interface to the endpoint security telemetry SQLite database."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or get_db_path())
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found at: {self.db_path}")
        self._conn: Optional[sqlite3.Connection] = None

    def _find_source_events_table(self, cur: sqlite3.Cursor, main_objects: set) -> Optional[str]:
        for candidate in (
            "events", "wazuh_events", "suricata_events", "eve_events", "alerts", "agent_events",
            "network_events", "flow_events", "edr_events", "siem_events", "telemetry", "logs", "sysmon", "security_events"
        ):
            if candidate in main_objects:
                return candidate
        
        best_table = None
        max_rows = -1
        for obj in main_objects:
            if obj.startswith("sqlite_"):
                continue
            try:
                cur.execute(f"PRAGMA main.table_info({obj});")
                cols = {r[1].lower() for r in cur.fetchall()}
                if any(t in cols for t in ("timestamp", "@timestamp", "time", "event_time", "datetime")):
                    cur.execute(f"SELECT count(*) FROM main.{obj};")
                    cnt = cur.fetchone()[0]
                    if cnt > max_rows:
                        max_rows = cnt
                        best_table = obj
            except Exception:
                continue
        return best_table

    def _init_temp_views(self, conn: sqlite3.Connection) -> None:
        """Create in-memory virtual adapter views.
        
        If a database already has populated relational tables (processes, files, etc.),
        this ensures convenience fields (timestamp, host_id) are projected safely.
        
        If a database only has raw telemetry in `events` (or sub-tables are missing/empty),
        this automatically synthesizes relational tables (`processes`, `files`,
        `network_connections`, `registry_events`, `hosts`, `users`, `agent_events`)
        in-memory directly from `events.raw_json` using SQLite's native `json_extract()`.
        
        Zero database mutation on disk: all views live exclusively in SQLite session RAM.
        """
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view');")
            main_objects = {row[0] for row in cur.fetchall()}

            source_table = self._find_source_events_table(cur, main_objects)
            if not source_table:
                return

            def has_rows(tbl: str) -> bool:
                try:
                    c = conn.cursor()
                    c.execute(f"SELECT 1 FROM main.{tbl} LIMIT 1;")
                    return c.fetchone() is not None
                except Exception:
                    return False

            def get_cols(tbl: str) -> set:
                try:
                    c = conn.cursor()
                    c.execute(f"PRAGMA main.table_info({tbl});")
                    return {row[1] for row in c.fetchall()}
                except Exception:
                    return set()

            event_cols = get_cols(source_table)
            has_raw = "raw_json" in event_cols

            stmts = []
            ev_view = _build_events_view(source_table, event_cols, has_raw)
            if ev_view:
                stmts.append(ev_view)

            stmts.extend([
                _build_processes_view(source_table, event_cols, has_raw, main_objects, has_rows, get_cols),
                _build_files_view(source_table, event_cols, has_raw, main_objects, has_rows, get_cols),
                _build_network_connections_view(source_table, event_cols, has_raw, main_objects, has_rows, get_cols),
                _build_registry_events_view(source_table, event_cols, has_raw, main_objects, has_rows, get_cols),
                _build_hosts_view(source_table, event_cols, has_raw, main_objects, has_rows, get_cols),
                _build_users_view(source_table, event_cols, has_raw, main_objects, has_rows, get_cols),
            ])

            if "agent_events" not in main_objects or source_table != "events":
                stmts.append("CREATE TEMP VIEW IF NOT EXISTS agent_events AS SELECT * FROM events;")

            for s in stmts:
                cur.execute(s)
        except Exception:
            pass

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            # Open in SQLite URI read-only mode to prevent any writes at the file driver level
            uri = f"file:{self.db_path.resolve().as_posix()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._init_temp_views(conn)
            self._conn = conn
        return self._conn

    def close(self) -> None:
        """Close active cached connection if open."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def execute_query(self, sql: str, params: tuple = (), max_rows: int = 50) -> List[Dict[str, Any]]:
        """Execute a read-only SQL query safely."""
        clean_sql = sql.strip()
        if not clean_sql:
            return []

        # Disallow mutation statements
        disallowed = ["insert", "update", "delete", "drop", "alter", "create", "attach", "detach", "vacuum", "reindex"]
        first_word = clean_sql.split()[0].lower()
        if first_word in disallowed or ";" in clean_sql.rstrip(";"):
            raise DatabaseAccessError("Security violation: Only single read-only SELECT queries are permitted.")
        
        if not first_word.startswith(("select", "pragma", "with")):
            raise DatabaseAccessError(f"Disallowed query type: '{first_word}'. Only SELECT queries are permitted.")

        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(clean_sql, params)
        rows = cursor.fetchmany(max_rows)
        return [dict(row) for row in rows]

    def get_schema(self) -> Dict[str, List[str]]:
        """Return table and view names along with their column names."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'
            UNION
            SELECT name FROM sqlite_temp_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%';
        """)
        items = cursor.fetchall()
        schema_info = {}
        for item in items:
            name = item["name"]
            c_cursor = conn.cursor()
            c_cursor.execute(f"PRAGMA table_info('{name}');")
            cols = [col["name"] for col in c_cursor.fetchall()]
            schema_info[name] = cols
        return schema_info


_active_db: Optional[EndpointDatabase] = None


def get_active_db(db_path: Optional[Any] = None) -> EndpointDatabase:
    """Return the cached EndpointDatabase for the currently active DB path (or specified path)."""
    global _active_db
    current_path = Path(db_path) if db_path else get_db_path()
    if _active_db is None or _active_db.db_path != current_path:
        if _active_db is not None:
            _active_db.close()
        _active_db = EndpointDatabase(current_path)
    return _active_db


def reset_active_db() -> None:
    """Reset and close the cached active database instance."""
    global _active_db
    if _active_db is not None:
        _active_db.close()
        _active_db = None
