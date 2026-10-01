import sqlite3
from typing import Any, Dict, List, Optional
from pathlib import Path
from a1.config import get_db_path

class DatabaseAccessError(Exception):
    pass

class EndpointDatabase:
    """Safe, read-only interface to the endpoint security telemetry SQLite database."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or get_db_path())
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found at: {self.db_path}")
        self._conn: Optional[sqlite3.Connection] = None

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

            # 1. Discover primary events/telemetry source table
            def find_source_events_table() -> Optional[str]:
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

            source_table = find_source_events_table()
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

            def safe_coalesce(*items: str) -> str:
                """Combine non-empty expressions into a single valid COALESCE."""
                clean = [it.strip() for it in items if it and it.strip() != "NULL"]
                if not clean:
                    return "NULL"
                if len(clean) == 1:
                    return clean[0]
                return f"COALESCE({', '.join(clean)})"

            def jextract(*paths: str) -> List[str]:
                """Return list of json_extract expressions for raw_json."""
                if not has_raw:
                    return []
                return [f"json_extract(raw_json, '{p}')" for p in paths]

            def get_field(cols: Any, *raw_paths: str, default: Optional[str] = None) -> str:
                """Extract field from matching event column(s), raw_json paths, or fallback default."""
                parts = []
                if isinstance(cols, str):
                    cols = [cols]
                for c in cols:
                    if c in event_cols:
                        parts.append(c)
                parts.extend(jextract(*raw_paths))
                if default is not None:
                    parts.append(default)
                return safe_coalesce(*parts)

            stmts = []

            # 0. EVENTS: If source_table is not 'events' or missing standard columns, project an augmented events view
            required_event_cols = {
                "event_id", "timestamp", "provider", "event_code", "category",
                "event_type", "action", "outcome", "severity", "host_id",
                "user_id", "process_entity_id", "raw_json"
            }
            if source_table != "events" or not required_event_cols.issubset(event_cols):
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS events AS
                    SELECT 
                        {get_field(["event_id", "id"], '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
                        {get_field(["timestamp", "@timestamp", "time", "event_time"], '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
                        {get_field(["provider", "manager", "sensor"], '$."event.provider"', '$.event.provider', '$.provider', default="'Suricata'")} AS provider,
                        {get_field(["event_code", "rule_id", "code", "alert_signature_id", "signature_id"], '$."event.code"', '$.event.code', '$.event_code', '$."rule.id"', default="'1'")} AS event_code,
                        {get_field(["category", "rule_groups", "alert_category"], '$."event.category"', '$.event.category', '$.category', default="'network'")} AS category,
                        {get_field(["event_type", "subcategory", "app_proto"], '$."event.type"', '$.event.type', '$.type', default="'alert'")} AS event_type,
                        {get_field(["action", "event_action", "rule_description", "alert_signature", "signature"], '$."event.action"', '$.event.action', '$.action', default=get_field(["event_type", "app_proto"], default="'alert'"))} AS action,
                        {get_field(["outcome", "status"], '$."event.outcome"', '$.event.outcome', '$.outcome', default="'success'")} AS outcome,
                        {get_field(["severity", "rule_level", "alert_severity"], '$."event.severity"', '$.event.severity', '$.severity', default="0")} AS severity,
                        {get_field(["host_id", "agent_id", "agent_name", "hostname", "asset_id", "src_ip"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', '$.src_ip', default="'unknown'")} AS host_id,
                        {get_field(["user_id", "source_user", "username"], '$."user.id"', '$.user.id', '$.user_id', '$."user.name"', '$.user.name', default="'unknown'")} AS user_id,
                        {get_field(["process_entity_id", "entity_id"], '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id', default="'proc-' || rowid")} AS process_entity_id,
                        {get_field(["raw_json"], default="'{}'")} AS raw_json
                    FROM main.{source_table};
                """)

            # 1. PROCESSES
            proc_cols = get_cols("processes")
            if has_rows("processes") and {"process_entity_id", "process_name", "pid"}.issubset(proc_cols):
                eid_expr = "p.event_id" if "event_id" in proc_cols else "NULL AS event_id"
                hid_expr = "p.host_id" if "host_id" in proc_cols else ("e.host_id" if ("events" in main_objects and "host_id" in event_cols) else "NULL AS host_id")
                exe_expr = "p.executable" if "executable" in proc_cols else "NULL AS executable"
                peid_expr = "COALESCE(p.parent_entity_id, json_extract(p.raw_json, '$.\"process.parent.entity_id\"'), json_extract(p.raw_json, '$.process.parent.entity_id'), json_extract(p.raw_json, '$.parent_entity_id')) AS parent_entity_id" if "parent_entity_id" in proc_cols else "COALESCE(json_extract(p.raw_json, '$.\"process.parent.entity_id\"'), json_extract(p.raw_json, '$.process.parent.entity_id'), json_extract(p.raw_json, '$.parent_entity_id')) AS parent_entity_id"
                ppid_expr = "COALESCE(p.parent_pid, CAST(json_extract(p.raw_json, '$.\"process.parent.pid\"') AS INTEGER), CAST(json_extract(p.raw_json, '$.process.parent.pid') AS INTEGER), CAST(json_extract(p.raw_json, '$.parent_pid') AS INTEGER)) AS parent_pid" if "parent_pid" in proc_cols else "COALESCE(CAST(json_extract(p.raw_json, '$.\"process.parent.pid\"') AS INTEGER), CAST(json_extract(p.raw_json, '$.process.parent.pid') AS INTEGER), CAST(json_extract(p.raw_json, '$.parent_pid') AS INTEGER)) AS parent_pid"
                p_pname_expr = "COALESCE(p.parent_process_name, json_extract(p.raw_json, '$.\"process.parent.name\"'), json_extract(p.raw_json, '$.process.parent.name'), json_extract(p.raw_json, '$.process_parent_name')) AS parent_process_name" if "parent_process_name" in proc_cols else "COALESCE(json_extract(p.raw_json, '$.\"process.parent.name\"'), json_extract(p.raw_json, '$.process.parent.name'), json_extract(p.raw_json, '$.process_parent_name')) AS parent_process_name"
                cmd_expr = "COALESCE(p.command_line, json_extract(p.raw_json, '$.\"process.command_line\"'), json_extract(p.raw_json, '$.process.command_line'), json_extract(p.raw_json, '$.process_cmdline')) AS command_line" if "command_line" in proc_cols else "COALESCE(json_extract(p.raw_json, '$.\"process.command_line\"'), json_extract(p.raw_json, '$.process.command_line'), json_extract(p.raw_json, '$.process_cmdline')) AS command_line"
                raw_expr = "p.raw_json" if "raw_json" in proc_cols else "'{}' AS raw_json"
                join_clause = "LEFT JOIN main.events e ON p.event_id = e.event_id" if ("events" in main_objects and "event_id" in proc_cols and "event_id" in event_cols) else ""
                ts_expr = "e.timestamp" if join_clause and "timestamp" in event_cols else ("p.timestamp" if "timestamp" in proc_cols else "COALESCE(json_extract(p.raw_json, '$.\"@timestamp\"'), json_extract(p.raw_json, '$.@timestamp'), json_extract(p.raw_json, '$.timestamp')) AS timestamp")
                uid_expr = "e.user_id" if join_clause and "user_id" in event_cols else ("p.user_id" if "user_id" in proc_cols else "COALESCE(json_extract(p.raw_json, '$.\"user.id\"'), json_extract(p.raw_json, '$.user.id'), json_extract(p.raw_json, '$.user_id')) AS user_id")

                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS processes AS
                    SELECT p.process_entity_id, {eid_expr}, {hid_expr}, p.pid, p.process_name,
                           {exe_expr}, {cmd_expr}, {peid_expr}, {ppid_expr}, {p_pname_expr}, {raw_expr},
                           {ts_expr}, {uid_expr}
                    FROM main.processes p
                    {join_clause};
                """)
            else:
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS processes AS
                    SELECT 
                        {get_field(["process_entity_id", "entity_id"], '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id', '$.entity_id', default="'proc-' || rowid")} AS process_entity_id,
                        {get_field(["event_id", "id"], '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
                        {get_field(["host_id", "agent_id", "agent_name", "hostname"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', default="'unknown'")} AS host_id,
                        CAST({get_field(["pid", "process_id"], '$."process.pid"', '$.process.pid', '$.process_pid', '$."data.win.eventdata.processId"', default="0")} AS INTEGER) AS pid,
                        {get_field(["process_name", "name"], '$."process.name"', '$.process.name', '$.process_name', '$."data.win.eventdata.image"', default="'unknown'")} AS process_name,
                        {get_field(["executable", "process_path"], '$."process.executable"', '$.process.executable', '$.executable', '$."data.win.eventdata.image"')} AS executable,
                        {get_field(["command_line", "process_cmdline"], '$."process.command_line"', '$.process.command_line', '$.command_line', '$."data.win.eventdata.commandLine"')} AS command_line,
                        {get_field(["parent_entity_id"], '$."process.parent.entity_id"', '$.process.parent.entity_id', '$.parent_entity_id', '$.parent.process_entity_id')} AS parent_entity_id,
                        CAST({get_field(["parent_pid", "process_parent_id"], '$."process.parent.pid"', '$.process.parent.pid', '$.parent_pid', '$."data.win.eventdata.parentProcessId"')} AS INTEGER) AS parent_pid,
                        {get_field(["parent_process_name", "process_parent_name"], '$."process.parent.name"', '$.process.parent.name', '$.parent_process_name', '$."data.win.eventdata.parentImage"')} AS parent_process_name,
                        {get_field(["raw_json"], default="'{}'")} AS raw_json,
                        {get_field(["timestamp", "@timestamp", "time"], '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
                        {get_field(["user_id", "source_user", "username"], '$."user.id"', '$.user.id', '$.user_id')} AS user_id
                    FROM main.{source_table}
                    WHERE {safe_coalesce(*[c for c in ["command_line", "process_cmdline"] if c in event_cols], *jextract('$."process.command_line"', '$.process.command_line', '$.command_line', '$."data.win.eventdata.commandLine"'))} IS NOT NULL
                       OR {safe_coalesce(*[c for c in ["executable", "process_path"] if c in event_cols], *jextract('$."process.executable"', '$.process.executable', '$.executable'))} IS NOT NULL
                       OR {get_field(["event_code", "rule_id", "code"], '$."event.code"', '$.event.code', '$.event_code', '$."rule.id"')} IN ('1', '4688')
                       OR {get_field(["action", "event_action"], '$."event.action"', '$.action')} LIKE '%process%'
                       OR {get_field(["action", "event_action"], '$."event.action"', '$.action')} LIKE '%start%'
                       OR {get_field(["action", "event_action"], '$."event.action"', '$.action')} LIKE '%create%'
                       OR {get_field(["parent_entity_id"], '$."process.parent.entity_id"', '$.process.parent.entity_id', '$.parent_entity_id')} IS NOT NULL
                       OR ({get_field(["category"], '$."event.category"', '$.category')} LIKE '%process%' AND {safe_coalesce(*[c for c in ["process_name", "name"] if c in event_cols], *jextract('$."process.name"', '$.process.name', '$.process_name'))} IS NOT NULL);
                """)

            # 2. FILES
            file_cols = get_cols("files")
            if has_rows("files") and {"file_path", "file_name"}.issubset(file_cols):
                fid_expr = "f.file_id" if "file_id" in file_cols else "f.rowid AS file_id"
                eid_expr = "f.event_id" if "event_id" in file_cols else "NULL AS event_id"
                peid_expr = "f.process_entity_id" if "process_entity_id" in file_cols else "NULL AS process_entity_id"
                ext_expr = "COALESCE(f.extension, json_extract(f.raw_json, '$.\"file.extension\"'), json_extract(f.raw_json, '$.file.extension'), json_extract(f.raw_json, '$.extension')) AS extension" if "extension" in file_cols else "COALESCE(json_extract(f.raw_json, '$.\"file.extension\"'), json_extract(f.raw_json, '$.file.extension'), json_extract(f.raw_json, '$.extension')) AS extension"
                sz_expr = "COALESCE(f.size, CAST(json_extract(f.raw_json, '$.\"file.size\"') AS INTEGER), CAST(json_extract(f.raw_json, '$.file.size') AS INTEGER), CAST(json_extract(f.raw_json, '$.size') AS INTEGER)) AS size" if "size" in file_cols else "COALESCE(CAST(json_extract(f.raw_json, '$.\"file.size\"') AS INTEGER), CAST(json_extract(f.raw_json, '$.file.size') AS INTEGER), CAST(json_extract(f.raw_json, '$.size') AS INTEGER)) AS size"
                sha_expr = "COALESCE(f.sha256, json_extract(f.raw_json, '$.\"file.hash.sha256\"'), json_extract(f.raw_json, '$.file.hash.sha256'), json_extract(f.raw_json, '$.file.sha256'), json_extract(f.raw_json, '$.sha256'), json_extract(f.raw_json, '$.file_hash')) AS sha256" if "sha256" in file_cols else "COALESCE(json_extract(f.raw_json, '$.\"file.hash.sha256\"'), json_extract(f.raw_json, '$.file.hash.sha256'), json_extract(f.raw_json, '$.file.sha256'), json_extract(f.raw_json, '$.sha256'), json_extract(f.raw_json, '$.file_hash')) AS sha256"
                raw_expr = "f.raw_json" if "raw_json" in file_cols else "'{}' AS raw_json"
                join_clause = "LEFT JOIN main.events e ON f.event_id = e.event_id" if ("events" in main_objects and "event_id" in file_cols and "event_id" in event_cols) else ""
                ts_expr = "e.timestamp" if join_clause and "timestamp" in event_cols else ("f.timestamp" if "timestamp" in file_cols else "COALESCE(json_extract(f.raw_json, '$.\"@timestamp\"'), json_extract(f.raw_json, '$.@timestamp'), json_extract(f.raw_json, '$.timestamp')) AS timestamp")
                hid_expr = "e.host_id" if join_clause and "host_id" in event_cols else ("f.host_id" if "host_id" in file_cols else "COALESCE(json_extract(f.raw_json, '$.\"host.id\"'), json_extract(f.raw_json, '$.host.id'), json_extract(f.raw_json, '$.host_id'), 'unknown') AS host_id")
                uid_expr = "e.user_id" if join_clause and "user_id" in event_cols else ("f.user_id" if "user_id" in file_cols else "COALESCE(json_extract(f.raw_json, '$.\"user.id\"'), json_extract(f.raw_json, '$.user.id'), json_extract(f.raw_json, '$.user_id')) AS user_id")

                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS files AS
                    SELECT {fid_expr}, {eid_expr}, {peid_expr}, f.file_path, f.file_name,
                           {ext_expr}, {sz_expr}, {sha_expr}, {raw_expr},
                           {ts_expr}, {hid_expr}, {uid_expr}
                    FROM main.files f
                    {join_clause};
                """)
            else:
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS files AS
                    SELECT 
                        rowid AS file_id,
                        {get_field(["event_id", "id"], '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
                        {get_field(["process_entity_id", "entity_id"], '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id')} AS process_entity_id,
                        {get_field(["file_path", "path"], '$."file.path"', '$.file.path', '$.file_path', '$.path')} AS file_path,
                        {get_field(["file_name", "name"], '$."file.name"', '$.file.name', '$.file_name', '$.name')} AS file_name,
                        {get_field(["extension"], '$."file.extension"', '$.file.extension', '$.file_extension', '$.extension')} AS extension,
                        CAST({get_field(["size"], '$."file.size"', '$.file.size', '$.file_size', '$.size', default="0")} AS INTEGER) AS size,
                        {get_field(["sha256", "file_hash"], '$."file.hash.sha256"', '$.file.hash.sha256', '$.file.sha256', '$.sha256')} AS sha256,
                        {get_field(["raw_json"], default="'{}'")} AS raw_json,
                        {get_field(["timestamp", "@timestamp", "time"], '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
                        {get_field(["host_id", "agent_id", "agent_name", "hostname"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', default="'unknown'")} AS host_id,
                        {get_field(["user_id", "source_user", "username"], '$."user.id"', '$.user.id', '$.user_id')} AS user_id
                    FROM main.{source_table}
                    WHERE {safe_coalesce(*[c for c in ["file_path", "file_name", "file_hash"] if c in event_cols], *jextract('$."file.path"', '$.file.path', '$."file.name"', '$.file.name', '$.file_path'))} IS NOT NULL
                       OR {get_field(["category"], '$."event.category"', '$.category')} LIKE '%file%'
                       OR {get_field(["action", "event_action"], '$."event.action"', '$.action')} LIKE '%file%';
                """)

            # 3. NETWORK_CONNECTIONS
            net_cols = get_cols("network_connections")
            if has_rows("network_connections") and {"destination_ip", "source_ip"}.issubset(net_cols):
                nid_expr = "nc.network_id" if "network_id" in net_cols else "nc.rowid AS network_id"
                eid_expr = "nc.event_id" if "event_id" in net_cols else "NULL AS event_id"
                peid_expr = "nc.process_entity_id" if "process_entity_id" in net_cols else "NULL AS process_entity_id"
                sport_expr = "COALESCE(nc.source_port, CAST(json_extract(nc.raw_json, '$.\"source.port\"') AS INTEGER), CAST(json_extract(nc.raw_json, '$.source.port') AS INTEGER), CAST(json_extract(nc.raw_json, '$.source_port') AS INTEGER), CAST(json_extract(nc.raw_json, '$.src_port') AS INTEGER)) AS source_port" if "source_port" in net_cols else "COALESCE(CAST(json_extract(nc.raw_json, '$.\"source.port\"') AS INTEGER), CAST(json_extract(nc.raw_json, '$.source.port') AS INTEGER), CAST(json_extract(nc.raw_json, '$.source_port') AS INTEGER), CAST(json_extract(nc.raw_json, '$.src_port') AS INTEGER)) AS source_port"
                dport_expr = "COALESCE(nc.destination_port, CAST(json_extract(nc.raw_json, '$.\"destination.port\"') AS INTEGER), CAST(json_extract(nc.raw_json, '$.destination.port') AS INTEGER), CAST(json_extract(nc.raw_json, '$.destination_port') AS INTEGER), CAST(json_extract(nc.raw_json, '$.dest_port') AS INTEGER), CAST(json_extract(nc.raw_json, '$.dst_port') AS INTEGER)) AS destination_port" if "destination_port" in net_cols else "COALESCE(CAST(json_extract(nc.raw_json, '$.\"destination.port\"') AS INTEGER), CAST(json_extract(nc.raw_json, '$.destination.port') AS INTEGER), CAST(json_extract(nc.raw_json, '$.destination_port') AS INTEGER), CAST(json_extract(nc.raw_json, '$.dest_port') AS INTEGER), CAST(json_extract(nc.raw_json, '$.dst_port') AS INTEGER)) AS destination_port"
                proto_expr = "nc.protocol" if "protocol" in net_cols else "'tcp' AS protocol"
                raw_expr = "nc.raw_json" if "raw_json" in net_cols else "'{}' AS raw_json"
                join_clause = "LEFT JOIN main.events e ON nc.event_id = e.event_id" if ("events" in main_objects and "event_id" in net_cols and "event_id" in event_cols) else ""
                ts_expr = "e.timestamp" if join_clause and "timestamp" in event_cols else ("nc.timestamp" if "timestamp" in net_cols else "COALESCE(json_extract(nc.raw_json, '$.\"@timestamp\"'), json_extract(nc.raw_json, '$.@timestamp'), json_extract(nc.raw_json, '$.timestamp')) AS timestamp")
                hid_expr = "e.host_id" if join_clause and "host_id" in event_cols else ("nc.host_id" if "host_id" in net_cols else "COALESCE(json_extract(nc.raw_json, '$.\"host.id\"'), json_extract(nc.raw_json, '$.host.id'), json_extract(nc.raw_json, '$.host_id'), 'unknown') AS host_id")
                uid_expr = "e.user_id" if join_clause and "user_id" in event_cols else ("nc.user_id" if "user_id" in net_cols else "COALESCE(json_extract(nc.raw_json, '$.\"user.id\"'), json_extract(nc.raw_json, '$.user.id'), json_extract(nc.raw_json, '$.user_id')) AS user_id")

                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS network_connections AS
                    SELECT {nid_expr}, {eid_expr}, {peid_expr}, nc.source_ip, {sport_expr},
                           nc.destination_ip, {dport_expr}, {proto_expr}, {raw_expr},
                           {ts_expr}, {hid_expr}, {hid_expr} AS source_host_id, NULL AS destination_host_id, {uid_expr}
                    FROM main.network_connections nc
                    {join_clause};
                """)
            else:
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS network_connections AS
                    SELECT 
                        rowid AS network_id,
                        {get_field(["event_id", "id"], '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
                        {get_field(["process_entity_id", "entity_id"], '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id')} AS process_entity_id,
                        {get_field(["source_ip", "src_ip"], '$."source.ip"', '$.source.ip', '$.source_ip', '$.src_ip')} AS source_ip,
                        CAST({get_field(["source_port", "src_port"], '$."source.port"', '$.source.port', '$.source_port', '$.src_port')} AS INTEGER) AS source_port,
                        {get_field(["destination_ip", "dest_ip", "network_dst", "dst_ip"], '$."destination.ip"', '$.destination.ip', '$.destination_ip', '$.dst_ip', '$.dest_ip')} AS destination_ip,
                        CAST({get_field(["destination_port", "dest_port", "network_dst_port", "dst_port"], '$."destination.port"', '$.destination.port', '$.destination_port', '$.dst_port', '$.dest_port')} AS INTEGER) AS destination_port,
                        {get_field(["protocol", "network_protocol", "proto"], '$."network.protocol"', '$.network.protocol', '$.protocol', default="'tcp'")} AS protocol,
                        {get_field(["raw_json"], default="'{}'")} AS raw_json,
                        {get_field(["timestamp", "@timestamp", "time"], '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
                        {get_field(["host_id", "agent_id", "agent_name", "hostname", "asset_id", "src_ip"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', default="'unknown'")} AS host_id,
                        {get_field(["host_id", "agent_id", "agent_name", "hostname", "asset_id", "src_ip"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', default="'unknown'")} AS source_host_id,
                        NULL AS destination_host_id,
                        {get_field(["user_id", "source_user", "username"], '$."user.id"', '$.user.id', '$.user_id')} AS user_id
                    FROM main.{source_table}
                    WHERE {safe_coalesce(*[c for c in ["destination_ip", "dest_ip", "network_dst", "dst_ip"] if c in event_cols], *jextract('$."destination.ip"', '$.destination.ip', '$.dest_ip', '$.dst_ip'))} IS NOT NULL
                       OR ({get_field(["category"], '$."event.category"', '$.category')} LIKE '%network%' AND {safe_coalesce(*[c for c in ["source_ip", "src_ip"] if c in event_cols], *jextract('$."source.ip"', '$.source.ip', '$.src_ip'))} IS NOT NULL)
                       OR ({get_field(["action", "event_action"], '$."event.action"', '$.action')} LIKE '%network%' AND {safe_coalesce(*[c for c in ["source_ip", "src_ip"] if c in event_cols], *jextract('$."source.ip"', '$.source.ip', '$.src_ip'))} IS NOT NULL);
                """)

            # 4. REGISTRY_EVENTS
            reg_cols = get_cols("registry_events")
            if has_rows("registry_events") and {"registry_path"}.issubset(reg_cols):
                rid_expr = "r.registry_id" if "registry_id" in reg_cols else "r.rowid AS registry_id"
                eid_expr = "r.event_id" if "event_id" in reg_cols else "NULL AS event_id"
                peid_expr = "r.process_entity_id" if "process_entity_id" in reg_cols else "NULL AS process_entity_id"
                rkey_expr = "COALESCE(r.registry_key, json_extract(r.raw_json, '$.\"registry.key\"'), json_extract(r.raw_json, '$.registry.key'), json_extract(r.raw_json, '$.registry_key')) AS registry_key" if "registry_key" in reg_cols else "COALESCE(json_extract(r.raw_json, '$.\"registry.key\"'), json_extract(r.raw_json, '$.registry.key'), json_extract(r.raw_json, '$.registry_key')) AS registry_key"
                rval_expr = "COALESCE(r.registry_value, json_extract(r.raw_json, '$.\"registry.value\"'), json_extract(r.raw_json, '$.registry.value'), json_extract(r.raw_json, '$.registry_value')) AS registry_value" if "registry_value" in reg_cols else "COALESCE(json_extract(r.raw_json, '$.\"registry.value\"'), json_extract(r.raw_json, '$.registry.value'), json_extract(r.raw_json, '$.registry_value')) AS registry_value"
                vtype_expr = "COALESCE(r.value_type, json_extract(r.raw_json, '$.\"registry.value_type\"'), json_extract(r.raw_json, '$.registry.value_type'), json_extract(r.raw_json, '$.value_type')) AS value_type" if "value_type" in reg_cols else "COALESCE(json_extract(r.raw_json, '$.\"registry.value_type\"'), json_extract(r.raw_json, '$.registry.value_type'), json_extract(r.raw_json, '$.value_type')) AS value_type"
                raw_expr = "r.raw_json" if "raw_json" in reg_cols else "'{}' AS raw_json"
                join_clause = "LEFT JOIN main.events e ON r.event_id = e.event_id" if ("events" in main_objects and "event_id" in reg_cols and "event_id" in event_cols) else ""
                ts_expr = "e.timestamp" if join_clause and "timestamp" in event_cols else ("r.timestamp" if "timestamp" in reg_cols else "COALESCE(json_extract(r.raw_json, '$.\"@timestamp\"'), json_extract(r.raw_json, '$.@timestamp'), json_extract(r.raw_json, '$.timestamp')) AS timestamp")
                hid_expr = "e.host_id" if join_clause and "host_id" in event_cols else ("r.host_id" if "host_id" in reg_cols else "COALESCE(json_extract(r.raw_json, '$.\"host.id\"'), json_extract(r.raw_json, '$.host.id'), json_extract(r.raw_json, '$.host_id'), 'unknown') AS host_id")
                uid_expr = "e.user_id" if join_clause and "user_id" in event_cols else ("r.user_id" if "user_id" in reg_cols else "COALESCE(json_extract(r.raw_json, '$.\"user.id\"'), json_extract(r.raw_json, '$.user.id'), json_extract(r.raw_json, '$.user_id')) AS user_id")

                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS registry_events AS
                    SELECT {rid_expr}, {eid_expr}, {peid_expr}, r.registry_path,
                           {rkey_expr}, {rval_expr}, {vtype_expr}, {raw_expr},
                           {ts_expr}, {hid_expr}, {uid_expr}
                    FROM main.registry_events r
                    {join_clause};
                """)
            else:
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS registry_events AS
                    SELECT 
                        rowid AS registry_id,
                        {get_field(["event_id", "id"], '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
                        {get_field(["process_entity_id", "entity_id"], '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id')} AS process_entity_id,
                        {get_field(["registry_path"], '$."registry.path"', '$.registry.path', '$.registry_path')} AS registry_path,
                        {get_field(["registry_key"], '$."registry.key"', '$.registry.key', '$.registry_key')} AS registry_key,
                        {get_field(["registry_value"], '$."registry.value"', '$.registry.value', '$.registry_value')} AS registry_value,
                        {get_field(["value_type"], '$."registry.value_type"', '$.registry.value_type', '$.value_type')} AS value_type,
                        {get_field(["raw_json"], default="'{}'")} AS raw_json,
                        {get_field(["timestamp", "@timestamp", "time"], '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
                        {get_field(["host_id", "agent_id", "agent_name", "hostname"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', default="'unknown'")} AS host_id,
                        {get_field(["user_id", "source_user", "username"], '$."user.id"', '$.user.id', '$.user_id')} AS user_id
                    FROM main.{source_table}
                    WHERE {safe_coalesce(*[c for c in ["registry_path", "registry_key", "registry_value"] if c in event_cols], *jextract('$."registry.path"', '$.registry.path', '$."registry.key"', '$.registry.key'))} IS NOT NULL
                       OR {get_field(["category"], '$."event.category"', '$.category')} LIKE '%registry%'
                       OR {get_field(["action", "event_action"], '$."event.action"', '$.action')} LIKE '%registry%';
                """)

            # 5. HOSTS
            host_tbl = "hosts" if "hosts" in main_objects else ("network_assets" if "network_assets" in main_objects else ("endpoints" if "endpoints" in main_objects else None))
            if host_tbl and has_rows(host_tbl):
                host_cols = get_cols(host_tbl)
                hid_expr = "host_id" if "host_id" in host_cols else ("asset_id" if "asset_id" in host_cols else ("endpoint_id" if "endpoint_id" in host_cols else "rowid"))
                hname_expr = "host_name" if "host_name" in host_cols else ("hostname" if "hostname" in host_cols else hid_expr)
                hname_alias = "hostname" if "hostname" in host_cols else ("host_name" if "host_name" in host_cols else hid_expr)
                ip_expr = "ip_address" if "ip_address" in host_cols else "NULL AS ip_address"
                raw_expr = "raw_json" if "raw_json" in host_cols else "'{}' AS raw_json"
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS hosts AS
                    SELECT 
                        {hid_expr} AS host_id,
                        {hname_expr} AS host_name,
                        {hname_alias} AS hostname,
                        {ip_expr},
                        {raw_expr}
                    FROM main.{host_tbl};
                """)
            else:
                target_hid = get_field(["host_id", "agent_id", "agent_name", "hostname", "asset_id", "src_ip"], '$."host.id"', '$.host.id', '$.host_id', '$."agent.id"', '$.agent.id', '$."agent.name"', '$.agent.name', '$.src_ip')
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS hosts AS
                    SELECT 
                        {target_hid} AS host_id,
                        COALESCE(MAX({safe_coalesce(*[c for c in ["hostname", "agent_name", "src_ip"] if c in event_cols], *jextract('$."host.name"', '$.host.name', '$.host.hostname', '$.hostname'))}), {target_hid}) AS host_name,
                        COALESCE(MAX({safe_coalesce(*[c for c in ["hostname", "agent_name", "src_ip"] if c in event_cols], *jextract('$."host.hostname"', '$.host.hostname', '$.hostname'))}), {target_hid}) AS hostname,
                        COALESCE(
                            MAX({safe_coalesce(*[c for c in ["ip_address"] if c in event_cols], *jextract('$."host.ip"', '$.host.ip', '$.ip_address'))}),
                            MAX(CASE WHEN {safe_coalesce(*[c for c in ["source_ip", "src_ip"] if c in event_cols], *jextract('$."source.ip"', '$.source.ip', '$.src_ip'))} IS NOT NULL THEN {safe_coalesce(*[c for c in ["source_ip", "src_ip"] if c in event_cols], *jextract('$."source.ip"', '$.source.ip', '$.src_ip'))} ELSE NULL END)
                        ) AS ip_address,
                        {get_field(["raw_json"], default="'{}'")} AS raw_json
                    FROM main.{source_table}
                    WHERE {target_hid} IS NOT NULL AND {target_hid} <> ''
                    GROUP BY 1;
                """)

            # 6. USERS
            user_cols = get_cols("users")
            if has_rows("users"):
                uname_expr = "user_name" if "user_name" in user_cols else ("username" if "username" in user_cols else "user_id")
                uname_alias = "username" if "username" in user_cols else ("user_name" if "user_name" in user_cols else "user_id")
                raw_expr = "raw_json" if "raw_json" in user_cols else "'{}' AS raw_json"
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS users AS
                    SELECT 
                        user_id,
                        {uname_expr} AS user_name,
                        {uname_alias} AS username,
                        {raw_expr}
                    FROM main.users;
                """)
            elif "network_assets" in main_objects and has_rows("network_assets"):
                # Extract asset owners from network_assets in NIDS/Suricata schemas
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS users AS
                    SELECT 
                        COALESCE(json_extract(raw_json, '$.owner'), 'user-' || rowid) AS user_id,
                        COALESCE(json_extract(raw_json, '$.owner'), 'Asset Owner ' || rowid) AS user_name,
                        COALESCE(json_extract(raw_json, '$.owner'), 'Asset Owner ' || rowid) AS username,
                        raw_json
                    FROM main.network_assets
                    WHERE json_extract(raw_json, '$.owner') IS NOT NULL;
                """)
            else:
                target_uid = get_field(["user_id", "source_user", "username"], '$."user.id"', '$.user.id', '$.user_id')
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS users AS
                    SELECT 
                        {target_uid} AS user_id,
                        COALESCE({safe_coalesce(*[c for c in ["username", "source_user"] if c in event_cols], *jextract('$."user.name"', '$.user.name', '$.user_name', '$.username'))}, {target_uid}) AS user_name,
                        COALESCE({safe_coalesce(*[c for c in ["username", "source_user"] if c in event_cols], *jextract('$."user.name"', '$.user.name', '$.user_name', '$.username'))}, {target_uid}) AS username,
                        {get_field(["raw_json"], default="'{}'")} AS raw_json
                    FROM main.{source_table}
                    WHERE {target_uid} IS NOT NULL AND {target_uid} <> ''
                    GROUP BY 1;
                """)

            # 7. AGENT_EVENTS
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
