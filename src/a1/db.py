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

            # If agent_events exists but events does not, synthesize events view
            if "events" not in main_objects and "agent_events" in main_objects:
                cur.execute("CREATE TEMP VIEW IF NOT EXISTS events AS SELECT * FROM main.agent_events;")
                main_objects.add("events")

            if "events" not in main_objects:
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

            event_cols = get_cols("events")
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

            def get_field(col: str, *raw_paths: str, default: Optional[str] = None) -> str:
                """Extract field from event column, raw_json paths, or fallback default."""
                parts = []
                if col in event_cols:
                    parts.append(col)
                parts.extend(jextract(*raw_paths))
                if default is not None:
                    parts.append(default)
                return safe_coalesce(*parts)

            stmts = []

            # 0. EVENTS: If main.events is a raw single-table export missing any standard columns, project an augmented events view
            required_event_cols = {
                "event_id", "timestamp", "provider", "event_code", "category",
                "event_type", "action", "outcome", "severity", "host_id",
                "user_id", "process_entity_id", "raw_json"
            }
            if "events" in main_objects and not required_event_cols.issubset(event_cols):
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS events AS
                    SELECT 
                        {get_field("event_id", '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
                        {get_field("timestamp", '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
                        {get_field("provider", '$."event.provider"', '$.event.provider', '$.provider', default="'Sysmon'")} AS provider,
                        {get_field("event_code", '$."event.code"', '$.event.code', '$.event_code', default="'1'")} AS event_code,
                        {get_field("category", '$."event.category"', '$.event.category', '$.category', default="'process'")} AS category,
                        {get_field("event_type", '$."event.type"', '$.event.type', '$.type', default="'start'")} AS event_type,
                        {get_field("action", '$."event.action"', '$.event.action', '$.action', default="'start'")} AS action,
                        {get_field("outcome", '$."event.outcome"', '$.event.outcome', '$.outcome', default="'success'")} AS outcome,
                        {get_field("severity", '$."event.severity"', '$.event.severity', '$.severity', default="0")} AS severity,
                        {get_field("host_id", '$."host.id"', '$.host.id', '$.host_id', default="'unknown'")} AS host_id,
                        {get_field("user_id", '$."user.id"', '$.user.id', '$.user_id', default="'unknown'")} AS user_id,
                        {get_field("process_entity_id", '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id')} AS process_entity_id,
                        {get_field("raw_json", default="'{}'")} AS raw_json
                    FROM main.events;
                """)

            # 1. PROCESSES
            proc_cols = get_cols("processes")
            if has_rows("processes") and {"process_entity_id", "process_name", "pid"}.issubset(proc_cols):
                eid_expr = "p.event_id" if "event_id" in proc_cols else "NULL AS event_id"
                hid_expr = "p.host_id" if "host_id" in proc_cols else ("e.host_id" if ("events" in main_objects and "host_id" in event_cols) else "NULL AS host_id")
                exe_expr = "p.executable" if "executable" in proc_cols else "NULL AS executable"
                peid_expr = "p.parent_entity_id" if "parent_entity_id" in proc_cols else "NULL AS parent_entity_id"
                ppid_expr = "p.parent_pid" if "parent_pid" in proc_cols else "NULL AS parent_pid"
                raw_expr = "p.raw_json" if "raw_json" in proc_cols else "'{}' AS raw_json"
                join_clause = "LEFT JOIN main.events e ON p.event_id = e.event_id" if ("events" in main_objects and "event_id" in proc_cols and "event_id" in event_cols) else ""
                ts_expr = "e.timestamp" if join_clause and "timestamp" in event_cols else ("p.timestamp" if "timestamp" in proc_cols else "NULL AS timestamp")
                uid_expr = "e.user_id" if join_clause and "user_id" in event_cols else ("p.user_id" if "user_id" in proc_cols else "NULL AS user_id")

                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS processes AS
                    SELECT p.process_entity_id, {eid_expr}, {hid_expr}, p.pid, p.process_name,
                           {exe_expr}, {peid_expr}, {ppid_expr}, {raw_expr},
                           {ts_expr}, {uid_expr}
                    FROM main.processes p
                    {join_clause};
                """)
            else:
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS processes AS
                    SELECT 
                        {get_field("process_entity_id", '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id', '$.entity_id', default="'proc-' || rowid")} AS process_entity_id,
                        {get_field("event_id", '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
                        {get_field("host_id", '$."host.id"', '$.host.id', '$.host_id', default="'unknown'")} AS host_id,
                        CAST({get_field("pid", '$."process.pid"', '$.process.pid', '$.process_pid', '$.pid', default="0")} AS INTEGER) AS pid,
                        {get_field("process_name", '$."process.name"', '$.process.name', '$.process_name', '$.name', default="'unknown'")} AS process_name,
                        {get_field("executable", '$."process.executable"', '$.process.executable', '$.executable')} AS executable,
                        {get_field("parent_entity_id", '$."process.parent.entity_id"', '$.process.parent.entity_id', '$.parent_entity_id', '$.parent.process_entity_id')} AS parent_entity_id,
                        CAST({get_field("parent_pid", '$."process.parent.pid"', '$.process.parent.pid', '$.parent_pid', '$.parent.pid')} AS INTEGER) AS parent_pid,
                        {get_field("raw_json", default="'{}'")} AS raw_json,
                        {get_field("timestamp", '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
                        {get_field("user_id", '$."user.id"', '$.user.id', '$.user_id')} AS user_id
                    FROM main.events
                    WHERE {safe_coalesce(*jextract('$."process.name"', '$.process.name', '$.process_name'), *(['process_name'] if 'process_name' in event_cols else []))} IS NOT NULL
                       OR {safe_coalesce(*jextract('$."process.executable"', '$.process.executable', '$.executable'), *(['executable'] if 'executable' in event_cols else []))} IS NOT NULL
                       OR {safe_coalesce(*jextract('$."process.pid"', '$.process.pid', '$.pid'), *(['pid'] if 'pid' in event_cols else []))} IS NOT NULL
                       OR {get_field("action", '$."event.action"', '$.event.action', '$.action')} = 'process_started'
                       OR {get_field("category", '$."event.category"', '$.event.category', '$.category')} = 'process';
                """)

            # 2. FILES
            file_cols = get_cols("files")
            if has_rows("files") and {"file_path", "file_name"}.issubset(file_cols):
                fid_expr = "f.file_id" if "file_id" in file_cols else "f.rowid AS file_id"
                eid_expr = "f.event_id" if "event_id" in file_cols else "NULL AS event_id"
                peid_expr = "f.process_entity_id" if "process_entity_id" in file_cols else "NULL AS process_entity_id"
                ext_expr = "f.extension" if "extension" in file_cols else "NULL AS extension"
                sz_expr = "f.size" if "size" in file_cols else "NULL AS size"
                sha_expr = "f.sha256" if "sha256" in file_cols else "NULL AS sha256"
                raw_expr = "f.raw_json" if "raw_json" in file_cols else "'{}' AS raw_json"
                join_clause = "LEFT JOIN main.events e ON f.event_id = e.event_id" if ("events" in main_objects and "event_id" in file_cols and "event_id" in event_cols) else ""
                ts_expr = "e.timestamp" if join_clause and "timestamp" in event_cols else ("f.timestamp" if "timestamp" in file_cols else "NULL AS timestamp")
                hid_expr = "e.host_id" if join_clause and "host_id" in event_cols else ("f.host_id" if "host_id" in file_cols else "NULL AS host_id")
                uid_expr = "e.user_id" if join_clause and "user_id" in event_cols else ("f.user_id" if "user_id" in file_cols else "NULL AS user_id")

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
                        {get_field("event_id", '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
                        {get_field("process_entity_id", '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id')} AS process_entity_id,
                        {get_field("file_path", '$."file.path"', '$.file.path', '$.file_path', '$.path')} AS file_path,
                        {get_field("file_name", '$."file.name"', '$.file.name', '$.file_name', '$.name')} AS file_name,
                        {get_field("extension", '$."file.extension"', '$.file.extension', '$.file_extension', '$.extension')} AS extension,
                        CAST({get_field("size", '$."file.size"', '$.file.size', '$.file_size', '$.size', default="0")} AS INTEGER) AS size,
                        {get_field("sha256", '$."file.hash.sha256"', '$.file.hash.sha256', '$.file.sha256', '$.sha256', '$.hash_sha256')} AS sha256,
                        {get_field("raw_json", default="'{}'")} AS raw_json,
                        {get_field("timestamp", '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
                        {get_field("host_id", '$."host.id"', '$.host.id', '$.host_id', default="'unknown'")} AS host_id,
                        {get_field("user_id", '$."user.id"', '$.user.id', '$.user_id')} AS user_id
                    FROM main.events
                    WHERE {safe_coalesce(*jextract('$."file.path"', '$.file.path', '$.file_path'), *(['file_path'] if 'file_path' in event_cols else []))} IS NOT NULL
                       OR {safe_coalesce(*jextract('$."file.name"', '$.file.name', '$.file_name'), *(['file_name'] if 'file_name' in event_cols else []))} IS NOT NULL
                       OR {get_field("category", '$."event.category"', '$.event.category', '$.category')} LIKE '%file%';
                """)

            # 3. NETWORK_CONNECTIONS
            net_cols = get_cols("network_connections")
            if has_rows("network_connections") and {"destination_ip", "source_ip"}.issubset(net_cols):
                nid_expr = "nc.network_id" if "network_id" in net_cols else "nc.rowid AS network_id"
                eid_expr = "nc.event_id" if "event_id" in net_cols else "NULL AS event_id"
                peid_expr = "nc.process_entity_id" if "process_entity_id" in net_cols else "NULL AS process_entity_id"
                sport_expr = "nc.source_port" if "source_port" in net_cols else "NULL AS source_port"
                dport_expr = "nc.destination_port" if "destination_port" in net_cols else "NULL AS destination_port"
                proto_expr = "nc.protocol" if "protocol" in net_cols else "'tcp' AS protocol"
                raw_expr = "nc.raw_json" if "raw_json" in net_cols else "'{}' AS raw_json"
                join_clause = "LEFT JOIN main.events e ON nc.event_id = e.event_id" if ("events" in main_objects and "event_id" in net_cols and "event_id" in event_cols) else ""
                ts_expr = "e.timestamp" if join_clause and "timestamp" in event_cols else ("nc.timestamp" if "timestamp" in net_cols else "NULL AS timestamp")
                hid_expr = "e.host_id" if join_clause and "host_id" in event_cols else ("nc.host_id" if "host_id" in net_cols else "NULL AS host_id")
                uid_expr = "e.user_id" if join_clause and "user_id" in event_cols else ("nc.user_id" if "user_id" in net_cols else "NULL AS user_id")

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
                        {get_field("event_id", '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
                        {get_field("process_entity_id", '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id')} AS process_entity_id,
                        {get_field("source_ip", '$."source.ip"', '$.source.ip', '$.source_ip', '$.src_ip')} AS source_ip,
                        CAST({get_field("source_port", '$."source.port"', '$.source.port', '$.source_port', '$.src_port')} AS INTEGER) AS source_port,
                        {get_field("destination_ip", '$."destination.ip"', '$.destination.ip', '$.destination_ip', '$.dst_ip')} AS destination_ip,
                        CAST({get_field("destination_port", '$."destination.port"', '$.destination.port', '$.destination_port', '$.dst_port')} AS INTEGER) AS destination_port,
                        {get_field("protocol", '$."network.protocol"', '$.network.protocol', '$.protocol', '$.network.transport', default="'tcp'")} AS protocol,
                        {get_field("raw_json", default="'{}'")} AS raw_json,
                        {get_field("timestamp", '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
                        {get_field("host_id", '$."host.id"', '$.host.id', '$.host_id', default="'unknown'")} AS host_id,
                        {get_field("host_id", '$."host.id"', '$.host.id', '$.host_id', default="'unknown'")} AS source_host_id,
                        NULL AS destination_host_id,
                        {get_field("user_id", '$."user.id"', '$.user.id', '$.user_id')} AS user_id
                    FROM main.events
                    WHERE {safe_coalesce(*jextract('$."destination.ip"', '$.destination.ip', '$.destination_ip', '$.dst_ip'), *(['destination_ip'] if 'destination_ip' in event_cols else []))} IS NOT NULL
                       OR {safe_coalesce(*jextract('$."source.ip"', '$.source.ip', '$.source_ip', '$.src_ip'), *(['source_ip'] if 'source_ip' in event_cols else []))} IS NOT NULL
                       OR {get_field("category", '$."event.category"', '$.event.category', '$.category')} LIKE '%network%';
                """)

            # 4. REGISTRY_EVENTS
            reg_cols = get_cols("registry_events")
            if has_rows("registry_events") and {"registry_path"}.issubset(reg_cols):
                rid_expr = "r.registry_id" if "registry_id" in reg_cols else "r.rowid AS registry_id"
                eid_expr = "r.event_id" if "event_id" in reg_cols else "NULL AS event_id"
                peid_expr = "r.process_entity_id" if "process_entity_id" in reg_cols else "NULL AS process_entity_id"
                rkey_expr = "r.registry_key" if "registry_key" in reg_cols else "NULL AS registry_key"
                rval_expr = "r.registry_value" if "registry_value" in reg_cols else "NULL AS registry_value"
                vtype_expr = "r.value_type" if "value_type" in reg_cols else "NULL AS value_type"
                raw_expr = "r.raw_json" if "raw_json" in reg_cols else "'{}' AS raw_json"
                join_clause = "LEFT JOIN main.events e ON r.event_id = e.event_id" if ("events" in main_objects and "event_id" in reg_cols and "event_id" in event_cols) else ""
                ts_expr = "e.timestamp" if join_clause and "timestamp" in event_cols else ("r.timestamp" if "timestamp" in reg_cols else "NULL AS timestamp")
                hid_expr = "e.host_id" if join_clause and "host_id" in event_cols else ("r.host_id" if "host_id" in reg_cols else "NULL AS host_id")
                uid_expr = "e.user_id" if join_clause and "user_id" in event_cols else ("r.user_id" if "user_id" in reg_cols else "NULL AS user_id")

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
                        {get_field("event_id", '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
                        {get_field("process_entity_id", '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id')} AS process_entity_id,
                        {get_field("registry_path", '$."registry.path"', '$.registry.path', '$.registry_path')} AS registry_path,
                        {get_field("registry_key", '$."registry.key"', '$.registry.key', '$.registry_key')} AS registry_key,
                        {get_field("registry_value", '$."registry.value"', '$.registry.value', '$.registry_value')} AS registry_value,
                        {get_field("value_type", '$."registry.value_type"', '$.registry.value_type', '$.value_type')} AS value_type,
                        {get_field("raw_json", default="'{}'")} AS raw_json,
                        {get_field("timestamp", '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
                        {get_field("host_id", '$."host.id"', '$.host.id', '$.host_id', default="'unknown'")} AS host_id,
                        {get_field("user_id", '$."user.id"', '$.user.id', '$.user_id')} AS user_id
                    FROM main.events
                    WHERE {safe_coalesce(*jextract('$."registry.path"', '$.registry.path', '$.registry_path'), *(['registry_path'] if 'registry_path' in event_cols else []))} IS NOT NULL
                       OR {safe_coalesce(*jextract('$."registry.key"', '$.registry.key', '$.registry_key'), *(['registry_key'] if 'registry_key' in event_cols else []))} IS NOT NULL
                       OR {get_field("category", '$."event.category"', '$.event.category', '$.category')} LIKE '%registry%';
                """)

            # 5. HOSTS
            host_cols = get_cols("hosts")
            if has_rows("hosts"):
                hname_expr = "host_name" if "host_name" in host_cols else ("hostname" if "hostname" in host_cols else "host_id")
                hname_alias = "hostname" if "hostname" in host_cols else ("host_name" if "host_name" in host_cols else "host_id")
                raw_expr = "raw_json" if "raw_json" in host_cols else "'{}' AS raw_json"
                if "host_name" not in host_cols or "hostname" not in host_cols or "raw_json" not in host_cols:
                    stmts.append(f"""
                        CREATE TEMP VIEW IF NOT EXISTS hosts AS
                        SELECT 
                            host_id,
                            {hname_expr} AS host_name,
                            {hname_alias} AS hostname,
                            {raw_expr}
                        FROM main.hosts;
                    """)
            else:
                target_hid = get_field("host_id", '$."host.id"', '$.host.id', '$.host_id')
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS hosts AS
                    SELECT 
                        {target_hid} AS host_id,
                        COALESCE({safe_coalesce(*jextract('$."host.name"', '$.host.name', '$.host.hostname', '$.hostname'))}, {target_hid}) AS host_name,
                        COALESCE({safe_coalesce(*jextract('$."host.hostname"', '$.host.hostname', '$."host.name"', '$.host.name', '$.hostname'))}, {target_hid}) AS hostname,
                        {get_field("raw_json", default="'{}'")} AS raw_json
                    FROM main.events
                    WHERE {target_hid} IS NOT NULL AND {target_hid} <> ''
                    GROUP BY 1;
                """)

            # 6. USERS
            user_cols = get_cols("users")
            if has_rows("users"):
                uname_expr = "user_name" if "user_name" in user_cols else ("username" if "username" in user_cols else "user_id")
                uname_alias = "username" if "username" in user_cols else ("user_name" if "user_name" in user_cols else "user_id")
                raw_expr = "raw_json" if "raw_json" in user_cols else "'{}' AS raw_json"
                if "user_name" not in user_cols or "username" not in user_cols or "raw_json" not in user_cols:
                    stmts.append(f"""
                        CREATE TEMP VIEW IF NOT EXISTS users AS
                        SELECT 
                            user_id,
                            {uname_expr} AS user_name,
                            {uname_alias} AS username,
                            {raw_expr}
                        FROM main.users;
                    """)
            else:
                target_uid = get_field("user_id", '$."user.id"', '$.user.id', '$.user_id')
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS users AS
                    SELECT 
                        {target_uid} AS user_id,
                        COALESCE({safe_coalesce(*jextract('$."user.name"', '$.user.name', '$.user_name', '$.username'))}, {target_uid}) AS user_name,
                        COALESCE({safe_coalesce(*jextract('$."user.name"', '$.user.name', '$.user_name', '$.username'))}, {target_uid}) AS username,
                        {get_field("raw_json", default="'{}'")} AS raw_json
                    FROM main.events
                    WHERE {target_uid} IS NOT NULL AND {target_uid} <> ''
                    GROUP BY 1;
                """)

            # 7. AGENT_EVENTS
            if "agent_events" not in main_objects:
                stmts.append(f"""
                    CREATE TEMP VIEW IF NOT EXISTS agent_events AS
                    SELECT 
                        {get_field("event_id", '$."event.id"', '$.event.id', '$.event_id', '$.id', default="'evt-' || rowid")} AS event_id,
                        {get_field("timestamp", '$."@timestamp"', '$.@timestamp', '$.timestamp', '$.time', default="datetime('now')")} AS timestamp,
                        {get_field("provider", '$."event.provider"', '$.event.provider', '$.provider', default="'Sysmon'")} AS provider,
                        {get_field("event_code", '$."event.code"', '$.event.code', '$.event_code', default="'1'")} AS event_code,
                        {get_field("category", '$."event.category"', '$.event.category', '$.category', default="'process'")} AS category,
                        {get_field("event_type", '$."event.type"', '$.event.type', '$.type', default="'start'")} AS event_type,
                        {get_field("action", '$."event.action"', '$.event.action', '$.action', default="'start'")} AS action,
                        {get_field("outcome", '$."event.outcome"', '$.event.outcome', '$.outcome', default="'success'")} AS outcome,
                        {get_field("severity", '$."event.severity"', '$.event.severity', '$.severity', default="0")} AS severity,
                        {get_field("host_id", '$."host.id"', '$.host.id', '$.host_id', default="'unknown'")} AS host_id,
                        {get_field("user_id", '$."user.id"', '$.user.id', '$.user_id', default="'unknown'")} AS user_id,
                        {get_field("process_entity_id", '$."process.entity_id"', '$.process.entity_id', '$.process_entity_id')} AS process_entity_id,
                        {get_field("raw_json", default="'{}'")} AS raw_json
                    FROM main.events;
                """)

            for s in stmts:
                cur.execute(s)
        except Exception:
            pass

    def _get_connection(self) -> sqlite3.Connection:
        # Open in SQLite URI read-only mode to prevent any writes at the file driver level
        uri = f"file:{self.db_path.resolve().as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        self._init_temp_views(conn)
        return conn

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

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(clean_sql, params)
            rows = cursor.fetchmany(max_rows)
            return [dict(row) for row in rows]

    def get_schema(self) -> Dict[str, List[str]]:
        """Return table and view names along with their column names."""
        with self._get_connection() as conn:
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
                c_cursor.execute(f"PRAGMA table_info({name});")
                cols = [col["name"] for col in c_cursor.fetchall()]
                schema_info[name] = cols
            return schema_info
