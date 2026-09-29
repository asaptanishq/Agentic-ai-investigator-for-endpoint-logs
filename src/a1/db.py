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
        """Create in-memory convenience views that project timestamp and host_id
        onto sub-tables like network_connections, files, and registry_events.
        Does not mutate the database on disk.
        """
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events';")
            if not cur.fetchone():
                return

            def get_cols(table_name: str) -> set:
                cur.execute(f"PRAGMA main.table_info({table_name});")
                return {row[1] for row in cur.fetchall()}

            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row[0] for row in cur.fetchall()}

            stmts = []
            if "network_connections" in tables:
                cols = get_cols("network_connections")
                expected = {"network_id", "event_id", "process_entity_id", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "raw_json"}
                if expected.issubset(cols):
                    stmts.append("""
                        CREATE TEMP VIEW IF NOT EXISTS network_connections AS
                        SELECT nc.network_id, nc.event_id, nc.process_entity_id, nc.source_ip, nc.source_port,
                               nc.destination_ip, nc.destination_port, nc.protocol, nc.raw_json,
                               e.timestamp, e.host_id, e.host_id AS source_host_id, NULL AS destination_host_id, e.user_id
                        FROM main.network_connections nc
                        LEFT JOIN main.events e ON nc.event_id = e.event_id;
                    """)
            if "processes" in tables:
                cols = get_cols("processes")
                expected = {"process_entity_id", "event_id", "host_id", "pid", "process_name", "executable", "parent_entity_id", "parent_pid", "raw_json"}
                if expected.issubset(cols):
                    stmts.append("""
                        CREATE TEMP VIEW IF NOT EXISTS processes AS
                        SELECT p.process_entity_id, p.event_id, p.host_id, p.pid, p.process_name,
                               p.executable, p.parent_entity_id, p.parent_pid, p.raw_json,
                               e.timestamp, e.user_id
                        FROM main.processes p
                        LEFT JOIN main.events e ON p.event_id = e.event_id;
                    """)
            if "files" in tables:
                cols = get_cols("files")
                expected = {"file_id", "event_id", "process_entity_id", "file_path", "file_name", "extension", "size", "sha256", "raw_json"}
                if expected.issubset(cols):
                    stmts.append("""
                        CREATE TEMP VIEW IF NOT EXISTS files AS
                        SELECT f.file_id, f.event_id, f.process_entity_id, f.file_path, f.file_name,
                               f.extension, f.size, f.sha256, f.raw_json,
                               e.timestamp, e.host_id, e.user_id
                        FROM main.files f
                        LEFT JOIN main.events e ON f.event_id = e.event_id;
                    """)
            if "registry_events" in tables:
                cols = get_cols("registry_events")
                expected = {"registry_id", "event_id", "process_entity_id", "registry_path", "registry_key", "registry_value", "value_type", "raw_json"}
                if expected.issubset(cols):
                    stmts.append("""
                        CREATE TEMP VIEW IF NOT EXISTS registry_events AS
                        SELECT r.registry_id, r.event_id, r.process_entity_id, r.registry_path,
                               r.registry_key, r.registry_value, r.value_type, r.raw_json,
                               e.timestamp, e.host_id, e.user_id
                        FROM main.registry_events r
                        LEFT JOIN main.events e ON r.event_id = e.event_id;
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
            cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%';")
            items = cursor.fetchall()
            schema_info = {}
            for item in items:
                name = item["name"]
                c_cursor = conn.cursor()
                c_cursor.execute(f"PRAGMA table_info({name});")
                cols = [col["name"] for col in c_cursor.fetchall()]
                schema_info[name] = cols
            return schema_info
