"""Dynamic schema introspection and semantic field adapter for DFIR telemetry databases."""
import re
import sqlite3
from typing import Dict, List, Set, Optional, Tuple, Any

# Canonical semantic alias mapping for standard DFIR entities across disparate schemas
SEMANTIC_FIELD_ALIASES: Dict[str, List[str]] = {
    "timestamp": [
        "timestamp", "@timestamp", "time", "event_time", "datetime",
        "TimeCreated", "UtcTime", "event_timestamp", "created_at"
    ],
    "host_id": [
        "host_id", "hostname", "host_name", "computer_name", "Computer",
        "MachineName", "agent_id", "agent_name", "endpoint_id", "asset_id",
        "device_id", "sensor_id"
    ],
    "user_id": [
        "user_id", "username", "user_name", "account_name", "TargetUserName",
        "SubjectUserName", "source_user", "src_user", "user"
    ],
    "process_name": [
        "process_name", "image", "process", "app", "exe_name",
        "OriginalFileName", "name"
    ],
    "command_line": [
        "command_line", "process_cmdline", "cmdline", "args", "CommandLine",
        "arguments", "process_args"
    ],
    "executable": [
        "executable", "process_path", "image_path", "path", "ImagePath"
    ],
    "pid": [
        "pid", "process_id", "ProcessId", "proc_id"
    ],
    "parent_process_name": [
        "parent_process_name", "parent_image", "parent_name", "ParentCommandLine",
        "parent_process"
    ],
    "parent_pid": [
        "parent_pid", "process_parent_id", "ParentProcessId", "ppid"
    ],
    "parent_entity_id": [
        "parent_entity_id", "parent_process_entity_id"
    ],
    "process_entity_id": [
        "process_entity_id", "entity_id", "ProcessGuid"
    ],
    "destination_ip": [
        "destination_ip", "dest_ip", "network_dst", "dst_ip", "remote_address",
        "DestinationIp", "remote_ip", "dst_address"
    ],
    "destination_port": [
        "destination_port", "dest_port", "network_dst_port", "dst_port",
        "remote_port", "DestinationPort"
    ],
    "source_ip": [
        "source_ip", "src_ip", "network_src", "SourceIp", "local_ip",
        "source_address"
    ],
    "source_port": [
        "source_port", "src_port", "network_src_port", "SourcePort", "local_port"
    ],
    "protocol": [
        "protocol", "network_protocol", "transport", "Protocol", "proto"
    ],
    "file_path": [
        "file_path", "target_filename", "path", "destination_path", "TargetFilename"
    ],
    "file_name": [
        "file_name", "filename", "name", "target_filename"
    ],
    "sha256": [
        "sha256", "hash", "file_hash", "hash_sha256", "Hashes", "imphash"
    ],
    "registry_key": [
        "registry_key", "target_object", "TargetObject", "key_name"
    ],
    "registry_path": [
        "registry_path", "key_path", "target_object", "TargetObject"
    ],
    "registry_value": [
        "registry_value", "value_data", "details", "Details"
    ],
    "action": [
        "action", "event_action", "rule_description", "Activity", "task_name",
        "alert_signature", "signature", "alert_name", "signature_name"
    ],
    "event_type": [
        "event_type", "subcategory", "type", "EventType", "app_proto"
    ],
    "event_code": [
        "event_code", "rule_id", "code", "EventID", "event_id",
        "alert_signature_id", "signature_id", "gid", "sid"
    ],
    "provider": [
        "provider", "manager", "channel", "source_name", "Provider_Name", "sensor"
    ],
    "outcome": [
        "outcome", "status", "result", "Status"
    ],
    "severity": [
        "severity", "rule_level", "alert_severity", "level", "priority"
    ],
    "raw_json": [
        "raw_json", "payload", "event_data", "data", "json_data", "eve_json", "raw"
    ]
}


class SchemaAdapter:
    """Introspects and maps any SQLite telemetry schema dynamically."""

    def __init__(self, conn: sqlite3.Connection):
        self.tables: Dict[str, List[str]] = {}
        self.views: Dict[str, List[str]] = {}
        self.primary_events_table: Optional[str] = None
        self._introspect(conn)

    def _introspect(self, conn: sqlite3.Connection) -> None:
        """Scan sqlite_master and sqlite_temp_master for table and view columns."""
        cur = conn.cursor()
        cur.execute("""
            SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'
            UNION
            SELECT name, type FROM sqlite_temp_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%';
        """)
        objects = cur.fetchall()

        for name, obj_type in objects:
            c = conn.cursor()
            try:
                c.execute(f"PRAGMA table_info('{name}');")
                cols = [row[1] for row in c.fetchall()]
            except Exception:
                cols = []
            if obj_type == "table":
                self.tables[name] = cols
            else:
                self.views[name] = cols

        self.primary_events_table = self._discover_primary_events_table(conn)

    def _discover_primary_events_table(self, conn: sqlite3.Connection) -> Optional[str]:
        """Find the table containing endpoint events/telemetry."""
        all_objs = {**self.tables, **self.views}
        
        # High-probability table names
        for candidate in (
            "events", "wazuh_events", "agent_events", "alerts",
            "edr_events", "siem_events", "telemetry", "logs", "sysmon",
            "security_events", "endpoint_events", "audit_logs"
        ):
            if candidate in all_objs:
                return candidate

        # Fallback: table with largest row count having a recognized timestamp column
        best_table = None
        max_rows = -1
        cur = conn.cursor()
        for obj, cols in all_objs.items():
            lower_cols = {c.lower() for c in cols}
            if any(t.lower() in lower_cols for t in SEMANTIC_FIELD_ALIASES["timestamp"]):
                try:
                    cur.execute(f"SELECT count(*) FROM '{obj}';")
                    cnt = cur.fetchone()[0]
                    if cnt > max_rows:
                        max_rows = cnt
                        best_table = obj
                except Exception:
                    continue

        return best_table or (list(self.tables.keys())[0] if self.tables else None)

    def has_table(self, name: str) -> bool:
        """Return True if table or view exists."""
        return name in self.tables or name in self.views

    def get_columns(self, table_name: str) -> List[str]:
        """Return columns for a given table or view."""
        return self.tables.get(table_name) or self.views.get(table_name) or []

    def get_column_for(self, table_name: str, semantic_field: str) -> Optional[str]:
        """Find matching physical column in table for semantic field."""
        cols = self.get_columns(table_name)
        if not cols:
            return None
        col_map = {c.lower(): c for c in cols}
        aliases = SEMANTIC_FIELD_ALIASES.get(semantic_field, [semantic_field])
        for alias in aliases:
            if alias.lower() in col_map:
                return col_map[alias.lower()]
        return None

    def get_field_aliases(self, table_name: str) -> Dict[str, str]:
        """Return dict of canonical_field -> physical_column for all matching fields."""
        mapping = {}
        for canonical in SEMANTIC_FIELD_ALIASES:
            col = self.get_column_for(table_name, canonical)
            if col:
                mapping[canonical] = col
        return mapping

    def get_timestamp_info(self) -> Tuple[Optional[str], Optional[str]]:
        """Return (table_name, column_name) for timestamps."""
        tbl = self.primary_events_table
        if tbl:
            col = self.get_column_for(tbl, "timestamp")
            if col:
                return tbl, col
        for t in list(self.tables.keys()) + list(self.views.keys()):
            col = self.get_column_for(t, "timestamp")
            if col:
                return t, col
        return None, None

    def get_diagnostic_hint(self, table_name: str, failed_term: Optional[str] = None) -> Dict[str, Any]:
        """Generate structured diagnostic feedback when a query produces zero results."""
        cols = self.get_columns(table_name)
        hints: Dict[str, Any] = {
            "table_queried": table_name,
            "table_exists": self.has_table(table_name),
            "available_columns": cols,
            "all_available_tables": list(self.tables.keys()) + list(self.views.keys()),
        }
        if failed_term:
            hints["checked_term"] = failed_term
            # Suggest closest matching column
