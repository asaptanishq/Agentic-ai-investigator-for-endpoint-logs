import pytest
from a1.db import EndpointDatabase, DatabaseAccessError

def test_db_schema_inspection():
    db = EndpointDatabase()
    schema = db.get_schema()
    assert "events" in schema
    assert "processes" in schema
    assert "files" in schema
    assert "network_connections" in schema
    assert "registry_events" in schema
    assert "hosts" in schema
    assert "users" in schema
    assert "agent_events" in schema

def test_db_safe_select():
    db = EndpointDatabase()
    results = db.execute_query("SELECT event_id, category FROM events LIMIT 5;")
    assert len(results) <= 5
    assert len(results) > 0
    assert "event_id" in results[0]

def test_db_blocks_mutations():
    db = EndpointDatabase()
    with pytest.raises(DatabaseAccessError):
        db.execute_query("DROP TABLE events;")

    with pytest.raises(DatabaseAccessError):
        db.execute_query("INSERT INTO hosts (host_id, host_name) VALUES ('h-bad', 'bad');")

    with pytest.raises(DatabaseAccessError):
        db.execute_query("SELECT 1; DROP TABLE events;")


def test_db_virtual_adapter_synthesizes_subtables_from_raw_events(tmp_path):
    """Verify that a single-table database containing only events and raw_json
    automatically synthesizes processes, files, network_connections, hosts, and users in-memory.
    """
    import json
    import sqlite3

    db_file = tmp_path / "raw_telemetry.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("""
        CREATE TABLE events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT,
            host_id TEXT,
            user_id TEXT,
            process_entity_id TEXT,
            category TEXT,
            action TEXT,
            raw_json TEXT
        )
    """)
    raw = json.dumps({
        "event.id": "evt-dyn-001",
        "@timestamp": "2026-09-20T10:05:00Z",
        "host.id": "host-dyn-01",
        "host.name": "WS-DYNAMIC-01",
        "user.id": "u-dyn-01",
        "user.name": "alice",
        "process.entity_id": "proc-dyn-4411",
        "process.pid": 4411,
        "process.name": "cmd.exe",
        "process.executable": "C:\\Windows\\System32\\cmd.exe",
        "file.name": "payload.exe",
        "file.path": "C:\\Users\\alice\\payload.exe",
        "file.hash.sha256": "abc123hash",
        "destination.ip": "203.0.113.88",
        "destination.port": 443,
    })
    conn.execute(
        "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("evt-dyn-001", "2026-09-20T10:05:00Z", "host-dyn-01", "u-dyn-01", "proc-dyn-4411", "process", "process_started", raw)
    )
    conn.commit()
    conn.close()

    db = EndpointDatabase(db_file)
    schema = db.get_schema()
    for table_name in ("events", "processes", "files", "network_connections", "registry_events", "hosts", "users", "agent_events"):
        assert table_name in schema

    # Verify synthesized rows
    proc_rows = db.execute_query("SELECT process_entity_id, process_name, pid, executable FROM processes")
    assert len(proc_rows) == 1
    assert proc_rows[0]["process_name"] == "cmd.exe"
    assert proc_rows[0]["pid"] == 4411

    file_rows = db.execute_query("SELECT file_name, file_path, sha256 FROM files")
    assert len(file_rows) == 1
    assert file_rows[0]["file_name"] == "payload.exe"

    host_rows = db.execute_query("SELECT host_id, host_name FROM hosts")
    assert len(host_rows) == 1
    assert host_rows[0]["host_name"] == "WS-DYNAMIC-01"

    user_rows = db.execute_query("SELECT user_id, user_name FROM users")
    assert len(user_rows) == 1
    assert user_rows[0]["user_name"] == "alice"


def test_db_raw_single_table_siem_export_and_zero_disk_mutation(tmp_path):
    """Verify raw single-table SIEM/EDR export: events(timestamp, host_id, raw_json)
    with zero disk mutation and on-the-fly synthesis of all sub-tables.
    """
    import json
    import hashlib
    import sqlite3

    db_file = tmp_path / "raw_siem_export.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("""
        CREATE TABLE events (
            timestamp TEXT,
            host_id TEXT,
            raw_json TEXT
        )
    """)
    events_data = [
        # Process start
        (
            "2026-09-20T11:00:00Z",
            "host-siem-99",
            json.dumps({
                "process": {
                    "name": "powershell.exe",
                    "pid": 5512,
                    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "entity_id": "proc-ps-101"
                },
                "user": {"id": "u-admin-1", "name": "admin_bob"},
                "host": {"id": "host-siem-99", "name": "DC-PRIMARY"}
            })
        ),
        # File written
        (
            "2026-09-20T11:00:05Z",
            "host-siem-99",
            json.dumps({
                "file": {
                    "name": "malware.dll",
                    "path": "C:\\Windows\\Temp\\malware.dll",
                    "size": 40960,
                    "hash": {"sha256": "deadbeef12345"}
                },
                "process": {"entity_id": "proc-ps-101"},
                "host": {"id": "host-siem-99", "name": "DC-PRIMARY"}
            })
        ),
        # Network beacon
        (
            "2026-09-20T11:00:10Z",
            "host-siem-99",
            json.dumps({
                "source": {"ip": "10.0.0.5", "port": 49152},
                "destination": {"ip": "198.51.100.22", "port": 4444},
                "network": {"protocol": "tcp"},
                "process": {"entity_id": "proc-ps-101"},
                "host": {"id": "host-siem-99", "name": "DC-PRIMARY"}
            })
        ),
        # Registry persistence
        (
            "2026-09-20T11:00:15Z",
            "host-siem-99",
            json.dumps({
                "registry": {
                    "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "key": "Backdoor",
                    "value": "C:\\Windows\\Temp\\malware.dll",
                    "value_type": "REG_SZ"
                },
                "process": {"entity_id": "proc-ps-101"},
                "host": {"id": "host-siem-99", "name": "DC-PRIMARY"}
            })
        )
    ]
    conn.executemany("INSERT INTO events VALUES (?, ?, ?)", events_data)
    conn.commit()
    conn.close()

    # Calculate initial hash of the db file to verify zero disk mutation
    initial_hash = hashlib.sha256(db_file.read_bytes()).hexdigest()

    db = EndpointDatabase(db_file)
    schema = db.get_schema()

    # All synthesized tables must appear in schema
    expected_tables = ["events", "processes", "files", "network_connections", "registry_events", "hosts", "users", "agent_events"]
    for t in expected_tables:
        assert t in schema

    # Synthesized process table
    procs = db.execute_query("SELECT process_name, pid, executable, host_id, user_id FROM processes")
    assert len(procs) >= 1
    assert any(p["process_name"] == "powershell.exe" and p["pid"] == 5512 for p in procs)

    # Synthesized files table
    files = db.execute_query("SELECT file_name, file_path, sha256 FROM files")
    assert len(files) >= 1
    assert any(f["file_name"] == "malware.dll" and f["sha256"] == "deadbeef12345" for f in files)

    # Synthesized network connections
    conns = db.execute_query("SELECT source_ip, destination_ip, destination_port, protocol FROM network_connections")
    assert len(conns) >= 1
    assert any(c["destination_ip"] == "198.51.100.22" and c["destination_port"] == 4444 for c in conns)

    # Synthesized registry events
    regs = db.execute_query("SELECT registry_path, registry_key, registry_value FROM registry_events")
    assert len(regs) >= 1
    assert any("Run" in r["registry_path"] and r["registry_key"] == "Backdoor" for r in regs)

    # Synthesized hosts & users
    hosts = db.execute_query("SELECT host_id, host_name FROM hosts")
    assert any(h["host_id"] == "host-siem-99" and h["host_name"] == "DC-PRIMARY" for h in hosts)

    users = db.execute_query("SELECT user_id, user_name FROM users")
    assert any(u["user_id"] == "u-admin-1" and u["user_name"] == "admin_bob" for u in users)

    # Verify zero database mutation on disk
    final_hash = hashlib.sha256(db_file.read_bytes()).hexdigest()
    assert initial_hash == final_hash, "Original database file on disk was mutated!"


def test_db_attack_lotl_fileless_shipped_dataset():
    """Verify shipped attack_lotl_fileless.db is single-table on disk, synthesizes all tables,
    and undergoes zero mutation when queried.
    """
    import hashlib
    import sqlite3
    from pathlib import Path

    db_path = Path("endpoint_security_dataset_expanded_corrected/attack_lotl_fileless.db")
    assert db_path.exists(), "attack_lotl_fileless.db must exist"

    # 1. Verify physical on-disk tables: ONLY 'events'
    raw_conn = sqlite3.connect(str(db_path))
    tables = [r[0] for r in raw_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    raw_conn.close()
    assert tables == ["events"], f"Expected only ['events'] on disk, found {tables}"

    # 2. Compute initial SHA-256 hash
    initial_hash = hashlib.sha256(db_path.read_bytes()).hexdigest()

    # 3. Test EndpointDatabase synthesized views and execution
    db = EndpointDatabase(db_path)
    schema = db.get_schema()
    for t in ("events", "processes", "files", "network_connections", "registry_events", "hosts", "users", "agent_events"):
        assert t in schema

    # LOLBins present
    lolbins = db.execute_query(
        "SELECT process_name, pid FROM processes WHERE process_name IN ('mshta.exe', 'powershell.exe', 'wmic.exe', 'certutil.exe', 'schtasks.exe', 'reg.exe')"
    )
    names = {p["process_name"] for p in lolbins}
    assert {"mshta.exe", "powershell.exe", "wmic.exe", "certutil.exe", "schtasks.exe", "reg.exe"}.issubset(names)

    # C2 Network connection
    c2 = db.execute_query("SELECT destination_ip, destination_port FROM network_connections WHERE destination_ip = '198.51.100.77'")
    assert len(c2) >= 1

    # Persistence Registry Run key
    reg = db.execute_query("SELECT registry_key, registry_value FROM registry_events WHERE registry_key = 'OneDriveSync'")
    assert len(reg) >= 1

    # 4. Test search_timeline tool and nested ECS details extraction
    from a1.tools.timeline import search_timeline
    import json
    import a1.config as cfg
    cfg.set_active_database(db_path)
    timeline_raw = search_timeline.invoke({"host_id": "host-lotl-02", "category": "process", "limit": 10})
    assert not timeline_raw.startswith("Error"), f"search_timeline failed: {timeline_raw}"
    timeline_events = json.loads(timeline_raw)
    assert len(timeline_events) > 0
    # Must have extracted nested details properly
    first_event = timeline_events[0]
    assert "details" in first_event
    assert "name" in first_event["details"] or "command_line" in first_event["details"]

    # 5. Verify ZERO disk mutation
    final_hash = hashlib.sha256(db_path.read_bytes()).hexdigest()
    assert initial_hash == final_hash, "attack_lotl_fileless.db was modified on disk!"



