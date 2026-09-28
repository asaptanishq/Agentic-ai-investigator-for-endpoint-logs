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
