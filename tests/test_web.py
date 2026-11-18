"""Tests for the A1 DFIR Web Interface API."""
import json

import pytest
from fastapi.testclient import TestClient
from a1.web.server import create_app

@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)

def test_index_page(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "A1 DFIR Investigator" in res.text
    assert "promptInput" in res.text
    assert "modelSelectorPill" in res.text
    assert "processLinksContainer" in res.text
    assert "process-links.js" in res.text

def test_api_status(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert "active_llm" in data
    assert "current_db" in data
    assert "databases" in data

def test_api_models(client):
    res = client.get("/api/models")
    assert res.status_code == 200
    data = res.json()
    assert "opencode" in data
    assert "ollama" in data
    assert "openai" in data
    assert len(data["opencode"]) > 0
    assert len(data["ollama"]) > 0


def test_api_chat_empty_message_rejected(client):
    res = client.post("/api/chat", json={"message": "   "})
    assert res.status_code == 400


def test_api_chat_stream_endpoint(client, monkeypatch):
    class FakeLLM:
        def invoke(self, messages):
            class Response:
                content = "Test copilot reply explaining evidence"
            return Response()

    import a1.web.server as server_mod
    monkeypatch.setattr(server_mod, "get_llm", lambda **kwargs: FakeLLM())

    res = client.post("/api/chat", json={"message": "Why was PID 4151 flagged?"})
    assert res.status_code == 200
    assert "text/event-stream" in res.headers["content-type"]
    text = res.text
    assert "Test copilot reply explaining evidence" in text

def test_api_set_model(client):
    res = client.post("/api/models/set", json={"provider": "ollama", "model": "gemma4:31b"})
    assert res.status_code == 200
    data = res.json()
    assert data["active_llm"]["model"] == "gemma4:31b"

def test_api_databases(client):
    res = client.get("/api/databases")
    assert res.status_code == 200
    data = res.json()
    assert len(data["databases"]) > 0
    assert all("scratch" not in d["path"].lower() for d in data["databases"])


def test_api_event_lookup_returns_specific_ids(client):
    listed = client.get("/api/events?limit=100")
    assert listed.status_code == 200
    events = listed.json()["events"]
    assert events
    event_id = events[0]["event_id"]

    res = client.post("/api/events/lookup", json={"ids": [event_id, "does-not-exist"]})
    assert res.status_code == 200
    data = res.json()
    assert [e["event_id"] for e in data["events"]] == [event_id]
    assert "details" in data["events"][0]


def test_api_set_database_valid(client):
    dbs = client.get("/api/databases").json()["databases"]
    target = dbs[0]["path"]
    res = client.post("/api/databases/set", json={"db_path": target})
    assert res.status_code == 200
    assert res.json()["status"] == "updated"


def test_api_set_database_rejects_traversal(client):
    res = client.post("/api/databases/set", json={"db_path": "../../windows/win.ini"})
    assert res.status_code == 400


def test_api_set_database_rejects_non_db(client):
    res = client.post("/api/databases/set", json={"db_path": "README.md"})
    assert res.status_code == 400


def test_api_set_database_not_found(client):
    res = client.post("/api/databases/set", json={"db_path": "endpoint_security_dataset_expanded_corrected/non_existent.db"})
    assert res.status_code == 404



def _upload_payload(tmp_path):
    import sqlite3
    src = tmp_path / "payload.db"
    conn = sqlite3.connect(src)
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, action TEXT)")
    conn.execute("INSERT INTO events (action) VALUES ('test')")
    conn.commit()
    conn.close()
    return src.read_bytes()


def test_api_upload_database(client, tmp_path, monkeypatch):
    import a1.web.server as server_mod
    custom = tmp_path / "custom"
    monkeypatch.setattr(server_mod, "CUSTOM_DB_DIR", custom)
    payload = _upload_payload(tmp_path)

    res = client.post(
        "/api/databases/upload?filename=my%20telemetry.db",
        content=payload,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["name"] == "my_telemetry.db"
    assert (custom / data["name"]).is_file()

    again = client.post(
        "/api/databases/upload?filename=my%20telemetry.db",
        content=payload,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert again.status_code == 200
    assert again.json()["name"] == "my_telemetry-2.db"


def test_api_upload_database_rejects_non_sqlite(client, tmp_path, monkeypatch):
    import a1.web.server as server_mod
    monkeypatch.setattr(server_mod, "CUSTOM_DB_DIR", tmp_path / "custom")
    res = client.post(
        "/api/databases/upload?filename=notes.db",
        content=b"this is not sqlite",
        headers={"Content-Type": "application/octet-stream"},
    )
    assert res.status_code == 400
    assert not list((tmp_path / "custom").glob("*.db"))


def test_api_upload_database_strips_paths(client, tmp_path, monkeypatch):
    import a1.web.server as server_mod
    custom = tmp_path / "custom"
    monkeypatch.setattr(server_mod, "CUSTOM_DB_DIR", custom)
    res = client.post(
        "/api/databases/upload?filename=..%2F..%2Fevil.db",
        content=_upload_payload(tmp_path),
        headers={"Content-Type": "application/octet-stream"},
    )
    assert res.status_code == 200
    assert res.json()["path"] == str(custom / "evil.db")


def test_api_upload_log_ingests_database(client, tmp_path, monkeypatch):
    import a1.web.server as server_mod
    custom = tmp_path / "custom"
    monkeypatch.setattr(server_mod, "CUSTOM_DB_DIR", custom)
    payload = b'{"timestamp":"2026-09-10T08:05:00Z","event_type":"alert","src_ip":"10.0.0.5","dest_ip":"10.0.0.9","alert":{"signature_id":7,"signature":"test","severity":2}}\n'

    res = client.post(
        "/api/databases/upload?filename=eve.jsonl",
        content=payload,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ingested"
    assert data["rows"] == 1
    assert data["source"] == "suricata"
    assert data["name"] == "eve.db"
    assert (custom / data["name"]).is_file()


def test_api_upload_log_rejects_malformed_json(client, tmp_path, monkeypatch):
    import a1.web.server as server_mod
    custom = tmp_path / "custom"
    monkeypatch.setattr(server_mod, "CUSTOM_DB_DIR", custom)
    res = client.post(
        "/api/databases/upload?filename=broken.json",
        content=b"{not json",
        headers={"Content-Type": "application/octet-stream"},
    )
    assert res.status_code == 400
    assert not list(custom.glob("*.db"))


def test_api_ingest_multi_merges_scenario_files(client, tmp_path, monkeypatch):
    import base64

    import a1.web.server as server_mod
    custom = tmp_path / "custom"
    monkeypatch.setattr(server_mod, "CUSTOM_DB_DIR", custom)

    wazuh = json.dumps({
        "timestamp": "2022-01-17T11:58:17.100+0000",
        "rule": {"id": "554", "level": 0, "description": "File added to the system."},
        "agent": {"id": "021", "name": "wazuh-client-21"},
        "manager": {"name": "wazuh-manager"},
        "decoder": {"name": "sshd"},
        "full_log": "Jan 17 11:58:17 intranet-server sshd[20749]: Accepted password for katelyn.clayton from 172.21.128.119 port 51222 ssh2",
    }) + "\n"
    aminer = json.dumps({
        "AnalysisComponent": {
            "AnalysisComponentIdentifier": 3,
            "AnalysisComponentType": "NewMatchPathValueComboDetector",
            "Message": "New path(es) detected",
            "TrainingMode": False,
        },
        "LogData": {
            "RawLogData": [
                "type=USER_CMD msg=audit(1642420709.209:663): pid=21058 uid=1002 "
                "msg='cwd=\"/var/www\" cmd=636174202F6574632F736861646F77 terminal=pts/1 res=success'"
            ],
            "Timestamps": [1642420709.25],
        },
        "AMiner": {"ID": "192.168.104.155"},
    }) + "\n"

    res = client.post(
        "/api/databases/ingest-multi",
        json={"files": [
            {"filename": "santos_wazuh.json", "data_base64": base64.b64encode(wazuh.encode()).decode()},
            {"filename": "santos_aminer.json", "data_base64": base64.b64encode(aminer.encode()).decode()},
        ]},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "ingested"
    assert data["name"] == "santos.db"
    assert data["rows"] == 2
    assert data["source"] == "wazuh+aminer"
    assert {entry["source"] for entry in data["files"]} == {"wazuh", "aminer"}
    assert (custom / "santos.db").is_file()


def test_api_ingest_multi_rejects_bad_base64(client, tmp_path, monkeypatch):
    import a1.web.server as server_mod
    monkeypatch.setattr(server_mod, "CUSTOM_DB_DIR", tmp_path / "custom")
    res = client.post(
        "/api/databases/ingest-multi",
        json={"files": [{"filename": "x.json", "data_base64": "!!not base64!!"}]},
    )
    assert res.status_code == 400


def test_api_delete_database_and_protects_active(client, tmp_path, monkeypatch):
    import a1.web.server as server_mod
    custom = tmp_path / "custom"
    monkeypatch.setattr(server_mod, "CUSTOM_DB_DIR", custom)
    payload = _upload_payload(tmp_path)
    uploaded = client.post(
        "/api/databases/upload?filename=delete-me.db",
        content=payload,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert uploaded.status_code == 200
    path = uploaded.json()["path"]
    assert (custom / "delete-me.db").is_file()

    deleted = client.delete("/api/databases", params={"path": path})
    assert deleted.status_code == 200
    assert deleted.json()["status"] == "deleted"
    assert not (custom / "delete-me.db").exists()

    active = client.get("/api/status").json()["current_db"]
    protected = client.delete("/api/databases", params={"path": active})
    assert protected.status_code == 409


def test_api_set_api_key_persists_and_updates_catalog(client, tmp_path, monkeypatch):
    import a1.config as cfg
    import a1.llm as llm
    env_file = tmp_path / ".env"
    monkeypatch.setattr(cfg, "ENV_PATH", env_file)
    old = cfg.OPENCODE_API_KEY
    try:
        res = client.post("/api/models/api-key", json={"provider": "opencode", "api_key": "sk-test-key"})
        assert res.status_code == 200
        assert res.json()["api_key_set"] is True
        assert 'OPENCODE_API_KEY="sk-test-key"' in env_file.read_text(encoding="utf-8")
        assert cfg.OPENCODE_API_KEY == "sk-test-key"
        assert llm.OPENCODE_API_KEY == "sk-test-key"
    finally:
        cfg.OPENCODE_API_KEY = old
        llm.OPENCODE_API_KEY = old

    bad = client.post("/api/models/api-key", json={"provider": "bogus", "api_key": "x"})
    assert bad.status_code == 400
