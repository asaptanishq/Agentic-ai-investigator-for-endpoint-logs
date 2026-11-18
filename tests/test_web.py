"""Tests for the A1 DFIR Web Interface API."""
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
