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

