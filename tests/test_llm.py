import pytest

import a1.llm as llm


def test_opencode_client_uses_go_endpoint_and_stable_session(monkeypatch):
    received = []

    class FakeChatOpenAI:
        def __init__(self, **kwargs):
            received.append(kwargs)

    monkeypatch.setattr("langchain_openai.ChatOpenAI", FakeChatOpenAI)
    monkeypatch.setattr(llm, "OPENCODE_API_KEY", "test-key")

    with llm.opencode_session("investigation-123"):
        llm.get_llm(provider="opencode", model="glm-5.3")
        llm.get_llm(provider="opencode", model="glm-5.3")

    assert len(received) == 2
    for params in received:
        assert params["model"] == "glm-5.3"
        assert params["base_url"] == llm.OPENCODE_BASE_URL
        assert params["api_key"] == "test-key"
        assert params["default_headers"]["x-opencode-session"] == "investigation-123"
        assert params["default_headers"]["User-Agent"] == "a1-dfir-investigator/0.1.0"


def test_opencode_session_generates_distinct_sessions(monkeypatch):
    sessions = []
    models = []

    class FakeChatOpenAI:
        def __init__(self, **kwargs):
            sessions.append(kwargs["default_headers"]["x-opencode-session"])
            models.append(kwargs["model"])

    monkeypatch.setattr("langchain_openai.ChatOpenAI", FakeChatOpenAI)
    monkeypatch.setattr(llm, "OPENCODE_API_KEY", "test-key")
    monkeypatch.setattr(llm, "OPENCODE_MODEL_NAME", "glm-5.3")

    llm.get_llm(provider="opencode")
    llm.get_llm(provider="opencode")

    assert sessions[0] != sessions[1]
    assert models == ["glm-5.3", "glm-5.3"]


def test_stream_investigation_reuses_web_session_id(monkeypatch):
    sessions = []

    class FakeChatOpenAI:
        def __init__(self, **kwargs):
            sessions.append(kwargs["default_headers"]["x-opencode-session"])

    class FakeGraph:
        def stream(self, state, stream_mode):
            llm.get_llm(provider="opencode")
            yield {"state": state, "mode": stream_mode}

    monkeypatch.setattr("langchain_openai.ChatOpenAI", FakeChatOpenAI)
    monkeypatch.setattr(llm, "OPENCODE_API_KEY", "test-key")

    result = list(llm.stream_investigation(FakeGraph(), {"query": "alert"}, "web-session"))

    assert result == [{"state": {"query": "alert"}, "mode": "values"}]
    assert sessions == ["web-session"]


def test_opencode_default_headers_preserve_custom_headers(monkeypatch):
    received = {}

    class FakeChatOpenAI:
        def __init__(self, **kwargs):
            received.update(kwargs)

    monkeypatch.setattr("langchain_openai.ChatOpenAI", FakeChatOpenAI)
    monkeypatch.setattr(llm, "OPENCODE_API_KEY", "test-key")

    llm.get_llm(
        provider="opencode",
        default_headers={"x-custom-header": "custom-value"},
    )

    assert received["default_headers"]["x-custom-header"] == "custom-value"
    assert received["default_headers"]["x-opencode-session"]
    assert received["default_headers"]["User-Agent"] == "a1-dfir-investigator/0.1.0"


def test_opencode_requires_api_key(monkeypatch):
    monkeypatch.setattr(llm, "OPENCODE_API_KEY", "")

    with pytest.raises(ValueError, match="OPENCODE_API_KEY is required"):
        llm.get_llm(provider="opencode")
