from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Dict, Iterator, Optional
from uuid import uuid4

from a1.config import (
    LLM_PROVIDER,
    OPENCODE_API_KEY,
    OPENCODE_BASE_URL,
    OPENCODE_MODEL_NAME,
    OPENAI_API_KEY,
    OPENAI_MODEL_NAME,
    OPENAI_BASE_URL,
    OLLAMA_MODEL_NAME,
    OLLAMA_BASE_URL,
    OLLAMA_NUM_CTX,
    OLLAMA_API_KEY,
)

_ACTIVE_PROVIDER: Optional[str] = None
_ACTIVE_MODEL: Optional[str] = None
_OPENCODE_SESSION_ID: ContextVar[Optional[str]] = ContextVar(
    "a1_opencode_session_id",
    default=None,
)


@contextmanager
def opencode_session(session_id: Optional[str] = None) -> Iterator[str]:
    """Keep OpenCode's session header stable across one investigation."""
    value = session_id or f"a1-{uuid4().hex}"
    token = _OPENCODE_SESSION_ID.set(value)
    try:
        yield value
    finally:
        _OPENCODE_SESSION_ID.reset(token)


def stream_investigation(
    graph: Any,
    state: dict,
    session_id: Optional[str] = None,
) -> Iterator[dict]:
    """Stream a graph run with one OpenCode session ID shared by its model calls."""
    with opencode_session(session_id):
        yield from graph.stream(state, stream_mode="values")


def set_active_llm(provider: Optional[str] = None, model: Optional[str] = None) -> None:
    """Set the active LLM provider and model dynamically at runtime."""
    global _ACTIVE_PROVIDER, _ACTIVE_MODEL
    if provider:
        _ACTIVE_PROVIDER = provider.strip().lower()
    if model:
        _ACTIVE_MODEL = model.strip()


def get_active_llm_info() -> Dict[str, str]:
    """Return the active provider and model name."""
    provider = (_ACTIVE_PROVIDER or LLM_PROVIDER).lower()
    if provider == "opencode":
        model = _ACTIVE_MODEL or OPENCODE_MODEL_NAME
    elif provider == "ollama":
        model = _ACTIVE_MODEL or OLLAMA_MODEL_NAME
    elif provider == "openai":
        model = _ACTIVE_MODEL or OPENAI_MODEL_NAME
    else:
        model = _ACTIVE_MODEL or "unknown"
    return {"provider": provider, "model": model}


def _create_ollama_llm(chosen_model: str, temperature: float, kwargs: dict) -> Any:
    from langchain_ollama import ChatOllama
    ollama_kwargs = dict(kwargs)
    client_kwargs = dict(ollama_kwargs.get("client_kwargs", {}))
    if "timeout" not in client_kwargs:
        client_kwargs["timeout"] = 300.0
    if OLLAMA_API_KEY and "headers" not in client_kwargs:
        client_kwargs["headers"] = {"Authorization": f"Bearer {OLLAMA_API_KEY}"}
    ollama_kwargs["client_kwargs"] = client_kwargs

    if "num_ctx" not in ollama_kwargs:
        ollama_kwargs["num_ctx"] = OLLAMA_NUM_CTX
    return ChatOllama(
        model=chosen_model,
        base_url=OLLAMA_BASE_URL,
        temperature=temperature,
        **ollama_kwargs
    )


def _create_openai_llm(chosen_model: str, temperature: float, kwargs: dict) -> Any:
    from langchain_openai import ChatOpenAI
    params: dict = {
        "model": chosen_model,
        "temperature": temperature,
        **kwargs
    }
    if OPENAI_API_KEY:
        params["api_key"] = OPENAI_API_KEY
    if OPENAI_BASE_URL:
        params["base_url"] = OPENAI_BASE_URL

    return ChatOpenAI(**params)


def _create_opencode_llm(chosen_model: str, temperature: float, kwargs: dict) -> Any:
    from langchain_openai import ChatOpenAI

    if not OPENCODE_API_KEY:
        raise ValueError("OPENCODE_API_KEY is required to use the OpenCode provider")

    headers = dict(kwargs.pop("default_headers", {}) or {})
    headers = {
        key: value
        for key, value in headers.items()
        if key.lower() not in {"user-agent", "x-opencode-session"}
    }
    headers["User-Agent"] = "a1-dfir-investigator/0.1.0"
    headers["x-opencode-session"] = _OPENCODE_SESSION_ID.get() or f"a1-{uuid4().hex}"
    params: dict = {
        "model": chosen_model,
        "temperature": temperature,
        "base_url": OPENCODE_BASE_URL,
        "api_key": OPENCODE_API_KEY,
        "default_headers": headers,
        **kwargs,
    }
    return ChatOpenAI(**params)


def get_llm(
    temperature: float = 0.0,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    **kwargs: Any
) -> Any:
    """Factory returning the configured chat model with optional overrides.
    Supports OpenCode, Ollama, and OpenAI.
    """
    chosen_provider = (provider or _ACTIVE_PROVIDER or LLM_PROVIDER).lower()
    active_model = (
        _ACTIVE_MODEL
        if _ACTIVE_PROVIDER is None or _ACTIVE_PROVIDER == chosen_provider
        else None
    )

    if chosen_provider == "opencode":
        chosen_model = model or active_model or OPENCODE_MODEL_NAME
        return _create_opencode_llm(chosen_model, temperature, kwargs)
    if chosen_provider == "ollama":
        chosen_model = model or active_model or OLLAMA_MODEL_NAME
        return _create_ollama_llm(chosen_model, temperature, kwargs)
    if chosen_provider == "openai":
        chosen_model = model or active_model or OPENAI_MODEL_NAME
        return _create_openai_llm(chosen_model, temperature, kwargs)
    raise ValueError(
        f"Unknown LLM_PROVIDER: '{chosen_provider}'. "
        "Supported providers: 'opencode', 'ollama', 'openai'"
    )


def check_llm_status() -> Dict[str, Any]:
    """Check LLM connection and retrieve active provider & model info."""
    provider = (_ACTIVE_PROVIDER or LLM_PROVIDER).lower()
    if provider == "opencode":
        return {
            "status": "configured" if OPENCODE_API_KEY else "missing_api_key",
            "provider": provider,
            "model": _ACTIVE_MODEL or OPENCODE_MODEL_NAME,
            "base_url": OPENCODE_BASE_URL,
            "api_key_set": bool(OPENCODE_API_KEY),
        }
    elif provider == "ollama":
        try:
            llm = get_llm()
            # Send a fast test prompt to verify API connectivity & model availability
            response = llm.invoke("ping")
            return {
                "status": "ok",
                "provider": provider,
                "model": _ACTIVE_MODEL or OLLAMA_MODEL_NAME,
                "base_url": OLLAMA_BASE_URL,
                "api_key_set": bool(OLLAMA_API_KEY),
                "response_preview": str(response.content)[:50],
            }
        except Exception as e:
            return {
                "status": "error",
                "provider": provider,
                "model": _ACTIVE_MODEL or OLLAMA_MODEL_NAME,
                "base_url": OLLAMA_BASE_URL,
                "error": str(e),
            }
    elif provider == "openai":
        return {
            "status": "configured",
            "provider": provider,
            "model": _ACTIVE_MODEL or OPENAI_MODEL_NAME,
            "api_key_set": bool(OPENAI_API_KEY),
        }
    return {"status": "unknown", "provider": provider}


def invoke_with_network_retry(runnable: Any, messages: Any, max_attempts: int = 3) -> Any:
    """Invoke an LLM or runnable with automatic backoff retry on transient network errors."""
    import time
    import logging

    logger = logging.getLogger("a1.llm")
    for attempt in range(max_attempts):
        try:
            return runnable.invoke(messages)
        except Exception as e:
            err_str = f"{type(e).__name__} {str(e)}".lower()
            is_net = any(k in err_str for k in ("disconnect", "protocol", "timeout", "connection", "remote", "reset"))
            if is_net and attempt < max_attempts - 1:
                delay = 1.5 * (attempt + 1)
                logger.warning(
                    f"Transient LLM network issue ({type(e).__name__}: {e}). Retrying attempt {attempt + 2}/{max_attempts} in {delay:.1f}s..."
                )
                time.sleep(delay)
                continue
            raise
