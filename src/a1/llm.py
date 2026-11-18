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
_REQUEST_PROVIDER: ContextVar[Optional[str]] = ContextVar(
    "a1_request_provider", default=None
)
_REQUEST_MODEL: ContextVar[Optional[str]] = ContextVar(
    "a1_request_model", default=None
)
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
    """Set the default LLM provider and model at runtime."""
    global _ACTIVE_PROVIDER, _ACTIVE_MODEL
    if provider:
        _ACTIVE_PROVIDER = provider.strip().lower()
    if model:
        _ACTIVE_MODEL = model.strip()


@contextmanager
def llm_request_context(
    provider: Optional[str] = None, model: Optional[str] = None
) -> Iterator[None]:
    """Scope a provider/model choice to one request thread instead of process globals."""
    provider_token = _REQUEST_PROVIDER.set(provider.strip().lower()) if provider else None
    model_token = _REQUEST_MODEL.set(model.strip()) if model else None
    try:
        yield
    finally:
        if model_token is not None:
            _REQUEST_MODEL.reset(model_token)
        if provider_token is not None:
            _REQUEST_PROVIDER.reset(provider_token)


def get_active_llm_info() -> Dict[str, str]:
    """Return the active provider and model name."""
    request_provider = _REQUEST_PROVIDER.get()
    provider = (request_provider or _ACTIVE_PROVIDER or LLM_PROVIDER).lower()
    requested_model = _REQUEST_MODEL.get() if request_provider else None
    if provider == "opencode":
        model = requested_model or _ACTIVE_MODEL or OPENCODE_MODEL_NAME
    elif provider == "ollama":
        model = requested_model or _ACTIVE_MODEL or OLLAMA_MODEL_NAME
    elif provider == "openai":
        model = requested_model or _ACTIVE_MODEL or OPENAI_MODEL_NAME
    else:
        model = requested_model or _ACTIVE_MODEL or "unknown"
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
    request_provider = _REQUEST_PROVIDER.get()
    request_model = _REQUEST_MODEL.get()
    chosen_provider = (provider or request_provider or _ACTIVE_PROVIDER or LLM_PROVIDER).lower()
    if model:
        active_model = model
    elif request_model and (request_provider or chosen_provider) == chosen_provider:
        active_model = request_model
    elif request_provider is None and (_ACTIVE_PROVIDER is None or _ACTIVE_PROVIDER == chosen_provider):
        active_model = _ACTIVE_MODEL
    else:
        active_model = None

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


def is_transient_llm_error(exc: Exception) -> bool:
    """Return True for network failures, timeouts, and rate limits worth retrying."""
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(getattr(exc, "response", None), "status_code", None)
    if status == 429 or status in (500, 502, 503, 504):
        return True
    if "ratelimit" in type(exc).__name__.lower():
        return True

    try:
        import openai
        if isinstance(exc, openai.RateLimitError):
            return True
        if isinstance(exc, (openai.APIConnectionError, openai.APITimeoutError)):
            return True
        if isinstance(exc, openai.APIStatusError) and exc.status_code >= 500:
            return True
    except ImportError:
        pass

    try:
        import httpx
        if isinstance(exc, (httpx.TimeoutException, httpx.RequestError)):
            return True
    except ImportError:
        pass

    import urllib.error
    if isinstance(exc, urllib.error.URLError):
        return True
    return isinstance(exc, (ConnectionError, TimeoutError))


def _retry_delay_seconds(exc: Exception, attempt: int) -> float:
    import random

    retry_after = getattr(exc, "retry_after", None)
    if retry_after is None:
        headers = getattr(getattr(exc, "response", None), "headers", {}) or {}
        retry_after = headers.get("retry-after")
    try:
        delay = float(retry_after)
    except (TypeError, ValueError):
        delay = 1.5 * (attempt + 1)
    return min(max(delay, 1.0), 30.0) + random.uniform(0, 0.5)


def invoke_with_network_retry(runnable: Any, messages: Any, max_attempts: int = 3) -> Any:
    """Invoke with backoff retry for network errors and HTTP 429/5xx responses."""
    import logging
    import time

    logger = logging.getLogger("a1.llm")
    for attempt in range(max_attempts):
        try:
            return runnable.invoke(messages)
        except Exception as e:
            if not is_transient_llm_error(e) or attempt >= max_attempts - 1:
                raise
            delay = _retry_delay_seconds(e, attempt)
            logger.warning(
                "Transient LLM error (%s: %s). Retrying attempt %d/%d in %.1fs...",
                type(e).__name__,
                e,
                attempt + 2,
                max_attempts,
                delay,
            )
            time.sleep(delay)
    raise RuntimeError("unreachable")
