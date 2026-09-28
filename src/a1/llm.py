from typing import Any, Dict, Optional
from a1.config import (
    LLM_PROVIDER,
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
    if provider == "ollama":
        model = _ACTIVE_MODEL or OLLAMA_MODEL_NAME
    elif provider == "openai":
        model = _ACTIVE_MODEL or OPENAI_MODEL_NAME
    else:
        model = _ACTIVE_MODEL or "unknown"
    return {"provider": provider, "model": model}

def get_llm(
    temperature: float = 0.0,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    **kwargs: Any
) -> Any:
    """Factory function returning the configured LangChain chat model.
    Supports Ollama and OpenAI. Accepts provider and model overrides.
    """
    chosen_provider = (provider or _ACTIVE_PROVIDER or LLM_PROVIDER).lower()

    if chosen_provider == "ollama":
        from langchain_ollama import ChatOllama
        chosen_model = model or _ACTIVE_MODEL or OLLAMA_MODEL_NAME
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
    elif chosen_provider == "openai":
        from langchain_openai import ChatOpenAI
        chosen_model = model or _ACTIVE_MODEL or OPENAI_MODEL_NAME
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
    else:
        raise ValueError(f"Unknown LLM_PROVIDER: '{chosen_provider}'. Supported providers: 'ollama', 'openai'")

def check_llm_status() -> Dict[str, Any]:
    """Check LLM connection and retrieve active provider & model info."""
    provider = LLM_PROVIDER.lower()
    if provider == "ollama":
        try:
            llm = get_llm()
            # Send a fast test prompt to verify API connectivity & model availability
            response = llm.invoke("ping")
            return {
                "status": "ok",
                "provider": provider,
                "model": OLLAMA_MODEL_NAME,
                "base_url": OLLAMA_BASE_URL,
                "api_key_set": bool(OLLAMA_API_KEY),
                "response_preview": str(response.content)[:50],
            }
        except Exception as e:
            return {
                "status": "error",
                "provider": provider,
                "model": OLLAMA_MODEL_NAME,
                "base_url": OLLAMA_BASE_URL,
                "error": str(e),
            }
    elif provider == "openai":
        return {
            "status": "configured",
            "provider": provider,
            "model": OPENAI_MODEL_NAME,
            "api_key_set": bool(OPENAI_API_KEY),
        }
    return {"status": "unknown", "provider": provider}

