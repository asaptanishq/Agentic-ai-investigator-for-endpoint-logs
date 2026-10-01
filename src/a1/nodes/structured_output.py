import json
from typing import Any, Dict, Optional, Sequence, Tuple

from langchain_core.messages import HumanMessage
from a1.llm import invoke_with_network_retry


class StructuredOutputRetryError(Exception):
    def __init__(self, first_error: Exception, retry_error: Exception):
        self.first_error = first_error
        self.retry_error = retry_error
        super().__init__(
            f"structured output failed on initial attempt and retry: {type(retry_error).__name__}"
        )


def invoke_structured_with_retry(
    structured_llm: Any,
    messages: Sequence[Any],
    output_label: str,
) -> Tuple[Any, bool]:
    """Invoke structured output with retries on transient network errors and format repair."""
    try:
        return invoke_with_network_retry(structured_llm, messages), False
    except Exception as first_error:
        err_str = f"{type(first_error).__name__} {str(first_error)}".lower()
        if any(k in err_str for k in ("disconnect", "protocol", "timeout", "connection", "remote", "reset")):
            raise

        retry_messages = [
            *messages,
            HumanMessage(content=(
                f"The previous {output_label} response could not be parsed into the required schema "
                f"({type(first_error).__name__}). Return the same analysis again using only the required "
                "structured fields. Do not include Markdown fences or surrounding commentary."
            )),
        ]
        try:
            return invoke_with_network_retry(structured_llm, retry_messages), True
        except Exception as retry_error:
            raise StructuredOutputRetryError(first_error, retry_error) from retry_error


def extract_outer_json(text: str) -> Optional[Dict[str, Any]]:
    """Find and parse the first valid outer JSON object from text."""
    if not text:
        return None
    decoder = json.JSONDecoder()
    pos = 0
    while True:
        idx = text.find("{", pos)
        if idx == -1:
            break
        try:
            obj, _ = decoder.raw_decode(text[idx:])
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
        pos = idx + 1
    return None
