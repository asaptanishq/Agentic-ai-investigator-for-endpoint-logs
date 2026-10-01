import json
from typing import Any, Dict, Optional, Sequence, Tuple

from langchain_core.messages import HumanMessage


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
    import time

    def _invoke_with_network_retry(runnable, msgs, max_attempts=3):
        for attempt in range(max_attempts):
            try:
                return runnable.invoke(msgs)
            except Exception as e:
                err_str = f"{type(e).__name__} {str(e)}".lower()
                is_net = any(k in err_str for k in ("disconnect", "protocol", "timeout", "connection", "remote", "reset"))
                if is_net and attempt < max_attempts - 1:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise

    try:
        return _invoke_with_network_retry(structured_llm, messages), False
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
            return _invoke_with_network_retry(structured_llm, retry_messages), True
        except Exception as retry_error:
            raise StructuredOutputRetryError(first_error, retry_error) from retry_error


def extract_outer_json(text: str) -> Optional[Dict[str, Any]]:
    """Find and parse the first valid outer JSON object from text using balanced bracket scanning."""
    if not text:
        return None
    search_starts = []
    comp_pos = text.lower().find("completion")
    if comp_pos != -1:
        search_starts.append(comp_pos)
    search_starts.append(0)

    for start_search in search_starts:
        start = -1
        depth = 0
        in_string = False
        escape = False

        for i in range(start_search, len(text)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == '\\' and in_string:
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue

            if ch == '{':
                if depth == 0:
                    start = i
                depth += 1
            elif ch == '}':
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start != -1:
                        candidate = text[start : i + 1]
                        try:
                            data = json.loads(candidate)
                            if isinstance(data, dict):
                                return data
                        except Exception:
                            pass
                        start = -1
    return None