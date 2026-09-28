from typing import Any, Sequence, Tuple

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
    """Invoke structured output once more with a concise format repair request."""
    try:
        return structured_llm.invoke(messages), False
    except Exception as first_error:
        retry_messages = [
            *messages,
            HumanMessage(content=(
                f"The previous {output_label} response could not be parsed into the required schema "
                f"({type(first_error).__name__}). Return the same analysis again using only the required "
                "structured fields. Do not include Markdown fences or surrounding commentary."
            )),
        ]
        try:
            return structured_llm.invoke(retry_messages), True
        except Exception as retry_error:
            raise StructuredOutputRetryError(first_error, retry_error) from retry_error