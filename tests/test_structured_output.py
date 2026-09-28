import pytest

from a1.nodes.structured_output import StructuredOutputRetryError, invoke_structured_with_retry


class _SequenceInvoker:
    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_structured_output_returns_first_success_without_retry():
    expected = {"verdict": "malicious"}
    invoker = _SequenceInvoker([expected])

    result, retried = invoke_structured_with_retry(invoker, [], "report")

    assert result == expected
    assert retried is False
    assert invoker.calls == 1


def test_structured_output_retries_once_after_parse_failure():
    expected = {"verdict": "malicious"}
    invoker = _SequenceInvoker([ValueError("invalid output"), expected])

    result, retried = invoke_structured_with_retry(invoker, [], "report")

    assert result == expected
    assert retried is True
    assert invoker.calls == 2


def test_structured_output_propagates_failure_after_one_retry():
    invoker = _SequenceInvoker([ValueError("first"), RuntimeError("second")])

    with pytest.raises(StructuredOutputRetryError, match="RuntimeError") as exc_info:
        invoke_structured_with_retry(invoker, [], "report")

    assert invoker.calls == 2
    assert str(exc_info.value.retry_error) == "second"