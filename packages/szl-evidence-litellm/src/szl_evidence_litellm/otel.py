"""OTel GenAI semantic-convention mapping — pure dicts, zero dependencies.

The evidence document's field names are ours; OpenTelemetry's GenAI semantic
conventions have their own vocabulary (``gen_ai.request.model``,
``gen_ai.usage.input_tokens``, …). This module is the one blessed place where
the translation lives, so every span the estate emits speaks the standard
names and every ``szl.*`` attribute is namespaced and greppable.

Deliberately dependency-free: :func:`enrich_span` duck-types any object with
a ``set_attribute(key, value)`` method, which covers OTel ``Span``,
OpenInference wrappers, and test doubles alike. No ``opentelemetry`` import
ever happens here.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = [
    "GEN_AI_OPERATION_NAME",
    "GEN_AI_REQUEST_MODEL",
    "GEN_AI_RESPONSE_FINISH_REASONS",
    "GEN_AI_SYSTEM",
    "GEN_AI_USAGE_INPUT_TOKENS",
    "GEN_AI_USAGE_OUTPUT_TOKENS",
    "enrich_span",
    "otel_attributes",
]

# OTel GenAI semconv attribute names (stable vocabulary).
GEN_AI_SYSTEM = "gen_ai.system"
GEN_AI_OPERATION_NAME = "gen_ai.operation.name"
GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
GEN_AI_RESPONSE_FINISH_REASONS = "gen_ai.response.finish_reasons"
GEN_AI_USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens"
GEN_AI_USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"


def otel_attributes(
    evidence: Mapping[str, Any],
    *,
    receipt_id: str | None = None,
    outcome: str | None = None,
) -> dict[str, Any]:
    """Map one evidence document to OTel GenAI semconv attributes.

    Only observed values are emitted — a missing token count is ``None`` in
    the evidence document and simply absent here, because an exporter that
    writes ``input_tokens: 0`` for an unobserved count is manufacturing data.
    ``szl.*`` attributes carry the evidence-plane correlation fields that
    have no semconv home.
    """
    attrs: dict[str, Any] = {GEN_AI_OPERATION_NAME: "chat"}

    provider = evidence.get("provider")
    if provider:
        attrs[GEN_AI_SYSTEM] = str(provider)
    model = evidence.get("model")
    if model:
        attrs[GEN_AI_REQUEST_MODEL] = str(model)
    finish_reason = evidence.get("finish_reason")
    if finish_reason:
        # semconv defines finish_reasons as a *list* of strings.
        attrs[GEN_AI_RESPONSE_FINISH_REASONS] = [str(finish_reason)]
    prompt_tokens = evidence.get("prompt_tokens")
    if isinstance(prompt_tokens, int) and not isinstance(prompt_tokens, bool):
        attrs[GEN_AI_USAGE_INPUT_TOKENS] = prompt_tokens
    completion_tokens = evidence.get("completion_tokens")
    if isinstance(completion_tokens, int) and not isinstance(completion_tokens, bool):
        attrs[GEN_AI_USAGE_OUTPUT_TOKENS] = completion_tokens

    call_id = evidence.get("call_id")
    if call_id:
        attrs["szl.llm.call_id"] = str(call_id)
    attempt_index = evidence.get("attempt_index")
    if isinstance(attempt_index, int) and not isinstance(attempt_index, bool):
        attrs["szl.llm.attempt_index"] = attempt_index
    if evidence.get("is_fallback") is not None:
        attrs["szl.llm.is_fallback"] = bool(evidence.get("is_fallback"))
    latency_ms = evidence.get("latency_ms")
    if isinstance(latency_ms, int | float) and not isinstance(latency_ms, bool):
        attrs["szl.llm.latency_ms"] = latency_ms
    cost_usd = evidence.get("cost_usd")
    if isinstance(cost_usd, int | float) and not isinstance(cost_usd, bool):
        attrs["szl.llm.cost_usd"] = cost_usd
    if evidence.get("mock"):
        attrs["szl.llm.mock"] = True
    if receipt_id:
        attrs["szl.receipt.id"] = receipt_id
    if outcome:
        attrs["szl.receipt.outcome"] = str(outcome)
    return attrs


def enrich_span(
    span: Any,
    evidence: Mapping[str, Any],
    *,
    receipt_id: str | None = None,
    outcome: str | None = None,
) -> dict[str, Any]:
    """Set the mapped attributes on *span* and return them (for testability).

    ``span`` is duck-typed: anything with ``set_attribute(key, value)``. The
    returned dict is exactly what was set, so callers can assert on it
    without a telemetry SDK in the test environment.
    """
    attrs = otel_attributes(evidence, receipt_id=receipt_id, outcome=outcome)
    set_attribute = getattr(span, "set_attribute", None)
    if not callable(set_attribute):
        raise TypeError("span must provide set_attribute(key, value)")
    for key, value in attrs.items():
        set_attribute(key, value)
    return attrs
