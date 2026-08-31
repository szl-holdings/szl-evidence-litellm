"""SZLEvidenceLogger — the LiteLLM CustomLogger that receipts every request.

Integration posture (pattern: capture via the callback lifecycle, *including*
per-attempt deployment hooks):

* ``log_pre_api_call`` fires once per logical call before the provider
  request. We snapshot the canonical request (model, messages, params) and
  the actor identity here, keyed by ``litellm_call_id``.
* ``async_log_success_event`` / ``async_log_failure_event`` fire once per
  logical call with the final response (or exception) and the true
  wall-clock latency. They produce exactly one terminal receipt per call.
* ``async_pre_call_deployment_hook`` fires per *attempt* (LiteLLM's
  retry/fallback machinery re-enters the call wrapper per attempt, and the
  hook fires on each entry) — each firing bumps that call's
  ``attempt_index``.
* ``async_post_call_success_deployment_hook`` fires per successful attempt
  with the raw deployment response — so a call that fell back leaves a
  receipt for every successful attempt, not just the logical winner.
* ``async_post_call_failure_deployment_hook`` completes the per-attempt
  story for harnesses/proxies that invoke it. Honesty note: LiteLLM 1.98's
  core retry loop does not itself call a per-attempt failure deployment
  hook; attempt-level failures are recovered at the terminal failure event
  (one FAIL receipt covering the exhausted attempt series). No success and
  no logical call ever escapes the trail.

Fail modes (see modes.py): receipt-construction or queueing failures either
raise out of the hook (FAIL_CLOSED — the request fails; with
``require_receipt_before_response`` it fails *before* the caller can see a
response) or are counted in ``stats`` and dropped loudly (FAIL_OPEN).

If litellm is not installed this class is a structural duck-type with
identical method signatures (module-level flag ``LITELLM_AVAILABLE``), so
the package imports and unit-tests anywhere.
"""

from __future__ import annotations

import os
import time
import warnings
from collections import OrderedDict
from datetime import datetime
from typing import Any

from szl_receipts import Outcome

from .modes import EvidencePolicy, FailMode
from .payload import (
    actor_from_api_key,
    build_attempt_receipt,
    canonical_request_doc,
    content_digest,
    jsonable,
)
from .sink import EvidenceBackpressure, EvidenceSink, PendingReceipt, verify_sink

try:  # LiteLLM is an optional extra; never a hard import failure.
    from litellm.integrations.custom_logger import CustomLogger as _LiteLLMCustomLogger

    LITELLM_AVAILABLE = True
except Exception:  # noqa: BLE001 — any litellm import failure means "absent"
    LITELLM_AVAILABLE = False

    class _LiteLLMCustomLogger:  # type: ignore[no-redef]
        """Duck-type base mirroring the litellm CustomLogger hook surface."""

        def log_pre_api_call(self, model: Any, messages: Any, kwargs: Any) -> None: ...
        def log_success_event(
            self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any
        ) -> None: ...
        def log_failure_event(
            self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any
        ) -> None: ...
        async def async_log_success_event(
            self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any
        ) -> None: ...
        async def async_log_failure_event(
            self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any
        ) -> None: ...
        async def async_pre_call_deployment_hook(
            self, kwargs: Any, call_type: Any = None
        ) -> None: ...
        async def async_post_call_success_deployment_hook(
            self, request_data: Any, response: Any, call_type: Any = None
        ) -> None: ...
        async def async_post_call_failure_deployment_hook(
            self, request_data: Any, exception: Any, call_type: Any = None
        ) -> None: ...


__all__ = [
    "LITELLM_AVAILABLE",
    "ReceiptConstructionError",
    "SZLEvidenceLogger",
    "evidence_logger",
]


class ReceiptConstructionError(Exception):
    """FAIL_CLOSED: a receipt could not be built or queued for this call."""


def _seconds_between(start: Any, end: Any) -> float | None:
    """Latency in seconds from LiteLLM's start/end values (datetime or float)."""
    try:
        if isinstance(start, datetime) and isinstance(end, datetime):
            return (end - start).total_seconds()
        return float(end) - float(start)
    except (TypeError, ValueError):
        return None


def _call_id_of(kwargs: Any) -> str | None:
    if isinstance(kwargs, dict):
        cid = kwargs.get("litellm_call_id")
        if cid:
            return str(cid)
        logging_obj = kwargs.get("litellm_logging_obj")
        cid = getattr(logging_obj, "litellm_call_id", None)
        if cid:
            return str(cid)
    return None


def _redacted_request_params(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Sampling/decoding params, minus secrets, bulk content, and live handles."""
    deny = {
        "messages",
        "input",
        "prompt",
        "api_key",
        "api_base",
        "headers",
        "litellm_logging_obj",
        "logger_fn",
        "litellm_call_id",
        "litellm_params",
        "mock_response",
        "client",
    }
    return {
        k: jsonable(v)
        for k, v in kwargs.items()
        if isinstance(k, str) and not k.startswith("_") and k not in deny
    }


def _response_doc(response: Any) -> dict[str, Any] | None:
    """Minimized response subject document: shape + digest, never content.

    We keep the *shape* of the response (id, model, choice count, finish
    reasons, usage) and the digest of each message body. Raw message text
    only ever lands on disk under explicit body capture
    (``SZL_CAPTURE_BODIES=1``), referenced by digest.
    """
    if response is None:
        return None
    data = jsonable(response)
    if not isinstance(data, dict):
        return {"repr_sha256": content_digest(data)}
    doc: dict[str, Any] = {
        "id": data.get("id"),
        "model": data.get("model"),
        "object": data.get("object"),
        "created": data.get("created"),
    }
    usage = data.get("usage")
    if isinstance(usage, dict):
        doc["usage"] = usage
    choices = data.get("choices")
    if isinstance(choices, list):
        doc["choices"] = [
            {
                "index": c.get("index") if isinstance(c, dict) else None,
                "finish_reason": c.get("finish_reason") if isinstance(c, dict) else None,
                "message_sha256": content_digest(c.get("message"))
                if isinstance(c, dict) and "message" in c
                else None,
            }
            for c in choices
        ]
    return doc


def _error_doc(exc: Any) -> dict[str, str]:
    return {
        "type": type(exc).__name__ if exc is not None else "UnknownError",
        "message": (str(exc) or repr(exc))[:512],
    }


class SZLEvidenceLogger(_LiteLLMCustomLogger):
    """LiteLLM callback emitting one hash-chained receipt per request/attempt."""

    def __init__(
        self,
        sink: EvidenceSink | None = None,
        *,
        policy: EvidencePolicy | None = None,
        actor_resolver: Any = None,
        sink_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        if sink is None:
            self.policy = policy or EvidencePolicy.from_env()
            sink = EvidenceSink(sink_dir or self._default_sink_dir(), policy=self.policy)
        else:
            self.policy = policy or sink.policy
        self.sink = sink
        self._actor_resolver = actor_resolver
        self._stats = {"emitted": 0, "errors": 0, "blocked": 0}
        # Per-call state keyed by litellm_call_id; attempts accumulate here so
        # retries/fallbacks share one receipt set with a growing attempt_index.
        self._calls: dict[str, dict[str, Any]] = {}
        # Bounded set of call_ids whose terminal event already emitted — some
        # LiteLLM paths can reach both the sync and async success twins for
        # one call; the second firing is a duplicate, not new evidence.
        self._terminal_seen: OrderedDict[str, None] = OrderedDict()
        # Receipt ids per call, retained (bounded) after the per-attempt
        # buffer is released at the terminal event, so proxies and callers
        # can still correlate after the fact.
        self._receipts_by_call: OrderedDict[str, list[str]] = OrderedDict()

    # ------------------------------------------------------------ internals

    @staticmethod
    def _default_sink_dir() -> str:
        return os.environ.get("SZL_SINK_DIR", "./szl-evidence")

    @classmethod
    def from_env(cls) -> SZLEvidenceLogger:
        """Build a logger entirely from SZL_* environment variables."""
        return cls(policy=EvidencePolicy.from_env())

    def _mark_terminal(self, call_id: str) -> bool:
        """True iff this is the FIRST terminal event for *call_id*."""
        if call_id in self._terminal_seen:
            return False
        self._terminal_seen[call_id] = None
        while len(self._terminal_seen) > 8192:
            self._terminal_seen.popitem(last=False)
        return True

    def _resolve_actor(self, kwargs: dict[str, Any]) -> str:
        if self._actor_resolver is not None:
            resolved = self._actor_resolver(kwargs)
            if resolved:
                return str(resolved)
        litellm_params = kwargs.get("litellm_params")
        key = None
        if isinstance(litellm_params, dict):
            key = litellm_params.get("api_key")
        if key is None:
            key = kwargs.get("api_key")
        if isinstance(key, str) and key:
            return actor_from_api_key(key)
        metadata = kwargs.get("metadata")
        if isinstance(metadata, dict):
            user = metadata.get("user") or metadata.get("user_id")
            if user:
                return f"user:{user}"
        return "anonymous"

    def _call_state(self, kwargs: Any) -> tuple[str, dict[str, Any]]:
        call_id = _call_id_of(kwargs)
        if call_id is None:
            # LiteLLM sets litellm_call_id before any hook fires; a missing id
            # means a foreign harness invoked the hook directly. Synthesize a
            # stable-per-kwargs id so the trail stays complete.
            call_id = f"external:{id(kwargs):x}"
        state = self._calls.get(call_id)
        if state is None:
            state = {
                "call_id": call_id,
                "attempt_index": 0,
                "request_doc": None,
                "actor": None,
                "mock": False,
            }
            self._calls[call_id] = state
        return call_id, state

    def _emit(
        self,
        *,
        kwargs: dict[str, Any] | None,
        state: dict[str, Any],
        response_doc: dict[str, Any] | None,
        outcome: Outcome,
        rationale: str,
        latency_s: float | None,
        error: dict[str, str] | None = None,
        model: str | None = None,
        response_obj: Any = None,
        event: str = "call",
    ) -> str | None:
        """Build and enqueue one receipt. Returns the receipt_id (or None).

        Raises under FAIL_CLOSED (ReceiptConstructionError, or bare
        EvidenceBackpressure when the queue is the failure). Under FAIL_OPEN
        failures are counted (``stats['errors']``) and None is returned —
        loud in the metrics, invisible to the caller's request.
        """
        try:
            kwargs = kwargs or {}
            request_doc = state.get("request_doc")
            if request_doc is None:
                request_doc = canonical_request_doc(
                    model or kwargs.get("model"),
                    kwargs.get("messages"),
                    _redacted_request_params(kwargs),
                )
            prompt_tokens = completion_tokens = None
            finish_reason = None
            cost_usd: float | None = None
            if response_doc is not None:
                usage = response_doc.get("usage") or {}
                if isinstance(usage, dict):
                    prompt_tokens = usage.get("prompt_tokens")
                    completion_tokens = usage.get("completion_tokens")
                choices = response_doc.get("choices") or []
                if choices and isinstance(choices[0], dict):
                    finish_reason = choices[0].get("finish_reason")
            if response_obj is not None:
                try:
                    hidden = getattr(response_obj, "_hidden_params", None) or {}
                    reported = hidden.get("response_cost") if isinstance(hidden, dict) else None
                except Exception:  # noqa: BLE001 — cost is best-effort, never a blocker
                    reported = None
                if isinstance(reported, int | float) and not isinstance(reported, bool):
                    cost_usd = float(reported)

            bodies_dir = None
            if self.sink_capture_bodies():
                bodies_dir = self.sink.directory / "bodies"

            built = build_attempt_receipt(
                policy=self.policy,
                actor=state.get("actor") or self._resolve_actor(kwargs),
                call_id=state["call_id"],
                attempt_index=state["attempt_index"],
                is_fallback=state["attempt_index"] > 1,
                model=model or kwargs.get("model"),
                provider=kwargs.get("custom_llm_provider"),
                request_doc=request_doc,
                response_doc=response_doc,
                outcome=outcome,
                rationale=rationale,
                latency_ms=latency_s * 1000 if latency_s is not None else None,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                finish_reason=finish_reason,
                cost_usd=cost_usd,
                error=error,
                stream=bool(kwargs.get("stream")),
                mock=bool(state.get("mock")),
                bodies_dir=bodies_dir,
                extra={"event": event},
            )
            self.sink.enqueue(
                PendingReceipt(
                    receipt=built.receipt,
                    evidence_doc=built.evidence_doc,
                    evidence_uri=built.evidence_uri,
                )
            )
        except Exception as exc:  # noqa: BLE001 — the fail-mode branch decides
            self._stats["errors"] += 1
            if self.policy.blocks_on_receipt_error():
                self._stats["blocked"] += 1
                if isinstance(exc, EvidenceBackpressure):
                    raise  # preserve the precise signal for audit tooling
                raise ReceiptConstructionError(
                    f"FAIL_CLOSED: no receipt, no response — {type(exc).__name__}: {exc}"
                ) from exc
            return None
        self._stats["emitted"] += 1
        return built.receipt["receipt_id"]

    # ------------------------------------------------------- lifecycle hooks

    def log_pre_api_call(self, model: Any, messages: Any, kwargs: Any) -> None:
        """Snapshot the canonical request and actor before the provider call."""
        if not isinstance(kwargs, dict):
            return
        try:
            _, state = self._call_state(kwargs)
            if state["request_doc"] is None:
                state["request_doc"] = canonical_request_doc(
                    model, messages, _redacted_request_params(kwargs)
                )
                state["actor"] = self._resolve_actor(kwargs)
                state["mock"] = kwargs.get("mock_response") is not None
        except Exception as exc:  # noqa: BLE001
            self._stats["errors"] += 1
            if self.policy.blocks_on_receipt_error():
                raise ReceiptConstructionError(
                    f"FAIL_CLOSED: request snapshot failed — {exc}"
                ) from exc

    async def async_pre_call_deployment_hook(self, kwargs: Any, call_type: Any = None) -> None:
        """Per-attempt entry: each retry/fallback re-enters here.

        Bumps ``attempt_index`` for the call and ensures the request snapshot
        exists. Never modifies the request — evidence is observe-only.
        """
        if not isinstance(kwargs, dict):
            return None
        try:
            _, state = self._call_state(kwargs)
            state["attempt_index"] += 1
            if state["request_doc"] is None:
                state["request_doc"] = canonical_request_doc(
                    kwargs.get("model"),
                    kwargs.get("messages"),
                    _redacted_request_params(kwargs),
                )
                state["actor"] = state.get("actor") or self._resolve_actor(kwargs)
                state["mock"] = kwargs.get("mock_response") is not None
        except Exception as exc:  # noqa: BLE001
            self._stats["errors"] += 1
            if self.policy.blocks_on_receipt_error():
                raise ReceiptConstructionError(
                    f"FAIL_CLOSED: attempt could not enter the evidence trail — {exc}"
                ) from exc
        return None

    async def async_post_call_success_deployment_hook(
        self, request_data: Any, response: Any, call_type: Any = None
    ) -> None:
        """Per-attempt success receipt, before fallbacks collapse.

        Returns None (response unmodified). With require_receipt_before_response
        set — LiteLLM only invokes this hook on its async path — the receipt
        exists (or the call has already raised) before the caller can consume
        the response: the audit-grade ordering guarantee.
        """
        if not isinstance(request_data, dict):
            return None
        _, state = self._call_state(request_data)
        if state["attempt_index"] == 0:
            state["attempt_index"] = 1  # sync path may skip the pre hook
        receipt_id = self._emit(
            kwargs=request_data,
            state=state,
            response_doc=_response_doc(response),
            outcome=Outcome.PASS,
            rationale=f"deployment attempt {state['attempt_index']} succeeded",
            latency_s=None,
            model=request_data.get("model"),
            response_obj=response,
            event="deployment_success",
        )
        if receipt_id:
            state.setdefault("receipt_ids", []).append(receipt_id)
        return None

    async def async_post_call_failure_deployment_hook(
        self, request_data: Any, exception: Any, call_type: Any = None
    ) -> None:
        """Per-attempt failure receipt (for hosts that wire this hook in).

        LiteLLM 1.98's core retry loop does not invoke a per-attempt failure
        deployment hook; this implementation serves proxies and routers that
        do, keeping the per-attempt story complete wherever it can be.
        """
        if not isinstance(request_data, dict):
            return None
        _, state = self._call_state(request_data)
        if state["attempt_index"] == 0:
            state["attempt_index"] = 1
        receipt_id = self._emit(
            kwargs=request_data,
            state=state,
            response_doc=None,
            outcome=Outcome.FAIL,
            rationale=(
                f"deployment attempt {state['attempt_index']} failed: "
                f"{type(exception).__name__}"
            ),
            latency_s=None,
            error=_error_doc(exception),
            model=request_data.get("model"),
            event="deployment_failure",
        )
        if receipt_id:
            state.setdefault("receipt_ids", []).append(receipt_id)
        return None

    # ----------------------------------------------- terminal (logical call)

    async def async_log_success_event(
        self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        """Terminal receipt for the logical call (success)."""
        self._terminal(kwargs, response_obj, start_time, end_time, success=True)

    async def async_log_failure_event(
        self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        """Terminal receipt for the logical call (failure)."""
        self._terminal(kwargs, response_obj, start_time, end_time, success=False)

    # Sync event twins: LiteLLM fires these from its sync call path. The emit
    # path is fully synchronous (build + put_nowait) and the sink accepts
    # receipts with or without a running loop, so the twins share _terminal.
    def log_success_event(
        self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        """Sync success twin of :meth:`async_log_success_event`."""
        self._terminal(kwargs, response_obj, start_time, end_time, success=True)

    def log_failure_event(
        self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        """Sync failure twin of :meth:`async_log_failure_event`."""
        self._terminal(kwargs, response_obj, start_time, end_time, success=False)

    def _terminal(
        self,
        kwargs: Any,
        response_obj: Any,
        start_time: Any,
        end_time: Any,
        *,
        success: bool,
    ) -> None:
        """Emit exactly one terminal receipt per logical call.

        ``_mark_terminal`` deduplicates sync/async double-fires. Receipt ids
        are retained (bounded) after the per-attempt buffer is released, so
        proxies can still correlate a response to its receipt afterwards.
        """
        if not isinstance(kwargs, dict):
            return
        _, state = self._call_state(kwargs)
        if not self._mark_terminal(state["call_id"]):
            self._calls.pop(state["call_id"], None)
            return  # duplicate terminal event — already receipted
        if state["attempt_index"] == 0:
            state["attempt_index"] = 1
        receipt_id = self._emit(
            kwargs=kwargs,
            state=state,
            response_doc=_response_doc(response_obj) if success else None,
            outcome=Outcome.PASS if success else Outcome.FAIL,
            rationale=(
                "llm.completion returned a response"
                if success
                else f"llm.completion raised: {type(response_obj).__name__}"
            ),
            latency_s=_seconds_between(start_time, end_time),
            error=None if success else _error_doc(response_obj),
            model=kwargs.get("model"),
            response_obj=response_obj if success else None,
            event="call_success" if success else "call_failure",
        )
        if receipt_id:
            state.setdefault("receipt_ids", []).append(receipt_id)
        self._receipts_by_call[state["call_id"]] = list(state.get("receipt_ids", []))
        while len(self._receipts_by_call) > 8192:
            self._receipts_by_call.popitem(last=False)
        # Terminal event: the call is over; release the per-attempt buffer.
        self._calls.pop(state["call_id"], None)

    # ---------------------------------------------------------------- extras

    def sink_capture_bodies(self) -> bool:
        """SZL_CAPTURE_BODIES=1 opts into body capture (digest-referenced)."""
        return os.environ.get("SZL_CAPTURE_BODIES", "").lower() in {"1", "true", "yes"}

    def stats(self) -> dict[str, Any]:
        """Plugin + sink counters. A nonzero errors/dropped count is a page."""
        out = dict(self._stats)
        out["sink"] = self.sink.stats()
        out["fail_mode"] = self.policy.fail_mode.value
        out["litellm_available"] = LITELLM_AVAILABLE
        return out

    def receipt_ids_for(self, call_id: str) -> list[str]:
        """Receipt ids emitted for a call (retained after the terminal event)."""
        state = self._calls.get(call_id)
        if state is not None:
            return list(state.get("receipt_ids", []))
        return list(self._receipts_by_call.get(call_id, []))

    def verify(self) -> dict[str, Any]:
        """Verify this logger's sink chain from genesis."""
        return verify_sink(self.sink.directory)

    async def aclose(self) -> None:
        """Drain the sink on shutdown (call from a FastAPI lifespan hook)."""
        await self.sink.aclose()

    def flush_sync(self) -> None:
        """Synchronous drain for shutdown paths without a running loop."""
        self.sink._worker_stop.set()  # noqa: SLF001 — shutdown path, same package
        worker = self.sink._worker  # noqa: SLF001
        if worker is not None and worker.is_alive():
            worker.join(timeout=max(self.sink.flush_interval_s * 2, 1.0))
        tqueue = self.sink._tqueue  # noqa: SLF001
        deadline = time.monotonic() + 5.0
        while tqueue is not None and not tqueue.empty() and time.monotonic() < deadline:
            time.sleep(min(self.sink.flush_interval_s, 0.05))
        if self.sink._queue is not None and not self.sink._queue.empty():  # noqa: SLF001
            raise RuntimeError(
                "receipts remain on the asyncio lane; drain with `await logger.aclose()`"
            )


def _build_module_logger() -> SZLEvidenceLogger | None:
    """The proxy-YAML singleton, created only when explicitly enabled.

    LiteLLM's proxy resolves ``callbacks: szl_evidence_litellm.plugin.evidence_logger``
    by importing this module and reading the attribute. Creation is gated on
    ``SZL_EVIDENCE_LOGGER=1`` so importing the plugin (tests, duck-type use)
    never spins up a sink as an import side effect.
    """
    if os.environ.get("SZL_EVIDENCE_LOGGER", "").lower() not in {"1", "true", "yes"}:
        return None
    policy = EvidencePolicy.from_env()
    sink = EvidenceSink(
        os.environ.get("SZL_SINK_DIR", "./szl-evidence"),
        policy=policy,
        maxsize=int(os.environ.get("SZL_QUEUE_MAXSIZE", "10000")),
    )
    if policy.fail_mode is FailMode.FAIL_OPEN and not os.environ.get("SZL_SINK_DIR"):
        warnings.warn(
            "szl-evidence-litellm: using default sink ./szl-evidence with "
            "FAIL_OPEN; set SZL_SINK_DIR and SZL_FAIL_MODE=fail_closed for "
            "the audit-grade posture",
            stacklevel=2,
        )
    return SZLEvidenceLogger(sink=sink, policy=policy)


evidence_logger = _build_module_logger()
