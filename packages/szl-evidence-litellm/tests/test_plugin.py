"""Plugin tests driven through the duck-typed hook surface directly.

These tests need no litellm: they invoke the exact CustomLogger hook
signatures with litellm-shaped kwargs, which is precisely what the
LITELLM_AVAILABLE=False fallback exists to support.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import pytest
from conftest import make_policy
from szl_evidence_litellm import (
    EvidenceBackpressure,
    EvidenceSink,
    FailMode,
    SZLEvidenceLogger,
    verify_sink,
)
from szl_evidence_litellm.plugin import LITELLM_AVAILABLE, ReceiptConstructionError


def _run(coro):
    return asyncio.run(coro)


def _kwargs(call_id: str, model: str = "gpt-3.5-turbo", **extra):
    base = {
        "litellm_call_id": call_id,
        "model": model,
        "messages": [{"role": "user", "content": "hello"}],
        "custom_llm_provider": "openai",
        "temperature": 0.0,
        "litellm_params": {"api_key": "sk-test-abc"},
    }
    base.update(extra)
    return base


def _evidence_of(sink, entry):
    import json

    uri = entry["receipt"]["evidence"][0]["uri"]
    return json.loads((sink.directory / uri).read_text())


def _response(model: str = "gpt-3.5-turbo", finish: str = "stop"):
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1756634400,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "hello back"},
                "finish_reason": finish,
            }
        ],
        "usage": {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4},
    }


@pytest.fixture()
def logger(sink, policy) -> SZLEvidenceLogger:
    return SZLEvidenceLogger(sink=sink, policy=policy)


class TestHappyPath:
    def test_pre_call_and_terminal_success_emit_chained_receipts(self, logger, policy, sink):
        async def scenario():
            await sink.start()
            logger.log_pre_api_call(
                "gpt-3.5-turbo", [{"role": "user", "content": "hello"}], _kwargs("c-1")
            )
            await logger.async_pre_call_deployment_hook(_kwargs("c-1"), "completion")
            await logger.async_post_call_success_deployment_hook(
                _kwargs("c-1"), _response(), "completion"
            )
            await logger.async_log_success_event(
                _kwargs("c-1"), _response(), time.time() - 0.2, time.time()
            )
            await sink.aclose()

        _run(scenario())
        entries = list(sink.iterate())
        assert len(entries) == 2  # deployment attempt + terminal call receipt
        events = [_evidence_of(sink, e)["extra"]["event"] for e in entries]
        assert events == ["deployment_success", "call_success"]
        assert verify_sink(sink.directory)["ok"]
        ids = logger.receipt_ids_for("c-1")
        assert len(ids) == 2
        assert all(len(rid) == 64 for rid in ids)

    def test_terminal_failure_receipt(self, logger, sink):
        async def scenario():
            await sink.start()
            logger.log_pre_api_call("gpt-3.5-turbo", [], _kwargs("c-2"))
            await logger.async_log_failure_event(
                _kwargs("c-2"), TimeoutError("provider timeout"), time.time(), time.time()
            )
            await sink.aclose()

        _run(scenario())
        (entry,) = list(sink.iterate())
        receipt = entry["receipt"]
        assert receipt["decision"]["outcome"] == "FAIL"
        evidence = _evidence_of(sink, entry)
        assert evidence["error"]["type"] == "TimeoutError"
        assert evidence["response_sha256"] is None
        assert [s["name"] for s in receipt["subjects"]] == ["request"]

    def test_actor_is_api_key_digest(self, logger, sink):
        async def scenario():
            await sink.start()
            logger.log_pre_api_call("m", [], _kwargs("c-3"))
            await logger.async_log_success_event(
                _kwargs("c-3"), _response(), time.time(), time.time()
            )
            await sink.aclose()

        _run(scenario())
        (entry,) = list(sink.iterate())
        actor = entry["receipt"]["actor"]
        assert actor.startswith("apikey-sha256:")
        assert "sk-test-abc" not in actor

    def test_terminal_events_dedupe_across_twins(self, logger, sink):
        """Sync and async success twins firing for one call = ONE receipt."""

        async def scenario():
            await sink.start()
            kwargs = _kwargs("c-4")
            await logger.async_log_success_event(kwargs, _response(), time.time(), time.time())
            logger.log_success_event(kwargs, _response(), time.time(), time.time())  # twin
            await logger.async_log_success_event(kwargs, _response(), time.time(), time.time())
            await sink.aclose()

        _run(scenario())
        assert len(list(sink.iterate())) == 1


class TestAttemptsAndFallbacks:
    def test_retry_attempts_chain_under_one_call(self, logger, sink):
        """Two pre-hooks (retry loop re-entry) → attempt_index 1, 2; fallback flagged."""

        async def scenario():
            await sink.start()
            for model in ["gpt-3.5-turbo", "gpt-4o-mini"]:
                await logger.async_pre_call_deployment_hook(
                    _kwargs("c-5", model=model), "completion"
                )
                await logger.async_post_call_success_deployment_hook(
                    _kwargs("c-5", model=model), _response(model=model), "completion"
                )
            await logger.async_log_success_event(
                _kwargs("c-5", model="gpt-4o-mini"), _response(model="gpt-4o-mini"),
                time.time() - 0.5, time.time(),
            )
            await sink.aclose()

        _run(scenario())
        entries = list(sink.iterate())
        assert len(entries) == 3
        docs = [_evidence_of(sink, e) for e in entries]
        assert [d["attempt_index"] for d in docs] == [1, 2, 2]
        assert docs[0]["is_fallback"] is False
        assert docs[1]["is_fallback"] is True  # attempt 2+ = retry/fallback territory
        assert {d["model"] for d in docs} == {"gpt-3.5-turbo", "gpt-4o-mini"}
        # All receipts belong to the same logical call.
        assert {d["call_id"] for d in docs} == {"c-5"}
        assert verify_sink(sink.directory)["ok"]

    def test_per_attempt_failure_hook(self, logger, sink):
        async def scenario():
            await sink.start()
            await logger.async_pre_call_deployment_hook(_kwargs("c-6"), "completion")
            await logger.async_post_call_failure_deployment_hook(
                _kwargs("c-6"), ConnectionError("refused"), "completion"
            )
            await sink.aclose()

        _run(scenario())
        (entry,) = list(sink.iterate())
        doc = _evidence_of(sink, entry)
        assert entry["receipt"]["decision"]["outcome"] == "FAIL"
        assert doc["extra"]["event"] == "deployment_failure"
        assert doc["error"]["type"] == "ConnectionError"


class TestFailClosedBlocking:
    def test_full_queue_blocks_the_call(self, sink_dir):
        closed = make_policy(fail_mode=FailMode.FAIL_CLOSED, require_receipt_before_response=True)
        sink = EvidenceSink(sink_dir, policy=closed, maxsize=1)
        logger = SZLEvidenceLogger(sink=sink, policy=closed)

        async def scenario():
            # No flusher started: the queue stays full after the first receipt.
            await logger.async_log_success_event(
                _kwargs("b-1"), _response(), time.time(), time.time()
            )
            with pytest.raises(EvidenceBackpressure):
                await logger.async_log_success_event(
                    _kwargs("b-2"), _response(), time.time(), time.time()
                )

        _run(scenario())
        assert logger.stats()["blocked"] == 1

    def test_construction_failure_blocks(self, sink_dir, monkeypatch):
        closed = make_policy(fail_mode=FailMode.FAIL_CLOSED)
        sink = EvidenceSink(sink_dir, policy=closed)
        logger = SZLEvidenceLogger(sink=sink, policy=closed)

        def boom(**_kwargs):
            raise RuntimeError("signer unreachable")

        # Receipt construction breaks *after* the pre-call snapshot: exactly
        # the failure audit-grade mode exists to stop at the terminal hook.
        monkeypatch.setattr("szl_evidence_litellm.plugin.build_attempt_receipt", boom)

        async def scenario():
            await sink.start()
            kwargs = _kwargs("b-3")
            logger.log_pre_api_call("gpt-3.5-turbo", [], kwargs)  # snapshot fine
            with pytest.raises(ReceiptConstructionError, match="no receipt, no response"):
                await logger.async_log_success_event(
                    kwargs, _response(), time.time(), time.time()
                )
            await sink.aclose()

        _run(scenario())
        assert logger.stats()["errors"] >= 1
        assert logger.stats()["blocked"] >= 1

    def test_construction_failure_fail_open_counts_and_continues(self, sink_dir, monkeypatch):
        open_policy = make_policy(fail_mode=FailMode.FAIL_OPEN)
        sink = EvidenceSink(sink_dir, policy=open_policy)
        logger = SZLEvidenceLogger(sink=sink, policy=open_policy)

        def boom(**_kwargs):
            raise RuntimeError("signer unreachable")

        monkeypatch.setattr("szl_evidence_litellm.plugin.build_attempt_receipt", boom)

        async def scenario():
            await sink.start()
            # Never raises; the failure is loud in stats, invisible to the call.
            await logger.async_log_success_event(
                _kwargs("b-4"), _response(), time.time(), time.time()
            )
            await sink.aclose()

        _run(scenario())
        stats = logger.stats()
        assert stats["errors"] == 1
        assert stats["emitted"] == 0
        assert list(sink.iterate()) == []  # nothing fabricated, nothing half-written

    def test_fail_open_counts_but_never_blocks(self, sink_dir):
        open_policy = make_policy(fail_mode=FailMode.FAIL_OPEN)
        sink = EvidenceSink(sink_dir, policy=open_policy, maxsize=1)
        logger = SZLEvidenceLogger(sink=sink, policy=open_policy)

        async def scenario():
            for i in range(4):  # first lands, the rest drop — no exception anywhere
                await logger.async_log_success_event(
                    _kwargs(f"f-{i}"), _response(), time.time(), time.time()
                )
            return logger.stats()

        stats = _run(scenario())
        assert stats["sink"]["dropped_counter"] == 3
        assert stats["blocked"] == 0


class TestShapeDefaults:
    def test_sync_twin_without_loop_still_receipts(self, logger, sink):
        """LiteLLM sync callbacks can land on executor threads with no loop."""
        logger.log_success_event(_kwargs("s-1"), _response(), time.time(), time.time())
        sink._worker_stop.set()
        if sink._worker is not None:
            sink._worker.join(timeout=2)
        tq = sink._tqueue
        while tq is not None and not tq.empty():
            sink._persist_batch([tq.get_nowait()])
        assert len(list(sink.iterate())) == 1
        assert verify_sink(sink.directory)["ok"]

    def test_missing_call_id_is_synthesized(self, logger, sink):
        async def scenario():
            await sink.start()
            kwargs = {"model": "m", "messages": []}  # no litellm_call_id
            await logger.async_log_success_event(kwargs, _response(), time.time(), time.time())
            await sink.aclose()

        _run(scenario())
        (entry,) = list(sink.iterate())
        assert _evidence_of(sink, entry)["call_id"].startswith("external:")

    def test_latency_and_tokens_in_evidence(self, logger, sink):
        async def scenario():
            await sink.start()
            start = datetime.now(UTC)
            end = datetime.now(UTC)
            await logger.async_log_success_event(_kwargs("m-1"), _response(), start, end)
            await sink.aclose()

        _run(scenario())
        (entry,) = list(sink.iterate())
        doc = _evidence_of(sink, entry)
        assert doc["latency_ms"] is not None and doc["latency_ms"] >= 0
        assert doc["prompt_tokens"] == 2
        assert doc["completion_tokens"] == 2
        assert doc["finish_reason"] == "stop"

    def test_duck_type_surface_without_litellm_note(self):
        # Whatever the install state, the hook surface exists and matches.
        for hook in (
            "log_pre_api_call",
            "async_log_success_event",
            "async_log_failure_event",
            "async_pre_call_deployment_hook",
            "async_post_call_success_deployment_hook",
            "async_post_call_failure_deployment_hook",
            "log_success_event",
            "log_failure_event",
        ):
            assert callable(getattr(SZLEvidenceLogger, hook)), hook
        assert isinstance(LITELLM_AVAILABLE, bool)
