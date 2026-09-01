"""Sink tests: batching, backpressure, drop signaling, checkpointing, boot gate."""

from __future__ import annotations

import asyncio
import json

import pytest
from conftest import make_pending, make_policy
from szl_evidence_litellm import (
    EvidenceBackpressure,
    EvidenceSink,
    FailMode,
    SinkBootError,
    verify_sink,
)
from szl_evidence_litellm.sink import CHAIN_HEAD_FILE, CHAIN_LOG_FILE, DROPS_LOG_FILE


def _run(coro):
    return asyncio.run(coro)


class TestBatchingAndFlush:
    def test_batches_flush_to_chained_jsonl(self, sink, policy):
        async def scenario():
            await sink.start()
            for i in range(5):
                sink.enqueue(make_pending(policy, call_id=f"call-{i}"))
            await sink.aclose()

        _run(scenario())
        entries = list(sink.iterate())
        assert len(entries) == 5
        assert entries[0]["seq"] == 1 and entries[0]["prev"] is None
        for earlier, later in zip(entries, entries[1:], strict=False):
            assert later["seq"] == earlier["seq"] + 1
            assert later["prev"] == earlier["entry_digest"]
        report = verify_sink(sink.directory)
        assert report["ok"], report["findings"]
        assert report["sidecars"] == {"checked": 5, "missing": 0, "mismatched": 0}

    def test_evidence_sidecars_materialize(self, sink, policy):
        pending = make_pending(policy)

        async def scenario():
            await sink.start()
            sink.enqueue(pending)
            await sink.aclose()

        _run(scenario())
        sidecar = sink.directory / pending.evidence_uri
        assert sidecar.exists()
        doc = json.loads(sidecar.read_text())
        assert doc["call_id"] == "call-1"
        assert doc["prompt_tokens"] == 7

    def test_flush_interval_persists_without_close(self, sink, policy):
        async def scenario():
            await sink.start()
            sink.enqueue(make_pending(policy))
            await asyncio.sleep(0.4)  # > flush_interval_s of 0.05
            assert (sink.directory / CHAIN_LOG_FILE).exists()
            await sink.aclose()

        _run(scenario())

    def test_checkpoint_file_tracks_head(self, sink, policy):
        async def scenario():
            await sink.start()
            for i in range(3):
                sink.enqueue(make_pending(policy, call_id=f"c{i}"))
            await sink.aclose()

        _run(scenario())
        checkpoint = json.loads((sink.directory / CHAIN_HEAD_FILE).read_text())
        entries = list(sink.iterate())
        assert checkpoint["entries"] == 3
        assert checkpoint["entry_digest"] == entries[-1]["entry_digest"]
        assert checkpoint["seq"] == entries[-1]["seq"]


class TestBackpressure:
    """Fill the queue; both fail modes must behave exactly as specified."""

    def test_fail_closed_raises_backpressure(self, sink_dir, closed_policy):
        closed = EvidenceSink(sink_dir, policy=closed_policy, maxsize=4)
        # No flusher started: the queue stays full — that IS the stall scenario.
        async def scenario():
            for i in range(4):
                closed.enqueue(make_pending(closed_policy, call_id=f"ok-{i}"))
            with pytest.raises(EvidenceBackpressure):
                closed.enqueue(make_pending(closed_policy, call_id="one-too-many"))

        _run(scenario())
        assert closed.stats()["dropped_counter"] == 0  # fail-closed refuses; it never drops

    def test_fail_open_drops_loudly(self, sink_dir):
        open_policy = make_policy(fail_mode=FailMode.FAIL_OPEN)
        sink = EvidenceSink(sink_dir, policy=open_policy, maxsize=3)

        async def scenario():
            for i in range(3):
                sink.enqueue(make_pending(open_policy, call_id=f"ok-{i}"))
            for i in range(5):  # five drops, one logical streak
                sink.enqueue(make_pending(open_policy, call_id=f"dropped-{i}"))
            return sink.stats()

        stats = _run(scenario())
        assert stats["dropped_counter"] == 5
        # The loud signal: one drop-streak line, naming the event.
        drops = (sink_dir / DROPS_LOG_FILE).read_text().strip().splitlines()
        assert len(drops) == 1
        record = json.loads(drops[0])
        assert record["event"] == "RECEIPT_DROPPED_FAIL_OPEN"

    def test_drain_after_stall_recovers(self, sink_dir, closed_policy):
        sink = EvidenceSink(sink_dir, policy=closed_policy, maxsize=2)

        async def scenario():
            await sink.start()
            for i in range(2):
                sink.enqueue(make_pending(closed_policy, call_id=f"a-{i}"))
            await asyncio.sleep(0.3)  # flusher drains
            sink.enqueue(make_pending(closed_policy, call_id="a-2"))
            sink.enqueue(make_pending(closed_policy, call_id="a-3"))
            async with asyncio.timeout(2.0):
                await sink.aclose()

        _run(scenario())
        assert len(list(sink.iterate())) == 4
        assert verify_sink(sink.directory)["ok"]


class TestThreadLane:
    """enqueue with no running loop (LiteLLM sync callbacks on executor threads)."""

    def test_thread_lane_persists_and_chains(self, sink, policy):
        for i in range(3):
            sink.enqueue(make_pending(policy, call_id=f"sync-{i}"))
        sink._worker_stop.set()
        worker = sink._worker
        if worker is not None:
            worker.join(timeout=2)
        # Drain anything the worker didn't get to.
        tq = sink._tqueue
        while tq is not None and not tq.empty():
            sink._persist_batch([tq.get_nowait()])
        assert len(list(sink.iterate())) == 3
        assert verify_sink(sink.directory)["ok"]

    def test_thread_lane_fail_closed_backpressure(self, sink_dir, closed_policy):
        sink = EvidenceSink(sink_dir, policy=closed_policy, maxsize=2)
        # Monkeypatch worker startup so the queue stays full deterministically.
        sink._worker_loop = lambda: None  # type: ignore[method-assign]
        sink.enqueue(make_pending(closed_policy, call_id="t-0"))
        sink.enqueue(make_pending(closed_policy, call_id="t-1"))
        with pytest.raises(EvidenceBackpressure):
            sink.enqueue(make_pending(closed_policy, call_id="t-2"))


class TestBootGateAndReads:
    def test_reopening_a_healthy_sink_is_fine(self, sink, policy):
        async def scenario():
            await sink.start()
            sink.enqueue(make_pending(policy))
            await sink.aclose()

        _run(scenario())
        again = EvidenceSink(sink.directory, policy=policy)  # boots clean
        assert again.stats()["entries"] == 1

    def test_broken_chain_refuses_to_boot(self, sink, policy):
        async def scenario():
            await sink.start()
            sink.enqueue(make_pending(policy))
            sink.enqueue(make_pending(policy, call_id="call-2"))
            await sink.aclose()

        _run(scenario())
        # Hand-edit the middle: corrupt entry 1's receipt actor.
        lines = (sink.directory / CHAIN_LOG_FILE).read_text().splitlines()
        entry = json.loads(lines[0])
        entry["receipt"]["actor"] = "mallory"
        lines[0] = json.dumps(entry)
        (sink.directory / CHAIN_LOG_FILE).write_text("\n".join(lines) + "\n")

        with pytest.raises(SinkBootError, match="refusing to extend a broken chain"):
            EvidenceSink(sink.directory, policy=policy)

    def test_receipt_lookup(self, sink, policy):
        pending = make_pending(policy)

        async def scenario():
            await sink.start()
            sink.enqueue(pending)
            await sink.aclose()

        _run(scenario())
        found = sink.receipt_by_id(pending.receipt["receipt_id"])
        assert found is not None
        receipt, evidence_doc = found
        assert receipt["receipt_id"] == pending.receipt["receipt_id"]
        assert evidence_doc["call_id"] == "call-1"
        assert sink.receipt_by_id("0" * 64) is None

    def test_read_only_stats_and_verify_sink_on_empty_dir(self, sink_dir):
        ro = EvidenceSink(sink_dir, read_only=True)
        assert ro.stats()["entries"] == 0
        assert ro.stats()["read_only"] is True
        assert verify_sink(sink_dir)["ok"]  # an empty chain is a valid chain

    def test_verify_sink_flags_missing_sidecar(self, sink, policy):
        pending = make_pending(policy)

        async def scenario():
            await sink.start()
            sink.enqueue(pending)
            await sink.aclose()

        _run(scenario())
        (sink.directory / pending.evidence_uri).unlink()  # sidecar deleted post-hoc
        report = verify_sink(sink.directory)
        assert report["ok"] is False
        assert report["sidecars"]["missing"] == 1
        assert any(f["code"] == "evidence-missing" for f in report["findings"])
