"""Shutdown must account for a batch already removed from the queue."""
from __future__ import annotations

import asyncio
import threading

import pytest
from conftest import make_pending
from szl_evidence_litellm import EvidenceSink, verify_sink


def _hold_write(sink):
    entered, release = threading.Event(), threading.Event()
    persist = sink._persist_batch

    def blocked(batch):
        entered.set()
        if not release.wait(5):
            raise TimeoutError("test did not release the write")
        return persist(batch)

    sink._persist_batch = blocked
    return entered, release


def test_aclose_waits_for_batch_already_dequeued(sink_dir, policy):
    async def run():
        sink = EvidenceSink(sink_dir, policy=policy)
        entered, release = _hold_write(sink)
        await sink.start()
        sink.enqueue(make_pending(policy))
        assert await asyncio.to_thread(entered.wait, 2)
        assert sink.stats()["queued"] == 0
        close = asyncio.create_task(sink.aclose())
        try:
            await asyncio.sleep(0.02)
            assert not close.done(), "shutdown returned before its in-flight write"
        finally:
            release.set()
            await asyncio.wait_for(close, timeout=2)
        assert len(list(sink.iterate())) == 1
        assert verify_sink(sink.directory)["ok"]

    asyncio.run(run())


def test_aclose_surfaces_completed_flusher_failure(sink_dir, policy):
    async def run():
        sink = EvidenceSink(sink_dir, policy=policy)

        def failed(_batch):
            raise OSError("synthetic disk failure")

        sink._persist_batch = failed
        await sink.start()
        sink.enqueue(make_pending(policy))
        with pytest.raises(OSError, match="synthetic disk failure"):
            await sink._flusher
        with pytest.raises(OSError, match="synthetic disk failure"):
            await sink.aclose()

    asyncio.run(run())


def test_aclose_timeout_keeps_write_awaitable_for_retry(sink_dir, policy):
    async def run():
        sink = EvidenceSink(sink_dir, policy=policy)
        entered, release = _hold_write(sink)
        await sink.start()
        sink.enqueue(make_pending(policy))
        assert await asyncio.to_thread(entered.wait, 2)
        try:
            with pytest.raises(TimeoutError):
                await sink.aclose(timeout_s=0.02)
        finally:
            release.set()
            await sink.aclose()
        assert len(list(sink.iterate())) == 1
        assert verify_sink(sink.directory)["ok"]

    asyncio.run(run())


def test_aclose_reports_thread_lane_still_writing(sink_dir, policy):
    async def run():
        sink = EvidenceSink(sink_dir, policy=policy)
        entered, release = _hold_write(sink)
        await asyncio.to_thread(sink.enqueue, make_pending(policy))
        assert await asyncio.to_thread(entered.wait, 2)
        try:
            with pytest.raises(TimeoutError, match="worker"):
                await sink.aclose(timeout_s=0.02)
        finally:
            release.set()
            await sink.aclose()
        assert len(list(sink.iterate())) == 1
        assert verify_sink(sink.directory)["ok"]

    asyncio.run(run())
