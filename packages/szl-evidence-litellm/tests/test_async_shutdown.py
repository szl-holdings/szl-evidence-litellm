"""Shutdown must account for a batch already removed from the queue."""
from __future__ import annotations

import asyncio
import threading

import pytest
from conftest import make_pending
from szl_evidence_litellm import EvidenceSink, SZLEvidenceLogger, verify_sink


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


def test_timed_out_write_can_finish_after_original_event_loop_closes(sink_dir, policy):
    sink = EvidenceSink(sink_dir, policy=policy)
    entered, release = _hold_write(sink)

    async def first_loop():
        await sink.start()
        sink.enqueue(make_pending(policy))
        assert await asyncio.to_thread(entered.wait, 2)
        with pytest.raises(TimeoutError):
            await sink.aclose(timeout_s=0.02)

    async def later_loop():
        close = asyncio.create_task(sink.aclose())
        try:
            await asyncio.sleep(0.02)
            assert not close.done(), "cross-loop close forgot the pending write"
        finally:
            release.set()
            await asyncio.wait_for(close, timeout=2)

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(first_loop())
    finally:
        loop.close()
    try:
        asyncio.run(later_loop())
    finally:
        release.set()
    assert len(list(sink.iterate())) == 1
    assert verify_sink(sink.directory)["ok"]


@pytest.mark.parametrize("after_commit", [False, True])
def test_thread_worker_failure_is_terminal_without_replaying_uncertain_batch(sink_dir, policy, after_commit):
    sink = EvidenceSink(sink_dir, policy=policy)
    persist = sink._persist_batch

    def failed(batch):
        if after_commit:
            persist(batch)
        raise OSError("synthetic persistence failure")

    sink._persist_batch = failed
    sink.enqueue(make_pending(policy))
    sink._worker.join(timeout=2)
    assert not sink._worker.is_alive()
    logger = SZLEvidenceLogger(sink=sink, policy=policy)
    for drain in (logger.flush_sync, sink.drain_thread_lane, lambda: asyncio.run(sink.aclose())):
        with pytest.raises(RuntimeError, match="commit outcome is unknown") as failure:
            drain()
        assert isinstance(failure.value.__cause__, OSError)
    with pytest.raises(RuntimeError, match="commit outcome is unknown"):
        sink.enqueue(make_pending(policy, call_id="after-failure"))
    assert sink.stats()["queued"] == 0
    assert sink.stats()["worker_failed"] is True
    assert sink.stats()["worker_failure_type"] == "OSError"
    assert len(list(sink.iterate())) == int(after_commit), "uncertain batch was replayed"


def test_cancelling_close_preserves_pending_write_for_later_close(sink_dir, policy):
    async def run():
        sink = EvidenceSink(sink_dir, policy=policy)
        entered, release = _hold_write(sink)
        await sink.start()
        sink.enqueue(make_pending(policy))
        assert await asyncio.to_thread(entered.wait, 2)
        close = asyncio.create_task(sink.aclose())
        await asyncio.sleep(0.01)
        close.cancel()
        try:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(close, timeout=2)
        finally:
            release.set()
            await sink.aclose()
        assert len(list(sink.iterate())) == 1
        assert verify_sink(sink.directory)["ok"]

    asyncio.run(run())


def test_flush_sync_refuses_dequeued_async_write_without_running_loop(sink_dir, policy):
    sink = EvidenceSink(sink_dir, policy=policy)
    entered, release = _hold_write(sink)

    async def begin():
        await sink.start()
        sink.enqueue(make_pending(policy))
        assert await asyncio.to_thread(entered.wait, 2)

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(begin())
        assert sink.stats()["queued"] == 0
        with pytest.raises(RuntimeError, match="asyncio lane"):
            SZLEvidenceLogger(sink=sink).flush_sync()
    finally:
        release.set()
        loop.run_until_complete(sink.aclose())
        loop.close()
    assert len(list(sink.iterate())) == 1
    assert verify_sink(sink.directory)["ok"]


def test_cancelled_application_can_drain_in_finally(sink_dir, policy):
    async def run():
        sink = EvidenceSink(sink_dir, policy=policy)
        entered, release = _hold_write(sink)
        cleanup_finished = []

        async def application():
            await sink.start()
            sink.enqueue(make_pending(policy))
            try:
                await asyncio.Event().wait()
            finally:
                await sink.aclose()
                cleanup_finished.append(True)

        task = asyncio.create_task(application())
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        try:
            await asyncio.sleep(0.03)
            assert not task.done(), "preexisting cancellation prevented graceful drain"
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=2)
            await sink.aclose()
        assert cleanup_finished == [True]
        assert len(list(sink.iterate())) == 1
        assert verify_sink(sink.directory)["ok"]

    asyncio.run(run())
