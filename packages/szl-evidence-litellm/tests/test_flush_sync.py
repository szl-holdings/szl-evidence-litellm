"""flush_sync(): the no-event-loop shutdown drain must persist or raise.

Regression for silent receipt loss. ``flush_sync()`` used to set the worker's
stop flag and join it, but ``EvidenceSink._worker_loop`` exits on that flag
without draining the thread-lane queue. ``flush_sync()`` then waited up to 5s
for a queue nothing was draining any more and returned normally, so receipts
still queued were lost at process exit with no error.
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest
from conftest import make_pending
from szl_evidence_litellm import EvidenceSink, SZLEvidenceLogger, verify_sink

N = 25


def _sink(sink_dir, policy, **overrides) -> EvidenceSink:
    options = {"batch_size": 4, "flush_interval_s": 0.05, **overrides}
    return EvidenceSink(sink_dir, policy=policy, **options)


def _enqueue_sync(sink, policy, n, prefix="sync"):
    for i in range(n):
        sink.enqueue(make_pending(policy, call_id=f"{prefix}-{i}"))


def _persisted(sink) -> int:
    return len(list(sink.iterate()))


def test_flush_sync_persists_receipts_the_worker_never_reached(sink_dir, policy):
    sink = _sink(sink_dir, policy)
    # The worker thread starts and exits at once, so only flush_sync can drain.
    sink._worker_loop = lambda: None  # type: ignore[method-assign]
    _enqueue_sync(sink, policy, N)
    assert sink.stats()["queued"] == N

    flushed = SZLEvidenceLogger(sink=sink, policy=policy).flush_sync()

    assert sink.stats()["queued"] == 0, "flush_sync returned with receipts still queued"
    assert _persisted(sink) == N
    assert flushed == N
    assert verify_sink(sink.directory)["ok"]


def test_flush_sync_drains_the_backlog_a_stopping_worker_leaves(sink_dir, policy):
    sink = _sink(sink_dir, policy)
    real_persist = sink._persist_batch
    worker_batches: list[int] = []
    worker_holding = threading.Event()

    def gated_persist(batch):
        if threading.current_thread() is sink._worker:
            # Hold the worker's first batch until shutdown has begun, so it is
            # guaranteed to exit on the stop flag with a backlog still queued.
            worker_holding.set()
            sink._worker_stop.wait(timeout=10)
            worker_batches.append(len(batch))
        return real_persist(batch)

    sink._persist_batch = gated_persist  # type: ignore[method-assign]
    _enqueue_sync(sink, policy, N)
    assert worker_holding.wait(timeout=10), "worker never picked up a batch"

    flushed = SZLEvidenceLogger(sink=sink, policy=policy).flush_sync()

    assert len(worker_batches) == 1 and 1 <= worker_batches[0] <= sink.batch_size
    assert sink.stats()["queued"] == 0, "flush_sync returned with receipts still queued"
    assert _persisted(sink) == N
    assert flushed == N - worker_batches[0]
    assert verify_sink(sink.directory)["ok"]


def test_flush_sync_covers_a_producer_that_restarts_the_worker_mid_drain(sink_dir, policy):
    """A producer enqueueing after the stop flag is set restarts the worker
    (``_enqueue_thread`` clears the flag when the worker is dead). The drain
    must persist those receipts too and stop the restarted worker."""
    sink = _sink(sink_dir, policy)
    real_persist = sink._persist_batch
    caller = threading.current_thread()
    late = 7
    seen: dict[str, threading.Thread | None] = {}

    def racing_persist(batch):
        if threading.current_thread() is caller and "late" not in seen:
            seen["before"] = sink._worker
            producer = threading.Thread(target=_enqueue_sync, args=(sink, policy, late, "late"))
            producer.start()
            producer.join(timeout=10)
            seen["late"] = sink._worker
        return real_persist(batch)

    sink._worker_loop = lambda: None  # type: ignore[method-assign]
    _enqueue_sync(sink, policy, N)
    # Only the late producer's worker is real; it races the drain.
    del sink._worker_loop
    sink._persist_batch = racing_persist  # type: ignore[method-assign]

    SZLEvidenceLogger(sink=sink, policy=policy).flush_sync()

    assert sink.stats()["queued"] == 0, "flush_sync returned with receipts still queued"
    restarted = seen.get("late")
    assert restarted is not None and restarted is not seen["before"], "race was not exercised"
    assert not restarted.is_alive()
    assert _persisted(sink) == N + late
    assert verify_sink(sink.directory)["ok"]


def test_flush_sync_raises_instead_of_returning_with_receipts_queued(sink_dir, policy):
    total = 10
    sink = _sink(sink_dir, policy, batch_size=1)
    sink._worker_loop = lambda: None  # type: ignore[method-assign]
    real_persist = sink._persist_batch

    def slow_persist(batch):
        time.sleep(0.1)
        return real_persist(batch)

    sink._persist_batch = slow_persist  # type: ignore[method-assign]
    _enqueue_sync(sink, policy, total)
    logger = SZLEvidenceLogger(sink=sink, policy=policy)

    with pytest.raises(TimeoutError, match="still queued"):
        logger.flush_sync(timeout_s=0.25)

    left = sink.stats()["queued"]
    assert left > 0
    # Nothing vanished: every receipt is either on disk or still queued.
    assert _persisted(sink) + left == total
    sink._persist_batch = real_persist  # type: ignore[method-assign]
    assert logger.flush_sync() == left
    assert _persisted(sink) == total
    assert verify_sink(sink.directory)["ok"]


def test_flush_sync_still_refuses_receipts_left_on_the_asyncio_lane(sink_dir, policy):
    sink = _sink(sink_dir, policy)

    async def strand_one():
        # Bypass enqueue() so no flusher exists to drain the asyncio queue.
        sink._require_queue().put_nowait(make_pending(policy, call_id="async-0"))

    asyncio.run(strand_one())

    with pytest.raises(RuntimeError, match="asyncio lane"):
        SZLEvidenceLogger(sink=sink, policy=policy).flush_sync()


def test_flush_sync_is_a_drain_point_not_a_permanent_close(sink_dir, policy):
    sink = _sink(sink_dir, policy)
    logger = SZLEvidenceLogger(sink=sink, policy=policy)
    logger.flush_sync()  # nothing ever queued: a no-op
    _enqueue_sync(sink, policy, 3, "first")
    logger.flush_sync()
    _enqueue_sync(sink, policy, 2, "second")  # a later enqueue restarts the worker
    logger.flush_sync()
    assert sink.stats()["queued"] == 0
    assert _persisted(sink) == 5
    assert verify_sink(sink.directory)["ok"]
