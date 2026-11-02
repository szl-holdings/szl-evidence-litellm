"""Independent regression: idempotent start must not erase a newer write."""
import asyncio
import threading

from conftest import make_pending
from szl_evidence_litellm import EvidencePolicy, EvidenceSink, verify_sink


def test_repeated_start_does_not_forget_next_batch(tmp_path):
    async def run():
        sink = EvidenceSink(tmp_path, policy=EvidencePolicy(), batch_size=1)
        persist = sink._persist_batch
        entered = [threading.Event(), threading.Event()]
        release = [threading.Event(), threading.Event()]
        calls = 0

        def writer(batch):
            nonlocal calls
            index = calls
            calls += 1
            entered[index].set()
            assert release[index].wait(3), "independent review did not release write"
            return persist(batch)

        sink._persist_batch = writer
        await sink.start()
        sink.enqueue(make_pending(sink.policy, call_id="review-first"))
        sink.enqueue(make_pending(sink.policy, call_id="review-second"))
        assert await asyncio.to_thread(entered[0].wait, 1)
        repeated_start = asyncio.create_task(sink.start())
        await asyncio.sleep(0.01)
        release[0].set()
        await asyncio.wait_for(repeated_start, timeout=1)
        assert await asyncio.to_thread(entered[1].wait, 1)
        close = asyncio.create_task(sink.aclose(timeout_s=0.05))
        try:
            await asyncio.sleep(0.1)
            if close.done() and not close.cancelled():
                assert isinstance(close.exception(), TimeoutError), (
                    "aclose returned success before the second write completed"
                )
        finally:
            release[1].set()
            try:
                await asyncio.wait_for(close, timeout=1)
            except TimeoutError:
                pass
            await sink.aclose()
        assert len(list(sink.iterate())) == 2
        assert verify_sink(tmp_path)["ok"]

    asyncio.run(run())
