"""Live LiteLLM integration: real callbacks through litellm's own machinery.

Uses LiteLLM's documented offline mock path (``mock_response=...``), so this
runs with no API keys and no network. Skipped cleanly when litellm is not
installed — the package never hard-depends on it.
"""

from __future__ import annotations

import asyncio

import pytest

litellm = pytest.importorskip(
    "litellm", reason="litellm not installed; duck-type path covered elsewhere"
)

from conftest import make_policy  # noqa: E402
from szl_evidence_litellm import EvidenceSink, SZLEvidenceLogger, verify_sink  # noqa: E402

# LiteLLM promotes litellm.callbacks into typed lists (_async_failure_callback
# et al.) at call time and DEDUPES CustomLogger instances by a class-name key —
# so a second SZLEvidenceLogger in the same process would silently inherit the
# first instance's registration. Tests get full isolation by snapshotting and
# resetting every typed list. (Real deployments run one logger per process.)
_CALLBACK_LIST_ATTRS = [
    "callbacks",
    "input_callback",
    "success_callback",
    "failure_callback",
    "service_callback",
    "_async_input_callback",
    "_async_success_callback",
    "_async_failure_callback",
]


def _clear_litellm_callbacks():
    for name in _CALLBACK_LIST_ATTRS:
        try:
            setattr(litellm, name, [])
        except AttributeError:
            pass


@pytest.fixture(autouse=True)
def _restore_callbacks():
    saved = {name: list(getattr(litellm, name, []) or []) for name in _CALLBACK_LIST_ATTRS}
    _clear_litellm_callbacks()
    try:
        yield
    finally:
        for name, values in saved.items():
            try:
                setattr(litellm, name, values)
            except AttributeError:
                pass


def _install(logger):
    _clear_litellm_callbacks()
    litellm.callbacks = [logger]


def test_acompletion_mock_response_produces_verifiable_receipt(sink_dir):
    """The money test: a real litellm call lands in the chain, and it verifies."""
    policy = make_policy()
    sink = EvidenceSink(sink_dir, policy=policy, flush_interval_s=0.05)
    logger = SZLEvidenceLogger(sink=sink, policy=policy)
    _install(logger)

    async def scenario():
        await sink.start()
        response = await litellm.acompletion(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "say hello"}],
            mock_response="hello",
        )
        await sink.aclose()
        return response

    response = asyncio.run(scenario())
    assert response is not None

    entries = list(sink.iterate())
    assert len(entries) >= 1, "no receipt landed in the sink"

    report = verify_sink(sink_dir)
    assert report["ok"], report["findings"]

    # Find the terminal receipt and check its evidence document.
    evidence_docs = []
    for entry in entries:
        uri = entry["receipt"]["evidence"][0]["uri"]
        import json

        evidence_docs.append(json.loads((sink_dir / uri).read_text()))
    assert any(doc["extra"]["event"] == "call_success" for doc in evidence_docs)
    terminal = next(doc for doc in evidence_docs if doc["extra"]["event"] == "call_success")
    assert terminal["mock"] is True  # honesty: the receipt knows it was mocked
    assert terminal["model"] == "gpt-3.5-turbo"
    assert terminal["latency_ms"] is not None

    # The request subject digest covers the canonical request params.
    receipt = next(
        e["receipt"] for e in entries if e["receipt"]["decision"]["outcome"] == "PASS"
    )
    subject_names = {s["name"] for s in receipt["subjects"]}
    assert "request" in subject_names


def test_acompletion_failure_produces_fail_receipt(sink_dir):
    policy = make_policy()
    sink = EvidenceSink(sink_dir, policy=policy, flush_interval_s=0.05)
    logger = SZLEvidenceLogger(sink=sink, policy=policy)
    _install(logger)

    async def scenario():
        await sink.start()
        with pytest.raises(Exception):  # noqa: B017 — litellm wraps provider errors
            await litellm.acompletion(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": "boom"}],
                mock_response=Exception("provider exploded"),
            )
        await sink.aclose()

    asyncio.run(scenario())

    entries = list(sink.iterate())
    assert len(entries) >= 1
    outcomes = {e["receipt"]["decision"]["outcome"] for e in entries}
    assert "FAIL" in outcomes
    assert verify_sink(sink_dir)["ok"]


def test_litellm_subclass_relationship():
    """When litellm IS installed, the logger must be a real CustomLogger."""
    from litellm.integrations.custom_logger import CustomLogger

    policy = make_policy()
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        sink = EvidenceSink(tmp, policy=policy)
        logger = SZLEvidenceLogger(sink=sink, policy=policy)
        assert isinstance(logger, CustomLogger)


def test_sink_shutdown_after_prior_event_loop(sink_dir):
    """Regression: aclose() stays bounded after a prior closed loop.

    Python 3.11 + litellm 1.98: an earlier ``asyncio.run`` leaves litellm's
    global logging worker bound to the closed loop; in that poisoned state the
    sink's flusher task can miss cancellation, and an unbounded ``await``
    would hang shutdown forever (observed: CI test (3.11) timing out at 15m).
    The bounded shutdown must either complete cleanly or raise TimeoutError —
    never hang — and whatever was persisted must verify as a valid chain.
    """
    import threading

    async def _bare_call():
        await litellm.acompletion(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "loop one"}],
            mock_response="one",
        )

    asyncio.run(_bare_call())  # loop 1: binds litellm's globals, then closes

    policy = make_policy()
    sink = EvidenceSink(sink_dir, policy=policy, flush_interval_s=0.05)
    logger = SZLEvidenceLogger(sink=sink, policy=policy)
    _install(logger)

    async def scenario():
        await sink.start()
        await litellm.acompletion(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "loop two"}],
            mock_response="two",
        )
        try:
            await sink.aclose()
        except TimeoutError:
            pass  # bounded loud failure is within contract; hanging is not

    done = threading.Event()
    failure: list[BaseException] = []

    def run():
        try:
            asyncio.run(scenario())
        except BaseException as exc:  # noqa: BLE001
            failure.append(exc)
        finally:
            done.set()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    assert done.wait(timeout=60), "sink aclose hung after a prior closed event loop"
    assert not failure, failure
    report = verify_sink(sink_dir)
    assert report["ok"], report["findings"]
