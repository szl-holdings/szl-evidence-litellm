"""The ledger is replaced crash-atomically: a failed batch never costs history.

Regression for whole-history loss. ``EvidenceSink._persist_batch`` used to
open ``receipts.jsonl`` with mode ``"w"`` (truncating it) and then write every
line. A crash, kill or IO error between the truncation and the completed
write left the ledger empty or torn, losing receipts that earlier batches had
already fsynced. The ledger is now written to a temp file, fsynced and renamed
over ``receipts.jsonl`` with ``os.replace``.
"""

from __future__ import annotations

import json
import os

import pytest
import szl_evidence_litellm.sink as sink_module
from conftest import make_pending
from szl_evidence_litellm import EvidenceSink, verify_sink
from szl_receipts import append as chain_append


def _sink(sink_dir, policy) -> EvidenceSink:
    return EvidenceSink(sink_dir, policy=policy, flush_interval_s=0.05)


def _batch(policy, prefix, n=3):
    return [make_pending(policy, call_id=f"{prefix}-{i}") for i in range(n)]


def _leftovers(sink) -> list[str]:
    return sorted(p.name for p in sink.directory.iterdir() if p.name.endswith(".tmp"))


class _TornWriter:
    """A file whose write puts half the data down, then fails like a crash."""

    def __init__(self, fh):
        self._fh = fh

    def write(self, data):
        self._fh.write(data[: len(data) // 2])
        self._fh.flush()
        raise OSError("simulated crash mid-write")

    def __getattr__(self, name):
        return getattr(self._fh, name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._fh.close()
        return False


def _tear_ledger_writes(monkeypatch):
    real_open = open

    def fake_open(file, mode="r", *args, **kwargs):
        fh = real_open(file, mode, *args, **kwargs)
        if any(flag in mode for flag in "wxa") and "receipts.jsonl" in os.fspath(file):
            return _TornWriter(fh)
        return fh

    monkeypatch.setattr(sink_module, "open", fake_open, raising=False)


def test_crash_mid_write_keeps_the_previous_ledger(sink_dir, policy, monkeypatch):
    sink = _sink(sink_dir, policy)
    sink._persist_batch(_batch(policy, "first"))
    before = sink.log_path.read_bytes()
    checkpoint_before = sink.checkpoint_path.read_bytes()

    _tear_ledger_writes(monkeypatch)
    with pytest.raises(OSError, match="simulated crash"):
        sink._persist_batch(_batch(policy, "second"))
    monkeypatch.undo()

    assert sink.log_path.read_bytes() == before, "a failed batch damaged committed history"
    assert sink.checkpoint_path.read_bytes() == checkpoint_before
    assert verify_sink(sink.directory)["ok"]
    assert _leftovers(sink) == []
    # The sink still boots and extends the intact chain.
    reopened = _sink(sink_dir, policy)
    reopened._persist_batch(_batch(policy, "third"))
    assert len(list(reopened.iterate())) == 6
    assert verify_sink(sink.directory)["ok"]


def test_failed_replace_keeps_the_previous_ledger(sink_dir, policy, monkeypatch):
    sink = _sink(sink_dir, policy)
    sink._persist_batch(_batch(policy, "first"))
    before = sink.log_path.read_bytes()

    def boom(src, dst):
        raise OSError("simulated crash at rename")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="simulated crash at rename"):
        sink._persist_batch(_batch(policy, "second"))
    monkeypatch.undo()

    assert sink.log_path.read_bytes() == before
    assert verify_sink(sink.directory)["ok"]
    assert _leftovers(sink) == []


def test_normal_path_bytes_match_the_legacy_writer(sink_dir, policy, tmp_path):
    sink = _sink(sink_dir, policy)
    first, second = _batch(policy, "a"), _batch(policy, "b", n=2)
    sink._persist_batch(first)
    sink._persist_batch(second)

    # The pre-fix writer: chain in memory, then open("w") and write every line.
    entries: list = []
    for pending in first + second:
        chain_append(entries, pending.receipt)
    legacy = tmp_path / "legacy.jsonl"
    with open(legacy, "w", encoding="utf-8") as fh:
        fh.write(
            "".join(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n" for e in entries)
        )

    assert sink.log_path.read_bytes() == legacy.read_bytes()
    checkpoint = json.loads(sink.checkpoint_path.read_text(encoding="utf-8"))
    assert checkpoint["entries"] == 5 and checkpoint["seq"] == 5
    assert checkpoint["entry_digest"] == entries[-1]["entry_digest"]
    assert _leftovers(sink) == []
    assert verify_sink(sink.directory)["ok"]


def test_windows_sharing_violation_is_retried(sink_dir, policy, monkeypatch):
    sink = _sink(sink_dir, policy)
    real_replace = os.replace
    calls = {"n": 0}

    def flaky(src, dst):
        if os.fspath(dst).endswith("receipts.jsonl") and calls["n"] < 2:
            calls["n"] += 1
            raise PermissionError("simulated sharing violation")
        return real_replace(src, dst)

    monkeypatch.setattr(sink_module, "_REPLACE_RETRIES", 3)
    monkeypatch.setattr(sink_module, "_REPLACE_RETRY_DELAY_S", 0.0)
    monkeypatch.setattr(os, "replace", flaky)
    sink._persist_batch(_batch(policy, "retry"))
    monkeypatch.undo()

    assert calls["n"] == 2
    assert len(list(sink.iterate())) == 3
    assert _leftovers(sink) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_replace_keeps_the_ledger_mode(sink_dir, policy):
    sink = _sink(sink_dir, policy)
    sink._persist_batch(_batch(policy, "first"))
    os.chmod(sink.log_path, 0o600)
    sink._persist_batch(_batch(policy, "second"))
    assert (sink.log_path.stat().st_mode & 0o777) == 0o600
