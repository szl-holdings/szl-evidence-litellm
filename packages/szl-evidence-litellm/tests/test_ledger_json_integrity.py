"""Ambiguous JSON must never be accepted or normalized into trusted history."""

import json

import pytest
from conftest import make_pending
from szl_evidence_litellm import EvidenceSink, verify_sink
from szl_evidence_litellm.sink import SinkBootError


def _ambiguous(line, location):
    if location == "sequence":
        return '{"seq":999,' + line[1:]
    if location == "same-value":
        return '{"seq":1,' + line[1:]
    if location == "actor":
        return line.replace('"actor":', '"actor":"shadowed","actor":', 1)
    if location == "escaped-actor":
        return line.replace('"actor":', r'"\u0061ctor":"shadowed","actor":', 1)
    if location == "outcome":
        return line.replace('"outcome":', '"outcome":"FAIL","outcome":', 1)
    if location == "evidence-uri":
        return line.replace('"uri":', '"uri":"outside.json","uri":', 1)
    raise AssertionError(location)


@pytest.mark.parametrize("location", [
    "sequence", "same-value", "actor", "escaped-actor", "outcome", "evidence-uri",
])
@pytest.mark.parametrize("operation", ["verify", "restart", "iterate", "append"])
def test_duplicate_ledger_keys_fail_before_accepting_or_rewriting_history(
    sink, policy, location, operation,
):
    pending = make_pending(policy)
    sink._persist_batch([pending])
    original = sink.log_path.read_text(encoding="utf-8")
    ambiguous = _ambiguous(original, location)
    assert ambiguous != original
    # A permissive decoder reconstructs the original object and all its
    # hashes, even when a first-key-wins consumer would see a different claim.
    assert json.loads(ambiguous) == json.loads(original)
    sink.log_path.write_text(ambiguous, encoding="utf-8")
    before = sink.log_path.read_bytes()
    checkpoint_before = sink.checkpoint_path.read_bytes()

    with pytest.raises(SinkBootError, match="duplicate.*JSON key"):
        if operation == "verify":
            verify_sink(sink.directory)
        elif operation == "restart":
            EvidenceSink(sink.directory, policy=policy)
        elif operation == "iterate":
            list(EvidenceSink(sink.directory, read_only=True).iterate())
        else:
            sink._persist_batch([make_pending(policy, call_id="next")])

    assert sink.log_path.read_bytes() == before
    assert sink.checkpoint_path.read_bytes() == checkpoint_before


def test_unambiguous_ledger_keeps_valid_verification_and_restart(sink, policy):
    sink._persist_batch([make_pending(policy)])
    before = sink.log_path.read_bytes()
    head = verify_sink(sink.directory)["head"]
    reopened = EvidenceSink(sink.directory, policy=policy)
    assert reopened.log_path.read_bytes() == before
    reopened._persist_batch([make_pending(policy, call_id="next")])
    entries = list(reopened.iterate())
    assert len(entries) == 2
    assert entries[1]["prev"] == head
    assert verify_sink(reopened.directory)["ok"]
