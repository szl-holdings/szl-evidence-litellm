"""Sidecar URIs never grant access outside their content-addressed location."""

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import make_pending
from szl_evidence_litellm import EvidenceSink, verify_sink
from szl_receipts import append, compute_receipt_id


def write_chain(base, pending, uri=None):
    if uri is not None:
        pending.receipt["evidence"][0]["uri"] = uri
        pending.receipt["receipt_id"] = compute_receipt_id(pending.receipt)
    chain = []
    append(chain, pending.receipt)
    base.mkdir(exist_ok=True)
    (base / "receipts.jsonl").write_text(json.dumps(chain[0]) + "\n")


@pytest.mark.parametrize("location", ["parent", "absolute", "other-name", "other-directory"])
def test_relocated_sidecar_is_not_verified_or_returned(tmp_path, policy, monkeypatch, location):
    pending = make_pending(policy)
    base = tmp_path / "sink"
    digest = pending.receipt["evidence"][0]["sha256"]
    uris = {"parent": "../outside.json", "absolute": str(tmp_path / "absolute.json"),
            "other-name": "evidence/renamed.json", "other-directory": f"other/{digest}.json"}
    uri = uris[location]
    target = base / uri
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(pending.evidence_doc))
    write_chain(base, pending, uri)
    original = Path.read_text

    def guarded(path, *args, **kwargs):
        assert path != target, "a noncanonical sidecar must never be opened"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded)
    report = verify_sink(base)
    assert report["ok"] is False
    assert report["sidecars"]["invalid"] == 1
    lookup = EvidenceSink(base, read_only=True).receipt_by_id(pending.receipt["receipt_id"])
    assert lookup == (pending.receipt, None)


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_sidecar_symlinks_are_rejected_without_reading_target(tmp_path, policy, monkeypatch, kind):
    pending = make_pending(policy)
    base = tmp_path / "sink"
    write_chain(base, pending)
    target = base / pending.evidence_uri
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / target.name
    outside_file.write_text(json.dumps(pending.evidence_doc))
    try:
        if kind == "file":
            target.parent.mkdir()
            target.symlink_to(outside_file)
        else:
            target.parent.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    monkeypatch.setattr(Path, "read_text", lambda *_a, **_k: pytest.fail("symlink was read"))
    report = verify_sink(base)
    assert report["ok"] is False
    assert report["sidecars"]["invalid"] == 1


@pytest.mark.parametrize("malformed", [b"{", b"\xff", b'{"x":NaN}', b"[" * 2000])
def test_invalid_sidecar_content_returns_a_failed_report(sink, policy, malformed):
    pending = make_pending(policy)
    sink._persist_batch([pending])
    (sink.directory / pending.evidence_uri).write_bytes(malformed)
    report = verify_sink(sink.directory)
    assert report["ok"] is False
    assert report["sidecars"]["invalid"] == 1
    assert any(item["code"] == "evidence-invalid" for item in report["findings"])


def test_duplicate_keys_cannot_preserve_a_successful_digest(sink, policy):
    pending = make_pending(policy)
    sink._persist_batch([pending])
    target = sink.directory / pending.evidence_uri
    body = target.read_text()
    # Ordinary json.loads would discard the extra key and reconstruct the
    # original document and digest, incorrectly treating this as valid evidence.
    target.write_text('{"call_id":"shadowed",' + body[1:])
    report = verify_sink(sink.directory)
    assert report["ok"] is False
    assert report["sidecars"]["invalid"] == 1


def test_cli_returns_structured_failure_for_malformed_sidecar(sink, policy, capsys):
    from szl_evidence_litellm.cli import main

    pending = make_pending(policy)
    sink._persist_batch([pending])
    (sink.directory / pending.evidence_uri).write_bytes(b"{")
    assert main(["verify", "--sink", str(sink.directory), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["sidecars"]["invalid"] == 1


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_special_sidecar_is_rejected_before_open(sink, policy, monkeypatch, kind):
    pending = make_pending(policy)
    sink._persist_batch([pending])
    target = sink.directory / pending.evidence_uri
    target.unlink()
    if kind == "directory":
        target.mkdir()
    elif hasattr(os, "mkfifo"):
        os.mkfifo(target)
    else:
        pytest.skip("FIFO creation unavailable")
    monkeypatch.setattr(Path, "read_text", lambda *_a, **_k: pytest.fail("special file was read"))
    report = verify_sink(sink.directory)
    assert report["ok"] is False
    assert report["sidecars"]["invalid"] == 1


def test_writer_refuses_noncanonical_uri_before_creating_any_sidecar(sink, policy):
    pending = replace(make_pending(policy), evidence_uri="../outside.json")
    with pytest.raises(ValueError, match="content-addressed"):
        sink._persist_batch([pending])
    assert not (sink.directory.parent / "outside.json").exists()
    assert not sink.log_path.exists()


def test_writer_refuses_existing_symlink_before_committing_ledger(sink, policy, tmp_path):
    pending = make_pending(policy)
    target = sink.directory / pending.evidence_uri
    target.parent.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("original")
    try:
        target.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="regular file"):
        sink._persist_batch([pending])
    assert outside.read_text() == "original"
    assert not sink.log_path.exists()
