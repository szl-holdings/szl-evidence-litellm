"""End-to-end chain integration: build through the plugin, verify, then attack.

These tests exercise the promise on the tin: a chain produced by the plugin
+ sink verifies clean, and a hand-edited middle entry is caught by
``szl_receipts.verify_chain`` with named findings.
"""

from __future__ import annotations

import asyncio
import json

from conftest import make_policy
from szl_evidence_litellm import (
    EvidenceSink as EvidenceSinkCls,
)
from szl_evidence_litellm import SZLEvidenceLogger, verify_sink
from szl_evidence_litellm.sink import CHAIN_LOG_FILE
from szl_receipts import verify_chain


def _run(coro):
    return asyncio.run(coro)


def _produce_chain(sink, policy, n_calls: int = 6) -> SZLEvidenceLogger:
    logger = SZLEvidenceLogger(sink=sink, policy=policy)

    async def scenario():
        await sink.start()
        for i in range(n_calls):
            kwargs = {
                "litellm_call_id": f"chain-{i}",
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": f"question {i}"}],
                "litellm_params": {"api_key": f"sk-test-{i}"},
            }
            logger.log_pre_api_call("gpt-3.5-turbo", kwargs["messages"], kwargs)
            if i % 2 == 0:
                await logger.async_log_success_event(
                    kwargs,
                    {
                        "id": f"chatcmpl-{i}",
                        "model": "gpt-3.5-turbo",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": f"answer {i}"},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {
                            "prompt_tokens": 3 + i,
                            "completion_tokens": 4,
                            "total_tokens": 7 + i,
                        },
                    },
                    0.0,
                    0.1 + i * 0.01,
                )
            else:
                await logger.async_log_failure_event(kwargs, TimeoutError(f"boom {i}"), 0.0, 0.05)
        await sink.aclose()

    _run(scenario())
    return logger


class TestChainEndToEnd:
    def test_produced_chain_verifies(self, sink, policy):
        _produce_chain(sink, policy)
        report = verify_sink(sink.directory)
        assert report["ok"], report["findings"]
        assert report["length"] == 6
        assert report["head"]
        assert report["sidecars"]["checked"] == 6

    def test_outcomes_mix_pass_and_fail(self, sink, policy):
        _produce_chain(sink, policy)
        outcomes = [e["receipt"]["decision"]["outcome"] for e in sink.iterate()]
        assert outcomes == ["PASS", "FAIL"] * 3

    def test_hand_edited_middle_entry_is_caught(self, sink, policy):
        _produce_chain(sink, policy)
        log = sink.directory / CHAIN_LOG_FILE
        lines = log.read_text().splitlines()
        middle = json.loads(lines[2])
        # The classic insider move: rewrite history to make a FAIL look PASSed.
        middle["receipt"]["decision"]["outcome"] = "PASS"
        middle["receipt"]["decision"]["rationale"] = "totally fine, trust me"
        lines[2] = json.dumps(middle)
        log.write_text("\n".join(lines) + "\n")

        entries = [json.loads(line) for line in log.read_text().splitlines()]
        report = verify_chain(entries)
        assert report.ok is False
        codes = {f["code"] for f in report.findings}
        # Content tamper is caught at the edited entry: its declared digest no
        # longer matches its rewritten content. (The prev-link of the NEXT
        # entry still matches the edited entry's declared digest string, which
        # is exactly why the digest check is the primary tripwire.)
        assert "digest-mismatch" in codes
        seqs = {f.get("seq") for f in report.findings}
        assert 3 in seqs

    def test_middle_entry_receipt_id_tamper_is_caught(self, sink, policy):
        _produce_chain(sink, policy)
        log = sink.directory / CHAIN_LOG_FILE
        lines = log.read_text().splitlines()
        middle = json.loads(lines[1])
        middle["receipt"]["actor"] = "mallory"  # receipt_id no longer matches body
        lines[1] = json.dumps(middle)
        log.write_text("\n".join(lines) + "\n")

        report = verify_sink(sink.directory)
        assert report["ok"] is False
        codes = {f["code"] for f in report["findings"]}
        assert "digest-mismatch" in codes

    def test_tail_truncation_detected_against_anchor(self, sink, policy):
        _produce_chain(sink, policy)
        full = [
            json.loads(line)
            for line in (sink.directory / CHAIN_LOG_FILE).read_text().splitlines()
        ]
        head_anchor = full[-1]["entry_digest"]  # the out-of-band anchor
        truncated = full[:-2]
        report = verify_chain(truncated, expected_entries=6, expected_head=head_anchor)
        assert report.ok is False
        codes = {f["code"] for f in report.findings}
        assert "truncated" in codes
        assert "head-mismatch" in codes

    def test_reorder_is_caught(self, sink, policy):
        _produce_chain(sink, policy)
        log = sink.directory / CHAIN_LOG_FILE
        lines = log.read_text().splitlines()
        lines[1], lines[3] = lines[3], lines[1]  # swap two entries
        log.write_text("\n".join(lines) + "\n")
        report = verify_sink(sink.directory)
        assert report["ok"] is False
        codes = {f["code"] for f in report["findings"]}
        assert codes & {"reorder", "broken-prev-link"}


class TestRestartContinuation:
    def test_new_sink_continues_the_chain(self, sink_dir, policy):
        sink_a = EvidenceSinkCls(sink_dir, policy=policy)
        _produce_chain(sink_a, policy, n_calls=2)
        head = verify_sink(sink_dir)["head"]

        # Process restarts: a fresh sink instance resumes on the same tail.
        sink_b = EvidenceSinkCls(sink_dir, policy=policy)
        _produce_chain(sink_b, policy, n_calls=3)
        entries = list(sink_b.iterate())
        assert len(entries) == 5
        assert entries[1]["entry_digest"] == head
        assert entries[2]["prev"] == head
        assert verify_sink(sink_dir)["ok"]


def test_policy_changing_mid_stream_is_visible(policy):
    """Receipts pin their policy digest; a posture change is auditable."""
    closed = make_policy(fail_mode="fail_closed", require_receipt_before_response=True)
    assert policy.digest_sha256() != closed.digest_sha256()
