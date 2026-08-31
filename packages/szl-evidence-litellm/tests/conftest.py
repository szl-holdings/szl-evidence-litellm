"""Shared fixtures and helpers for the szl-evidence-litellm suite."""

from __future__ import annotations

import pytest
from szl_evidence_litellm import (
    EvidencePolicy,
    EvidenceSink,
    FailMode,
    PendingReceipt,
    build_attempt_receipt,
)


def make_policy(**overrides) -> EvidencePolicy:
    return EvidencePolicy(**overrides)


def make_pending(
    policy: EvidencePolicy,
    *,
    call_id: str = "call-1",
    attempt_index: int = 1,
    prompt_tokens: int = 7,
    actor: str = "anonymous",
) -> PendingReceipt:
    built = build_attempt_receipt(
        policy=policy,
        actor=actor,
        call_id=call_id,
        attempt_index=attempt_index,
        is_fallback=attempt_index > 1,
        model="gpt-3.5-turbo",
        provider="openai",
        request_doc={"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hi"}]},
        response_doc={"usage": {"prompt_tokens": prompt_tokens, "completion_tokens": 3}},
        outcome="PASS",
        rationale="test",
        latency_ms=12.5,
        prompt_tokens=prompt_tokens,
        completion_tokens=3,
        finish_reason="stop",
    )
    return PendingReceipt(
        receipt=built.receipt,
        evidence_doc=built.evidence_doc,
        evidence_uri=built.evidence_uri,
    )


@pytest.fixture()
def policy() -> EvidencePolicy:
    return make_policy()


@pytest.fixture()
def sink_dir(tmp_path):
    return tmp_path / "evidence"


@pytest.fixture()
def sink(sink_dir, policy) -> EvidenceSink:
    return EvidenceSink(sink_dir, policy=policy, flush_interval_s=0.05)


@pytest.fixture()
def closed_policy() -> EvidencePolicy:
    return make_policy(fail_mode=FailMode.FAIL_CLOSED)
