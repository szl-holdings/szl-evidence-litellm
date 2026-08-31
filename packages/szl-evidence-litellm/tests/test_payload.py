"""Payload-level tests: digests are binding, subjects/evidence conform."""

from __future__ import annotations

import json
from datetime import datetime

import pytest
from szl_evidence_litellm import (
    EvidencePolicy,
    actor_from_api_key,
    build_attempt_receipt,
    canonical_request_doc,
    content_digest,
)
from szl_evidence_litellm.payload import jsonable
from szl_receipts import jcs_canon_bytes, sha256_hex, verify_receipt


def _build(policy: EvidencePolicy, **overrides):
    kwargs = {
        "policy": policy,
        "actor": "anonymous",
        "call_id": "call-x",
        "attempt_index": 1,
        "is_fallback": False,
        "model": "gpt-3.5-turbo",
        "provider": "openai",
        "request_doc": {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hi"}]},
        "response_doc": {"usage": {"prompt_tokens": 7, "completion_tokens": 3}},
        "outcome": "PASS",
        "rationale": "unit test",
        "prompt_tokens": 7,
        "completion_tokens": 3,
        "finish_reason": "stop",
    }
    kwargs.update(overrides)
    return build_attempt_receipt(**kwargs)


class TestReceiptShape:
    def test_receipt_is_valid_governed_action(self, policy):
        built = _build(policy)
        assert verify_receipt(built.receipt) == []
        assert built.receipt["action"] == "llm.completion"
        assert built.receipt["decision"]["outcome"] == "PASS"

    def test_subjects_are_request_and_response_digests(self, policy):
        built = _build(policy)
        subjects = {s["name"]: s["sha256"] for s in built.receipt["subjects"]}
        assert set(subjects) == {"request", "response"}
        assert subjects["request"] == content_digest(
            {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hi"}]}
        )
        assert subjects["response"] == content_digest(
            {"usage": {"prompt_tokens": 7, "completion_tokens": 3}}
        )

    def test_failed_attempt_has_no_response_subject(self, policy):
        built = _build(policy, response_doc=None, outcome="FAIL",
                       error={"type": "Timeout", "message": "boom"})
        names = [s["name"] for s in built.receipt["subjects"]]
        assert names == ["request"]  # the absence is the claim: no response happened
        assert built.evidence_doc["response_sha256"] is None
        assert built.evidence_doc["error"]["type"] == "Timeout"

    def test_evidence_reference_is_content_addressed(self, policy):
        built = _build(policy)
        (ev,) = built.receipt["evidence"]
        assert ev["uri"] == f"evidence/{built.evidence_digest}.json"
        assert ev["sha256"] == sha256_hex(jcs_canon_bytes(jsonable(built.evidence_doc)))

    def test_policy_block_is_digested(self, policy):
        built = _build(policy)
        assert built.receipt["policy"]["id"] == policy.name
        assert built.receipt["policy"]["version"] == policy.version
        assert built.receipt["policy"]["digest_sha256"] == policy.digest_sha256()


class TestDigestSensitivity:
    """The point of the exercise: any field-level tamper changes the digest."""

    def test_token_count_tamper_changes_evidence_digest(self, policy):
        honest = _build(policy, prompt_tokens=7)
        tampered = _build(policy, prompt_tokens=8)  # one token different
        assert honest.evidence_digest != tampered.evidence_digest
        assert honest.receipt["receipt_id"] != tampered.receipt["receipt_id"]
        (ev_h,) = honest.receipt["evidence"]
        (ev_t,) = tampered.receipt["evidence"]
        assert ev_h["sha256"] != ev_t["sha256"]

    def test_request_content_tamper_changes_subject_digest(self, policy):
        req_a = canonical_request_doc("gpt-3.5-turbo", [{"role": "user", "content": "hi"}])
        req_b = canonical_request_doc("gpt-3.5-turbo", [{"role": "user", "content": "hi!"}])
        assert content_digest(req_a) != content_digest(req_b)

    def test_canonical_form_absorbs_key_order(self, policy):
        a = canonical_request_doc(
            "m", [{"role": "user", "content": "x"}], {"temperature": 0.1, "top_p": 1}
        )
        b = {
            "params": {"top_p": 1, "temperature": 0.1},
            "messages": [{"content": "x", "role": "user"}],
            "model": "m",
        }
        assert content_digest(a) == content_digest(b)

    def test_model_swap_changes_digest(self):
        assert content_digest(canonical_request_doc("gpt-3.5-turbo", [])) != content_digest(
            canonical_request_doc("gpt-4o-mini", [])
        )


class TestJsonable:
    def test_reduces_pydantic_style_objects(self):
        class FakeUsage:
            def model_dump(self, mode="python"):
                return {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}

        out = jsonable({"usage": FakeUsage()})
        assert out == {"usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}}

    def test_datetime_and_bytes(self):
        out = jsonable({"when": datetime(2026, 8, 31, 12, 0), "blob": b"abc"})
        assert out["when"] == "2026-08-31T12:00:00Z"
        assert out["blob"] == {"_bytes_sha256": sha256_hex(b"abc")}

    def test_non_finite_floats_become_null(self):
        assert jsonable({"x": float("nan"), "y": float("inf")}) == {"x": None, "y": None}

    def test_unknown_object_degrades_to_repr(self):
        class Opaque:
            __slots__ = ()

            def __repr__(self):
                return "<opaque>"

        assert jsonable(Opaque()) == "<opaque>"


class TestActorsAndBodies:
    def test_actor_from_api_key_is_a_digest(self):
        actor = actor_from_api_key("sk-secret-123")
        assert actor.startswith("apikey-sha256:")
        assert "sk-secret-123" not in actor
        assert actor != actor_from_api_key("sk-secret-124")

    def test_bodies_off_by_default(self, policy):
        built = _build(policy)
        assert "bodies" not in built.evidence_doc

    def test_capture_bodies_writes_files_and_references(self, policy, tmp_path):
        bodies = tmp_path / "bodies"
        built = _build(policy, bodies_dir=bodies)
        refs = built.evidence_doc["bodies"]
        assert set(refs) == {"request", "response"}
        for ref in refs.values():
            path = tmp_path / "bodies" / f"{ref['sha256']}.json"
            assert path.exists()
            assert ref["uri"] == f"bodies/{ref['sha256']}.json"
            assert sha256_hex(path.read_bytes()) == ref["sha256"]
            # The body file is real content — and the receipt still carries only digests.
            assert json.loads(path.read_text())

    def test_cost_usd_only_when_provided(self, policy):
        without = _build(policy)
        assert "cost_usd" not in without.evidence_doc
        with_cost = _build(policy, cost_usd=0.00042)
        assert with_cost.evidence_doc["cost_usd"] == pytest.approx(0.00042)
