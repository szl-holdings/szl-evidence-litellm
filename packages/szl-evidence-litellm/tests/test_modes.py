"""The fail-open / fail-closed matrix, pinned as executable truth."""

from __future__ import annotations

import pytest
from szl_evidence_litellm import EvidencePolicy, FailMode


class TestFailMode:
    def test_values(self):
        assert FailMode.FAIL_CLOSED.value == "fail_closed"
        assert FailMode.FAIL_OPEN.value == "fail_open"

    def test_parse(self):
        assert FailMode.parse("fail_closed") is FailMode.FAIL_CLOSED
        assert FailMode.parse("FAIL_OPEN") is FailMode.FAIL_OPEN
        assert FailMode.parse(None) is FailMode.FAIL_OPEN  # default: latency-grade
        assert FailMode.parse(FailMode.FAIL_CLOSED) is FailMode.FAIL_CLOSED

    def test_parse_rejects_garbage(self):
        with pytest.raises(ValueError, match="fail_mode"):
            FailMode.parse("fail_sideways")


class TestPolicyMatrix:
    """Every cell of the README's matrix must hold in code."""

    @pytest.mark.parametrize(
        ("fail_mode", "require", "blocks", "posture"),
        [
            (FailMode.FAIL_CLOSED, True, True, "audit-grade"),
            (FailMode.FAIL_CLOSED, False, True, "strict"),
            (FailMode.FAIL_OPEN, True, False, "degraded-require"),
            (FailMode.FAIL_OPEN, False, False, "latency-grade"),
        ],
    )
    def test_matrix(self, fail_mode, require, blocks, posture):
        policy = EvidencePolicy(fail_mode=fail_mode, require_receipt_before_response=require)
        assert policy.blocks_on_receipt_error() is blocks, posture

    def test_default_policy_is_fail_open_latency_grade(self):
        policy = EvidencePolicy()
        assert policy.fail_mode is FailMode.FAIL_OPEN
        assert policy.require_receipt_before_response is False
        assert policy.blocks_on_receipt_error() is False

    def test_policy_is_frozen(self):
        policy = EvidencePolicy()
        with pytest.raises(Exception):  # noqa: B017 — frozen dataclass raises FrozenInstanceError
            policy.fail_mode = FailMode.FAIL_CLOSED  # type: ignore[misc]


class TestPolicyIdentity:
    def test_receipt_policy_shape(self):
        policy = EvidencePolicy()
        rp = policy.receipt_policy()
        assert set(rp) == {"id", "version", "digest_sha256"}
        assert rp["id"] == "szl.evidence.litellm"
        assert len(rp["digest_sha256"]) == 64

    def test_digest_tracks_every_knob(self):
        base = EvidencePolicy()
        assert base.digest_sha256() == EvidencePolicy().digest_sha256()  # deterministic
        variants = [
            EvidencePolicy(name="other"),
            EvidencePolicy(version="2.0.0"),
            EvidencePolicy(fail_mode=FailMode.FAIL_CLOSED),
            EvidencePolicy(require_receipt_before_response=True),
        ]
        for variant in variants:
            assert variant.digest_sha256() != base.digest_sha256()


class TestFromEnv:
    def test_env_round_trip(self):
        env = {
            "SZL_FAIL_MODE": "fail_closed",
            "SZL_REQUIRE_RECEIPT": "1",
            "SZL_POLICY_NAME": "custom.policy",
            "SZL_POLICY_VERSION": "9.9",
        }
        policy = EvidencePolicy.from_env(env)
        assert policy.fail_mode is FailMode.FAIL_CLOSED
        assert policy.require_receipt_before_response is True
        assert policy.name == "custom.policy"
        assert policy.version == "9.9"

    def test_env_defaults(self):
        policy = EvidencePolicy.from_env({})
        assert policy.fail_mode is FailMode.FAIL_OPEN
        assert policy.require_receipt_before_response is False
