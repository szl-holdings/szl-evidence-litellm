"""GovernedAction/v1 receipt tests: construction, identity, verification."""

import copy
from datetime import UTC, datetime

import pytest
from szl_receipts.receipt import (
    GOVERNED_ACTION_V1,
    build_receipt,
    compute_receipt_id,
    verify_receipt,
)


class TestBuild:
    def test_build_produces_verifiable_receipt(self):
        receipt = build_receipt(
            actor="ci",
            action="build",
            policy={"id": "p", "version": "1", "digest_sha256": "b" * 64},
            outcome="PASS",
            rationale="all gates green",
            subjects=[{"name": "out.bin", "sha256": "c" * 64}],
            evidence=[{"uri": "s3://bucket/log", "sha256": "d" * 64}, {"uri": "s3://bucket/raw"}],
        )
        assert receipt["receipt_type"] == GOVERNED_ACTION_V1
        assert receipt["receipt_id"] == compute_receipt_id(receipt)
        assert verify_receipt(receipt) == []

    def test_receipt_id_is_field_order_invariant(self):
        kwargs = dict(
            actor="ci",
            action="build",
            policy={"id": "p", "version": "1", "digest_sha256": "b" * 64},
            outcome="PASS",
            rationale="r",
            created_at="2026-08-31T00:00:00Z",
        )
        first = build_receipt(**kwargs)
        shuffled = dict(reversed(list(first.items())))
        assert compute_receipt_id(shuffled) == first["receipt_id"]

    def test_created_at_defaults_to_now_utc(self):
        receipt = build_receipt(
            actor="a",
            action="b",
            policy={"id": "p", "version": "1", "digest_sha256": "b" * 64},
            outcome="PASS",
            rationale="r",
        )
        assert receipt["created_at"].endswith("Z")
        parsed = datetime.fromisoformat(receipt["created_at"].replace("Z", "+00:00"))
        assert parsed.tzinfo is not None

    def test_created_at_normalizes_to_utc_z(self):
        receipt = build_receipt(
            actor="a",
            action="b",
            policy={"id": "p", "version": "1", "digest_sha256": "b" * 64},
            outcome="PASS",
            rationale="r",
            created_at=datetime(2026, 8, 31, 9, 0, tzinfo=UTC),
        )
        assert receipt["created_at"] == "2026-08-31T09:00:00Z"

    def test_naive_created_at_rejected(self):
        with pytest.raises(ValueError, match="timezone"):
            build_receipt(
                actor="a",
                action="b",
                policy={"id": "p", "version": "1", "digest_sha256": "b" * 64},
                outcome="PASS",
                rationale="r",
                created_at=datetime(2026, 8, 31, 9, 0),  # naive — no tzinfo
            )

    def test_bad_outcome_rejected_at_build_time(self):
        with pytest.raises(ValueError, match="not a valid outcome"):
            build_receipt(
                actor="a",
                action="b",
                policy={"id": "p", "version": "1", "digest_sha256": "b" * 64},
                outcome="GREEN",
                rationale="r",
            )

    def test_bad_policy_digest_rejected(self):
        with pytest.raises(ValueError, match="digest_sha256"):
            build_receipt(
                actor="a",
                action="b",
                policy={"id": "p", "version": "1", "digest_sha256": "sha256:abc"},
                outcome="PASS",
                rationale="r",
            )


class TestVerify:
    def test_good_receipt_has_no_findings(self, make_receipt):
        assert verify_receipt(make_receipt()) == []

    def test_never_raises_on_bad_data(self):
        garbage = [
            {},
            {"receipt_type": 42},
            {"receipt_id": None},
            {"receipt_type": GOVERNED_ACTION_V1, "subjects": "not-a-list"},
            {"receipt_id": "z" * 64},
        ]
        for item in garbage:
            assert isinstance(verify_receipt(item), list)

    def test_non_dict_raises_typeerror(self):
        with pytest.raises(TypeError):
            verify_receipt("not a dict")
        with pytest.raises(TypeError):
            verify_receipt([1, 2, 3])

    def test_field_tamper_detected(self, make_receipt):
        receipt = make_receipt()
        tampered = copy.deepcopy(receipt)
        tampered["decision"]["outcome"] = "PASS"
        tampered["actor"] = "mallory"  # actual tamper
        findings = verify_receipt(tampered)
        assert any("receipt_id mismatch" in f for f in findings)

    def test_every_field_tamper_detected(self, make_receipt):
        base = make_receipt()
        mutations = [
            lambda r: r.update(actor="mallory"),
            lambda r: r.update(action="steal"),
            lambda r: r["decision"].update(rationale="lies"),
            lambda r: r["policy"].update(version="0.0.0"),
            lambda r: r.update(created_at="1999-01-01T00:00:00Z"),
        ]
        for mutate in mutations:
            tampered = copy.deepcopy(base)
            mutate(tampered)
            findings = verify_receipt(tampered)
            assert any("receipt_id mismatch" in f for f in findings)

    def test_outcome_downgrade_attack_detected(self, make_receipt):
        # Rewriting FAIL→PASS without recomputing the id must not pass.
        receipt = make_receipt(outcome="FAIL")
        tampered = copy.deepcopy(receipt)
        tampered["decision"]["outcome"] = "PASS"
        assert any("receipt_id mismatch" in f for f in verify_receipt(tampered))

    def test_invalid_outcome_flagged(self, make_receipt):
        receipt = make_receipt()
        receipt["decision"]["outcome"] = "GREEN"
        findings = verify_receipt(receipt)
        assert any("outside the vocabulary" in f for f in findings)

    def test_subject_without_digest_flagged(self, make_receipt):
        # A name without a digest is a claim without evidence; verify must
        # name it. (build_receipt would refuse, so we mutate post-build —
        # which is exactly the path verify exists to police.)
        receipt = make_receipt()
        receipt["subjects"] = [{"name": "x.bin"}]
        findings = verify_receipt(receipt)
        assert any("sha256" in f for f in findings)

    def test_unexpected_keys_flagged(self, make_receipt):
        receipt = make_receipt()
        receipt["admin_override"] = True
        findings = verify_receipt(receipt)
        assert any("unexpected key: admin_override" in f for f in findings)

    def test_unreal_calendar_date_flagged(self, make_receipt):
        receipt = make_receipt()
        receipt["created_at"] = "2026-13-40T25:61:61Z"
        findings = verify_receipt(receipt)
        assert any("not a real calendar moment" in f for f in findings)
