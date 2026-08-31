"""Outcome doctrine tests: UNKNOWN is never passing, never promotable."""

import pytest
from szl_receipts.outcome import Outcome, is_passing, parse_outcome, promotion_gate


class TestVocabulary:
    def test_vocabulary_is_exactly_five(self):
        assert {m.value for m in Outcome} == {"PASS", "WARN", "FAIL", "BLOCKED", "UNKNOWN"}

    def test_enum_members_are_strings_for_json(self):
        assert Outcome.PASS == "PASS"  # noqa: S105 — a label, not a credential
        assert isinstance(Outcome.WARN, str)

    def test_parse_accepts_enum_value_and_name(self):
        assert parse_outcome(Outcome.PASS) is Outcome.PASS
        assert parse_outcome("PASS") is Outcome.PASS
        assert parse_outcome(Outcome["BLOCKED"]) is Outcome.BLOCKED

    def test_parse_rejects_outside_vocabulary(self):
        with pytest.raises(ValueError, match="not a valid outcome"):
            parse_outcome("GREEN")
        with pytest.raises(ValueError, match="not a valid outcome"):
            parse_outcome("pass")  # case-sensitive: lowercase drift is drift
        with pytest.raises(TypeError):
            parse_outcome(None)


class TestIsPassing:
    def test_only_pass_is_passing(self):
        assert is_passing(Outcome.PASS) is True
        for failing in (Outcome.WARN, Outcome.FAIL, Outcome.BLOCKED, Outcome.UNKNOWN):
            assert is_passing(failing) is False

    def test_unknown_is_never_passing(self):
        # The doctrine rule, named in the test so a refactor that weakens it
        # fails with an honest message.
        assert is_passing(Outcome.UNKNOWN) is False
        assert is_passing("UNKNOWN") is False


class TestPromotionGate:
    def test_pass_promotes(self):
        allowed, reason = promotion_gate(Outcome.PASS)
        assert allowed is True
        assert "PASS" in reason

    def test_warn_needs_explicit_override(self):
        allowed, reason = promotion_gate(Outcome.WARN)
        assert allowed is False
        assert "override" in reason
        allowed, reason = promotion_gate(Outcome.WARN, allow_warn=True)
        assert allowed is True

    def test_fail_and_blocked_never_promote(self):
        for outcome in (Outcome.FAIL, Outcome.BLOCKED):
            allowed, _ = promotion_gate(outcome)
            assert allowed is False
            allowed, _ = promotion_gate(outcome, allow_warn=True)
            assert allowed is False

    def test_unknown_never_promotes_even_with_override(self):
        allowed, reason = promotion_gate(Outcome.UNKNOWN)
        assert allowed is False
        assert "UNKNOWN" in reason
        allowed, _ = promotion_gate(Outcome.UNKNOWN, allow_warn=True)
        assert allowed is False
