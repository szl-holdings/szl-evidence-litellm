"""The estate's outcome vocabulary and the gates that consume it.

Doctrine rule 3: **UNKNOWN is never passing.** A governed action either
produced a verdict or it didn't; "we don't know" is informationally *worse*
than "it failed", because failure at least tells you where to look. Code that
treats "no verdict" as "passed" is how silent corruption ships. Centralizing
``is_passing`` and the promotion gate here — rather than scattering
``outcome == "PASS"`` checks across the codebase — means the rule has exactly
one definition and one place to audit.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["Outcome", "is_passing", "parse_outcome", "promotion_gate"]


class Outcome(StrEnum):
    """Closed outcome vocabulary for GovernedAction receipts.

    Closed deliberately: a free-text status field drifts ("ok", "green",
    "mostly fine") until nothing can be gated on it. StrEnum keeps every
    receipt plain JSON (values serialize as their text).
    """

    PASS = "PASS"  # noqa: S105 — a governance label, not a credential
    WARN = "WARN"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


def parse_outcome(value: Outcome | str) -> Outcome:
    """Coerce a string/Outcome into the enum; KeyError-style typo protection.

    Accepts the enum itself, its value ("PASS"), or its name (also "PASS" —
    values equal names, kept separate in case values ever diverge). Raises
    ValueError for anything outside the vocabulary. TypeError on wrong types
    is considered programmer error and propagates naturally.
    """
    if isinstance(value, Outcome):
        return value
    if isinstance(value, str):
        try:
            return Outcome(value)
        except ValueError:
            try:
                return Outcome[value]
            except KeyError:
                pass
        raise ValueError(
            f"{value!r} is not a valid outcome; expected one of "
            + ", ".join(member.value for member in Outcome)
        ) from None
    raise TypeError(f"outcome must be Outcome or str, got {type(value).__name__}")


def is_passing(outcome: Outcome | str) -> bool:
    """True only for a definite PASS. UNKNOWN is never passing.

    WARN is a recorded concern, not a pass; FAIL and BLOCKED are obvious
    refusals. The one-line body is the entire doctrine rule — anything more
    complicated would be a bug farm.
    """
    return parse_outcome(outcome) is Outcome.PASS


def promotion_gate(outcome: Outcome | str, allow_warn: bool = False) -> tuple[bool, str]:
    """Decide whether an outcome may promote an artifact, with a reason.

    Returns ``(allowed, rationale)`` so callers can log *why* promotion was
    refused — an unexplained gate is an operational dead end.

    Policy: PASS promotes. WARN promotes only with an explicit
    ``allow_warn=True`` override (the override is itself an auditable
    decision). FAIL, BLOCKED, and UNKNOWN never promote — UNKNOWN because we
    will not promote what we cannot characterize.
    """
    parsed = parse_outcome(outcome)
    if parsed is Outcome.PASS:
        return True, "PASS: promotion allowed"
    if parsed is Outcome.WARN:
        if allow_warn:
            return True, "WARN: promotion allowed by explicit allow_warn override"
        return False, "WARN: promotion requires an explicit allow_warn override"
    if parsed is Outcome.FAIL:
        return False, "FAIL: governed action failed; promotion refused"
    if parsed is Outcome.BLOCKED:
        return False, "BLOCKED: governed action is blocked; promotion refused"
    return False, "UNKNOWN: no verdict recorded; UNKNOWN is never promotable"
