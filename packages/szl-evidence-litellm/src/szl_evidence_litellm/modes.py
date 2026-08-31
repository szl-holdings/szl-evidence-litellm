"""Fail-open vs fail-closed: the two honest postures of an evidence plane.

An evidence layer has exactly one hard question to answer: *what happens to
the user's LLM request when the evidence machinery itself fails?* There are
two defensible answers and an infinity of dishonest ones ("log and hope").
This module names the two defensible ones:

* **FAIL_CLOSED** — the audit-grade posture. If a receipt cannot be
  constructed, signed, or queued, the *call fails*. No receipt, no response.
  Use it where an unrecorded LLM call is worse than a failed one (regulated
  workloads, policy-enforcement points, customer-facing agents with
  contractual logging).

* **FAIL_OPEN** — the latency-grade posture. Evidence is best-effort: a
  receipt failure is counted and surfaced in stats (never silent), but the
  user's response is never held hostage by the audit trail. Use it where
  availability outranks completeness.

``require_receipt_before_response`` sharpens FAIL_CLOSED: with it set, the
receipt (and its correlation id) must exist *before* LiteLLM returns the
response to the caller, so the response can carry the receipt id and a
construction failure blocks the response outright. Without it, FAIL_CLOSED
still raises out of the post-call hooks, but for streaming responses some
deltas may already have left the process — the README's honesty notes spell
out exactly what is and is not guaranteed.

The policy's identity is content-addressed: ``receipt_policy()`` digests the
canonical form of the policy document, so a receipt pins *which exact policy*
governed it — not a filename that can drift.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from szl_receipts import jcs_canon_bytes, sha256_hex

__all__ = ["DEFAULT_POLICY_NAME", "DEFAULT_POLICY_VERSION", "EvidencePolicy", "FailMode"]

DEFAULT_POLICY_NAME = "szl.evidence.litellm"
DEFAULT_POLICY_VERSION = "1.0.0"


class FailMode(StrEnum):
    """The two postures. Closed vocabulary on purpose — there is no third."""

    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"

    @classmethod
    def parse(cls, value: FailMode | str | None) -> FailMode:
        """Coerce config text into the enum; anything else is a build error."""
        if isinstance(value, cls):
            return value
        if value is None:
            return cls.FAIL_OPEN
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            raise ValueError(
                f"fail_mode must be one of {[m.value for m in cls]}, got {value!r}"
            ) from None


@dataclass(frozen=True)
class EvidencePolicy:
    """The governance policy under which LLM-call receipts are emitted.

    Frozen: a policy that mutates mid-flight is a policy whose receipts lie
    about what governed them. The receipt-visible identity is
    ``{id, version, digest_sha256}`` where the digest covers the canonical
    form of the *whole* policy document (name, version, fail mode, require
    flag) — change any knob and every receipt produced afterwards points at a
    different policy digest.
    """

    name: str = DEFAULT_POLICY_NAME
    version: str = DEFAULT_POLICY_VERSION
    fail_mode: FailMode = FailMode.FAIL_OPEN
    require_receipt_before_response: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "fail_mode", FailMode.parse(self.fail_mode))
        if not self.name:
            raise ValueError("policy name must be non-empty")
        if not self.version:
            raise ValueError("policy version must be non-empty")

    def document(self) -> dict[str, Any]:
        """The canonical policy document — the bytes that get digested."""
        return {
            "fail_mode": self.fail_mode.value,
            "name": self.name,
            "require_receipt_before_response": self.require_receipt_before_response,
            "version": self.version,
        }

    def digest_sha256(self) -> str:
        """sha256 of the canonical policy document. Identity, not a label."""
        return sha256_hex(jcs_canon_bytes(self.document()))

    def receipt_policy(self) -> dict[str, str]:
        """The ``policy`` block of a GovernedAction/v1 receipt."""
        return {
            "id": self.name,
            "version": self.version,
            "digest_sha256": self.digest_sha256(),
        }

    def blocks_on_receipt_error(self) -> bool:
        """True iff a receipt-construction/queueing failure must surface.

        FAIL_CLOSED always surfaces receipt failures (raising out of the
        hook; with ``require_receipt_before_response`` that raise happens
        before the caller sees the response, so it *blocks*). FAIL_OPEN
        never surfaces them to the caller — it counts them loudly instead.
        """
        return self.fail_mode is FailMode.FAIL_CLOSED

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> EvidencePolicy:
        """Build a policy from SZL_* environment variables.

        ``SZL_FAIL_MODE`` (``fail_open``|``fail_closed``, default open),
        ``SZL_REQUIRE_RECEIPT`` (``1``/true), ``SZL_POLICY_NAME`` /
        ``SZL_POLICY_VERSION`` override the identity fields.
        """
        env = os.environ if environ is None else environ
        return cls(
            name=env.get("SZL_POLICY_NAME", DEFAULT_POLICY_NAME),
            version=env.get("SZL_POLICY_VERSION", DEFAULT_POLICY_VERSION),
            fail_mode=FailMode.parse(env.get("SZL_FAIL_MODE")),
            require_receipt_before_response=env.get("SZL_REQUIRE_RECEIPT", "").lower()
            in {"1", "true", "yes"},
        )
