"""GovernedAction/v1 — the estate's receipt schema.

A receipt is the smallest honest unit of governance: it states *who* did
*what*, under *which policy* (identified by the sha256 of the policy
document, not its filename), with what *outcome*, over which *subjects*
(bytes, digested) and *evidence*. It is self-identifying:
``receipt_id`` is the sha256 of the receipt's own canonical (RFC 8785) body
computed with the ``receipt_id`` field removed, so a verifier anywhere can
recompute the identity and detect any field-level tamper without trusting a
registry.

``created_at`` is a real wall-clock timestamp. Receipts are runtime
artifacts, *not* deterministic build outputs — doctrine demands byte-repro-
ducible builds of the payload, but a receipt exists to record that something
happened at a moment in time; pretending otherwise would be the first lie in
the ledger. Determinism lives in the canonical form and the digest; the
timestamp is data, not formatting.

Error philosophy: :func:`verify_receipt` never raises on bad *data* — a
malformed or tampered receipt is an everyday operational event, so every
problem is returned as a finding string and an empty list means "this
receipt is well-formed and its identity checks out". It raises only on
programmer error (arguments of the wrong type), because that is a bug in the
caller, not in the receipt.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from .digests import sha256_hex
from .jcs import IJsonError, JcsError, jcs_canon_bytes
from .outcome import Outcome, parse_outcome

__all__ = [
    "GOVERNED_ACTION_V1",
    "RECEIPT_SCHEMA_VERSION",
    "build_receipt",
    "compute_receipt_id",
    "receipt_body_canonical_bytes",
    "verify_receipt",
]

GOVERNED_ACTION_V1 = "GovernedAction/v1"
RECEIPT_SCHEMA_VERSION = "1.0"

# Receipt identifiers are sha256 hex digests of canonical bodies — never
# human-chosen strings. Enforcing the shape here means a forged "id" of the
# form "important-receipt-final-v2" is structurally impossible.
_SHA256_HEX_RE = re.compile(r"\A[0-9a-f]{64}\Z")

# ISO-8601 with mandatory timezone offset — the only timestamp grammar the
# estate accepts on the wire. Naive datetimes have no place in an audit log:
# "14:00" in whose timezone?
_ISO_UTC_RE = re.compile(
    r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})\Z"
)

_REQUIRED_KEYS = frozenset(
    {
        "receipt_id",
        "receipt_type",
        "schema_version",
        "created_at",
        "actor",
        "action",
        "policy",
        "decision",
        "subjects",
        "evidence",
    }
)
_ALLOWED_KEYS = _REQUIRED_KEYS


def _validate_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_HEX_RE.match(value) is not None


def build_receipt(
    *,
    actor: str,
    action: str,
    policy: dict[str, Any],
    outcome: Outcome | str,
    rationale: str,
    subjects: list[dict[str, Any]] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    created_at: datetime | str | None = None,
    schema_version: str = RECEIPT_SCHEMA_VERSION,
) -> dict[str, Any]:
    """Construct a GovernedAction/v1 receipt and return it as a plain dict.

    All arguments are keyword-only: a receipt built positionally is a receipt
    whose fields drift under refactors. ``outcome`` accepts the enum or its
    string; anything outside the vocabulary raises ValueError *at build
    time*, because shipping a receipt with an un-gateable outcome is worse
    than crashing the builder.

    ``created_at`` defaults to now (UTC). Passing a datetime or ISO string is
    supported for replay/migration tooling; both are normalized to a
    UTC ``...Z`` string.

    Programmer errors (wrong types, missing required policy keys) raise
    immediately — this function builds receipts for the estate, and the
    estate does not guess.
    """
    if not isinstance(actor, str) or not actor:
        raise TypeError("actor must be a non-empty string")
    if not isinstance(action, str) or not action:
        raise TypeError("action must be a non-empty string")
    parsed_outcome = parse_outcome(outcome)

    policy_doc = _normalize_policy(policy)
    created_text = _normalize_created_at(created_at)
    subject_docs = [_normalize_subject(s, i) for i, s in enumerate(subjects or [])]
    evidence_docs = [_normalize_evidence(e, i) for i, e in enumerate(evidence or [])]

    body: dict[str, Any] = {
        "receipt_type": GOVERNED_ACTION_V1,
        "schema_version": schema_version,
        "created_at": created_text,
        "actor": actor,
        "action": action,
        "policy": policy_doc,
        "decision": {"outcome": parsed_outcome.value, "rationale": rationale},
        "subjects": subject_docs,
        "evidence": evidence_docs,
    }
    body["receipt_id"] = compute_receipt_id(body)
    return body


def compute_receipt_id(body: dict[str, Any]) -> str:
    """Compute the receipt_id of a receipt body (with or without one present).

    Identity is: sha256 over the RFC 8785 canonical bytes of the body with
    ``receipt_id`` excluded. The field ordering of the input dict is
    irrelevant — canonicalization absorbs it — so a producer with different
    dict insertion order computes the same id. That is the whole point.
    """
    idless = {key: value for key, value in body.items() if key != "receipt_id"}
    return sha256_hex(jcs_canon_bytes(idless))


def receipt_body_canonical_bytes(receipt: dict[str, Any]) -> bytes:
    """Canonical JCS bytes of the full receipt (for DSSE payload embedding).

    Signing the canonical form means a signature verifies even if the
    envelope travels through a JSON stack that reserializes whitespace or
    reorders keys — the bytes under the signature are semantic, not
    incidental.
    """
    return jcs_canon_bytes(dict(receipt))


def verify_receipt(receipt: Any) -> list[str]:
    """Validate a receipt, returning a list of findings ([] means sound).

    Checks, in order: mapping shape; required/extra keys; receipt_type and
    schema versions; created_at grammar and parseability; actor/action
    non-emptiness; policy shape incl. digest format; decision.outcome inside
    the closed vocabulary; subjects (each a non-empty name plus a well-formed
    64-hex sha256); evidence (each a non-empty uri, optional well-formed
    sha256); and finally recomputation of receipt_id against the canonical
    body. Every failure is a finding string; nothing about bad *data* raises.
    """
    if not isinstance(receipt, dict):
        raise TypeError(
            f"verify_receipt expects a dict, got {type(receipt).__name__}; "
            "caller must json.loads() untrusted text first"
        )
    findings: list[str] = []

    missing = sorted(_REQUIRED_KEYS - receipt.keys())
    extra = sorted(set(receipt.keys()) - _ALLOWED_KEYS)
    for key in missing:
        findings.append(f"missing required key: {key}")
    for key in extra:
        findings.append(f"unexpected key: {key}")
    if missing:
        # No point type-checking fields that are absent; report and stop.
        return findings

    _check_type_fields(receipt, findings)
    _check_policy(receipt.get("policy"), findings)
    _check_decision(receipt.get("decision"), findings)
    _check_subjects(receipt.get("subjects"), findings)
    _check_evidence(receipt.get("evidence"), findings)

    declared_id = receipt.get("receipt_id")
    if not _validate_sha256_hex(declared_id):
        findings.append(
            f"receipt_id must be 64 lowercase hex chars, got {declared_id!r}"
        )
    else:
        try:
            recomputed = compute_receipt_id(receipt)
        except (IJsonError, JcsError, TypeError) as exc:
            findings.append(f"receipt body cannot be canonicalized: {exc}")
        else:
            if recomputed != declared_id:
                findings.append(
                    "receipt_id mismatch: declared "
                    f"{declared_id}, recomputed {recomputed} — body was tampered "
                    "or produced by a non-canonical builder"
                )
    return findings


def _check_type_fields(receipt: dict[str, Any], findings: list[str]) -> None:
    if receipt.get("receipt_type") != GOVERNED_ACTION_V1:
        findings.append(
            f"receipt_type must be {GOVERNED_ACTION_V1!r}, got {receipt.get('receipt_type')!r}"
        )
    if not isinstance(receipt.get("schema_version"), str) or not receipt["schema_version"]:
        findings.append("schema_version must be a non-empty string")
    created = receipt.get("created_at")
    if not isinstance(created, str) or _ISO_UTC_RE.match(created) is None:
        findings.append(
            f"created_at must be ISO-8601 with timezone (…Z or ±hh:mm), got {created!r}"
        )
    else:
        # Grammar alone isn't enough: 2026-13-99T99:99 matches the regex.
        try:
            datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            findings.append(f"created_at is not a real calendar moment: {created!r}")
    for field in ("actor", "action"):
        if not isinstance(receipt.get(field), str) or not receipt[field]:
            findings.append(f"{field} must be a non-empty string")


def _check_policy(policy: Any, findings: list[str]) -> None:
    if not isinstance(policy, dict):
        findings.append(f"policy must be an object, got {type(policy).__name__}")
        return
    for field in ("id", "version"):
        if not isinstance(policy.get(field), str) or not policy[field]:
            findings.append(f"policy.{field} must be a non-empty string")
    if not _validate_sha256_hex(policy.get("digest_sha256")):
        findings.append(
            "policy.digest_sha256 must be 64 lowercase hex chars, got "
            f"{policy.get('digest_sha256')!r}"
        )


def _check_decision(decision: Any, findings: list[str]) -> None:
    if not isinstance(decision, dict):
        findings.append(f"decision must be an object, got {type(decision).__name__}")
        return
    outcome = decision.get("outcome")
    try:
        parse_outcome(outcome)
    except (ValueError, TypeError):
        findings.append(
            f"decision.outcome {outcome!r} is outside the vocabulary: "
            + ", ".join(member.value for member in Outcome)
        )
    if not isinstance(decision.get("rationale"), str):
        # An empty rationale is weak practice but not a violation; missing or
        # non-string is a shape error.
        findings.append("decision.rationale must be a string")


def _check_subjects(subjects: Any, findings: list[str]) -> None:
    if not isinstance(subjects, list):
        findings.append(f"subjects must be a list, got {type(subjects).__name__}")
        return
    for index, subject in enumerate(subjects):
        if not isinstance(subject, dict):
            findings.append(f"subjects[{index}] must be an object")
            continue
        if not isinstance(subject.get("name"), str) or not subject["name"]:
            findings.append(f"subjects[{index}].name must be a non-empty string")
        elif set(subject.keys()) - {"name", "sha256"}:
            findings.append(
                f"subjects[{index}] has unexpected keys: "
                + ", ".join(sorted(set(subject.keys()) - {"name", "sha256"}))
            )
        if not _validate_sha256_hex(subject.get("sha256")):
            findings.append(
                f"subjects[{index}].sha256 must be 64 lowercase hex chars, got "
                f"{subject.get('sha256')!r} — digests cover bytes, never names"
            )


def _check_evidence(evidence: Any, findings: list[str]) -> None:
    if not isinstance(evidence, list):
        findings.append(f"evidence must be a list, got {type(evidence).__name__}")
        return
    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            findings.append(f"evidence[{index}] must be an object")
            continue
        if not isinstance(item.get("uri"), str) or not item["uri"]:
            findings.append(f"evidence[{index}].uri must be a non-empty string")
        if "sha256" in item and not _validate_sha256_hex(item["sha256"]):
            findings.append(
                f"evidence[{index}].sha256, when present, must be 64 lowercase "
                f"hex chars, got {item['sha256']!r}"
            )


def _normalize_policy(policy: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise TypeError("policy must be a dict with id, version, digest_sha256")
    normalized: dict[str, Any] = {}
    for field in ("id", "version"):
        value = policy.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"policy.{field} must be a non-empty string")
        normalized[field] = value
    digest = policy.get("digest_sha256")
    if not _validate_sha256_hex(digest):
        raise ValueError(
            "policy.digest_sha256 must be 64 lowercase hex chars (sha256 of the "
            f"policy document's bytes), got {digest!r}"
        )
    normalized["digest_sha256"] = digest
    return normalized


def _normalize_created_at(created_at: datetime | str | None) -> str:
    if created_at is None:
        moment = datetime.now(UTC)
    elif isinstance(created_at, datetime):
        if created_at.tzinfo is None:
            raise ValueError(
                "created_at datetime must be timezone-aware; a naive timestamp "
                "in an audit log is an accident waiting for a timezone"
            )
        moment = created_at.astimezone(UTC)
    elif isinstance(created_at, str):
        text = created_at
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"created_at is not parseable ISO-8601: {text!r}") from exc
        if moment.tzinfo is None:
            raise ValueError(f"created_at lacks a timezone offset: {text!r}")
        return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")
    else:
        raise TypeError(
            f"created_at must be None, datetime, or str, got {type(created_at).__name__}"
        )
    return moment.isoformat().replace("+00:00", "Z")


def _normalize_subject(subject: Any, index: int) -> dict[str, Any]:
    if not isinstance(subject, dict):
        raise TypeError(f"subjects[{index}] must be a dict with name and sha256")
    name = subject.get("name")
    digest = subject.get("sha256")
    if not isinstance(name, str) or not name:
        raise ValueError(f"subjects[{index}].name must be a non-empty string")
    if not _validate_sha256_hex(digest):
        raise ValueError(
            f"subjects[{index}].sha256 must be 64 lowercase hex chars, got {digest!r}"
        )
    return {"name": name, "sha256": digest}


def _normalize_evidence(item: Any, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise TypeError(f"evidence[{index}] must be a dict with uri and optional sha256")
    uri = item.get("uri")
    if not isinstance(uri, str) or not uri:
        raise ValueError(f"evidence[{index}].uri must be a non-empty string")
    normalized: dict[str, Any] = {"uri": uri}
    if "sha256" in item and item["sha256"] is not None:
        digest = item["sha256"]
        if not _validate_sha256_hex(digest):
            raise ValueError(
                f"evidence[{index}].sha256 must be 64 lowercase hex chars, got {digest!r}"
            )
        normalized["sha256"] = digest
    return normalized
