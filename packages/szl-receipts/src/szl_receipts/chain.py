"""The append-only receipt chain: a transparency-log spine for the estate.

Each entry binds a receipt to its position and its predecessor:

    entry_digest = sha256(JCS({"seq": n, "receipt": {...}, "prev": <hex|null>}))

The genesis entry has ``prev = null``; every later entry's ``prev`` is the
``entry_digest`` of the entry before it. Because ``receipt`` itself embeds a
content-addressed ``receipt_id``, one digest recomputation authenticates the
entire history: the chain is only as mutable as sha256's collision
resistance.

Why an explicit verifier with a *findings list*: the attacks on a log are
known — truncate the tail, reorder entries, replay an entry, fork a sequence
number, or break a prev link — and each deserves its own named, testable
detection so an auditor reads *which* attack pattern fired instead of a bare
"invalid". :func:`verify_chain` never throws on bad chain data; it reports.

A note on scope: ``verify_chain`` verifies a *complete chain from genesis*.
A silent truncation of the newest entries is only detectable against an
external anchor, so the verifier accepts optional ``expected_entries`` /
``expected_head`` anchors (the estate publishes its head digest out-of-band).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .digests import sha256_hex
from .jcs import JcsError, jcs_canon_bytes
from .receipt import verify_receipt

__all__ = ["ChainReport", "append", "entry_digest_for", "verify_chain"]

_ENTRY_KEYS = frozenset({"seq", "receipt", "prev", "entry_digest"})


def entry_digest_for(seq: int, receipt: dict[str, Any], prev: str | None) -> str:
    """The binding digest of one chain entry.

    Computed over the RFC 8785 canonical form of exactly the three fields
    that define an entry's identity: sequence number, receipt, and previous
    digest. Canonicalization is what makes this reproducible by any
    independent implementation.
    """
    return sha256_hex(jcs_canon_bytes({"seq": seq, "receipt": receipt, "prev": prev}))


def append(chain: list[dict[str, Any]], receipt: dict[str, Any]) -> dict[str, Any]:
    """Append *receipt* to *chain* (mutating it) and return the new entry.

    The chain is an in-memory list of entry dicts; persistence (one JSON file
    per entry, a JSONL stream, …) is the caller's choice. The receipt is
    validated before it touches the chain: a chain containing an invalid
    receipt is a chain that lies with confidence, so append refuses.

    Raises ValueError listing verification findings if the receipt is
    invalid — that is programmer/workflow error, since receipts should be
    built with build_receipt, which cannot produce an invalid one.
    """
    if not isinstance(chain, list):
        raise TypeError("chain must be a list of entry dicts")
    findings = verify_receipt(receipt)
    if findings:
        raise ValueError(
            "refusing to chain an invalid receipt: " + "; ".join(findings)
        )
    if chain:
        last = chain[-1]
        seq = int(last["seq"]) + 1
        prev = last["entry_digest"]
    else:
        seq = 1
        prev = None  # genesis
    entry: dict[str, Any] = {"seq": seq, "receipt": receipt, "prev": prev}
    entry["entry_digest"] = entry_digest_for(seq, receipt, prev)
    chain.append(entry)
    return entry


@dataclass
class ChainReport:
    """Verdict of a chain verification.

    ``ok`` is the boolean gate; ``findings`` is the audit narrative. Every
    finding carries a stable ``code`` so tooling (and tests) can match on
    attack classes without parsing prose:

      malformed-entry · digest-mismatch · reorder · gap · replay · fork ·
      broken-prev-link · genesis-prev-not-null · truncated · head-mismatch
    """

    ok: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    length: int = 0
    head: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "length": self.length,
            "head": self.head,
            "findings": self.findings,
        }


def _finding(code: str, message: str, seq: Any = None, index: int | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"code": code, "message": message}
    if seq is not None:
        entry["seq"] = seq
    if index is not None:
        entry["index"] = index
    return entry


def verify_chain(
    entries: Any,
    *,
    expected_entries: int | None = None,
    expected_head: str | None = None,
) -> ChainReport:
    """Verify a complete receipt chain, from genesis, detecting known attacks.

    Detections, each emitted as its own finding:

    * **digest-mismatch** — entry content doesn't hash to its entry_digest
      (field-level tamper inside an entry).
    * **reorder** — seq numbers not strictly increasing along the list.
    * **gap** — seq jumps forward (middle truncation).
    * **replay** — the same seq reappears with the identical digest.
    * **fork** — the same seq reappears with a different digest.
    * **broken-prev-link** — entry.prev != digest of the preceding entry.
    * **genesis-prev-not-null** — the first entry must anchor at null.
    * **truncated** — fewer entries than the ``expected_entries`` anchor.
    * **head-mismatch** — final digest differs from the ``expected_head``
      anchor (silent tail truncation / rollback).

    Note the honest limit of any self-verifying log: *without* an external
    anchor, dropping the newest entries yields a shorter but perfectly valid
    chain. The estate therefore anchors its head out-of-band; pass
    ``expected_entries``/``expected_head`` whenever an anchor exists.
    """
    if not isinstance(entries, list):
        return ChainReport(
            ok=False,
            findings=[
                _finding("not-a-list", f"chain must be a list, got {type(entries).__name__}")
            ],
        )

    findings: list[dict[str, Any]] = []
    seen: dict[int, str] = {}
    max_seq = 0
    prev_entry: dict[str, Any] | None = None

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not _ENTRY_KEYS <= entry.keys():
            problems = (
                sorted(_ENTRY_KEYS - entry.keys())
                if isinstance(entry, dict)
                else [f"not an object: {type(entry).__name__}"]
            )
            findings.append(
                _finding("malformed-entry", f"index {index}: missing {problems}", index=index)
            )
            prev_entry = None  # link state unknown from here
            continue

        seq = entry["seq"]
        receipt = entry["receipt"]
        prev = entry["prev"]
        digest = entry["entry_digest"]

        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            findings.append(
                _finding("malformed-entry", f"index {index}: bad seq {seq!r}", index=index)
            )
            prev_entry = None
            continue
        if not isinstance(digest, str):
            findings.append(
                _finding("malformed-entry", f"seq {seq}: entry_digest not a string", seq, index)
            )
            prev_entry = None
            continue

        # 1. Self-consistency: does the entry hash to its declared digest?
        try:
            recomputed = entry_digest_for(seq, receipt, prev)
        except (JcsError, TypeError) as exc:
            findings.append(
                _finding("malformed-entry", f"seq {seq}: not canonicalizable: {exc}", seq, index)
            )
            prev_entry = None
            continue
        if recomputed != digest:
            findings.append(
                _finding(
                    "digest-mismatch",
                    f"seq {seq}: content hashes to {recomputed}, not declared {digest}",
                    seq,
                    index,
                )
            )

        # 2. Replay / fork: same seq seen before?
        if seq in seen:
            if seen[seq] == digest:
                findings.append(
                    _finding("replay", f"seq {seq} duplicated with identical digest", seq, index)
                )
            else:
                findings.append(
                    _finding(
                        "fork",
                        f"seq {seq} appears with two different digests "
                        f"({seen[seq]} vs {digest})",
                        seq,
                        index,
                    )
                )
        else:
            seen[seq] = digest

        # 3. Order and contiguity.
        if seq <= max_seq:
            findings.append(
                _finding("reorder", f"seq {seq} follows seq {max_seq}", seq, index)
            )
        elif prev_entry is not None and seq != prev_entry["seq"] + 1:
            findings.append(
                _finding(
                    "gap",
                    f"seq jumps from {prev_entry['seq']} to {seq} — entries missing",
                    seq,
                    index,
                )
            )
        max_seq = max(max_seq, seq)

        # 4. Linkage to the predecessor.
        if index == 0:
            if prev is not None:
                findings.append(
                    _finding(
                        "genesis-prev-not-null",
                        f"genesis entry must have prev=null, got {prev!r}",
                        seq,
                        index,
                    )
                )
        elif prev_entry is None:
            findings.append(
                _finding(
                    "broken-prev-link",
                    f"seq {seq}: predecessor at index {index - 1} is malformed, "
                    "link unverifiable",
                    seq,
                    index,
                )
            )
        elif prev != prev_entry["entry_digest"]:
            findings.append(
                _finding(
                    "broken-prev-link",
                    f"seq {seq}: prev {prev} != digest of preceding entry "
                    f"{prev_entry['entry_digest']}",
                    seq,
                    index,
                )
            )
        prev_entry = entry

    # 5. External anchors — the only defense against silent tail truncation.
    if expected_entries is not None and len(entries) < expected_entries:
        findings.append(
            _finding(
                "truncated",
                f"chain holds {len(entries)} entries but anchor expects "
                f"{expected_entries}",
            )
        )
    head = None
    if entries:
        last = entries[-1]
        if isinstance(last, dict):
            head_value = last.get("entry_digest")
            if isinstance(head_value, str):
                head = head_value
    if expected_head is not None and head != expected_head:
        findings.append(
            _finding(
                "head-mismatch",
                f"chain head {head} does not match expected anchor {expected_head}",
            )
        )

    return ChainReport(ok=not findings, findings=findings, length=len(entries), head=head)
