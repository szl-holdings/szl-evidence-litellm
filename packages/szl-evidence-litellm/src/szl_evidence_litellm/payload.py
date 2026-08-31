"""The canonical per-request evidence payload.

One LLM request produces one GovernedAction/v1 receipt (built with
:func:`szl_receipts.build_receipt`, so the schema is the estate's, not ours)
plus one *evidence document* holding the request telemetry. The split is a
direct consequence of the receipt schema's discipline:

* ``subjects`` may carry only ``name`` + ``sha256`` — so the request and
  response enter the receipt as digests of their canonical bytes:
  ``{'name': 'request', 'sha256': ...}`` and ``{'name': 'response', ...}``.
* ``evidence`` entries may carry only ``uri`` + ``sha256`` — so the telemetry
  (model, provider, call_id, attempt_index, tokens, latency, cost, …) lives
  in a content-addressed sidecar document, referenced from the receipt as
  ``evidence/<digest>.json``. The sink materializes that sidecar; a verifier
  re-hashes the file and compares.

**Privacy by minimization**: prompt and response *bodies* are never inlined
into the receipt or the evidence document — only their digests. Operators who
need bodies for replay set ``SZL_CAPTURE_BODIES=1`` (or pass
``capture_bodies=True``); bodies are then written to ``bodies/<digest>.json``
next to the sink and referenced by digest. The default trail proves *that* a
call happened and *what shaped it* without storing a single token of user
content.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from szl_receipts import Outcome, build_receipt, jcs_canon_bytes, sha256_hex

from .modes import EvidencePolicy

__all__ = [
    "ACTION_LLM_COMPLETION",
    "EVIDENCE_KIND",
    "BuiltAttempt",
    "actor_from_api_key",
    "build_attempt_receipt",
    "canonical_request_doc",
    "content_digest",
    "jsonable",
]

#: The receipt action for every request this plugin records.
ACTION_LLM_COMPLETION = "llm.completion"

#: Schema tag carried inside every evidence document.
EVIDENCE_KIND = "szl.llm_completion_evidence/v1"


def jsonable(obj: Any, _depth: int = 0) -> Any:
    """Reduce arbitrary SDK objects to JSON-compatible data, deterministically.

    LiteLLM hands callbacks pydantic models (``ModelResponse``), plain dicts,
    ``datetime`` objects and occasionally raw exceptions depending on the code
    path. Digests must cover *bytes*, so everything is normalized here before
    canonicalization. Unknown objects degrade to ``repr()`` — a digest over a
    repr is still binding for tamper-evidence, it just isn't portable.
    """
    if _depth > 32:
        return repr(obj)
    if obj is None or isinstance(obj, str | bool | int):
        return obj
    if isinstance(obj, float):
        # RFC 8785 / I-JSON: NaN and Infinity have no canonical form.
        return obj if math.isfinite(obj) else None
    if isinstance(obj, dict):
        return {str(k): jsonable(v, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [jsonable(v, _depth + 1) for v in obj]
    if isinstance(obj, set | frozenset):
        return sorted((jsonable(v, _depth + 1) for v in obj), key=repr)
    if isinstance(obj, datetime):
        moment = obj if obj.tzinfo else obj.replace(tzinfo=UTC)
        return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(obj, bytes):
        return {"_bytes_sha256": sha256_hex(obj)}
    model_dump = getattr(obj, "model_dump", None)  # pydantic v2
    if callable(model_dump):
        try:
            return jsonable(model_dump(mode="json"), _depth + 1)
        except Exception:  # noqa: S110 — fall through to the next strategy
            pass
    to_dict = getattr(obj, "dict", None)  # pydantic v1
    if callable(to_dict):
        try:
            return jsonable(to_dict(), _depth + 1)
        except Exception:  # noqa: S110 — fall through to the next strategy
            pass
    if hasattr(obj, "__dict__"):
        return {k: jsonable(v, _depth + 1) for k, v in vars(obj).items()}
    return repr(obj)


def content_digest(doc: Any) -> str:
    """sha256 of the RFC 8785 canonical bytes of *doc* (after jsonable())."""
    return sha256_hex(jcs_canon_bytes(jsonable(doc)))


def actor_from_api_key(key_material: str) -> str:
    """Actor identity from raw key material: a digest, never the key itself."""
    return f"apikey-sha256:{sha256_hex(key_material.encode('utf-8'))}"


def canonical_request_doc(
    model: str | None,
    messages: Any,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The canonical request representation whose digest becomes a subject.

    Covers exactly what shaped the model's answer: the model string, the
    messages, and the sampled/decoding parameters. Canonicalization absorbs
    dict ordering, so two producers describing the same call compute the same
    digest.
    """
    return {
        "messages": jsonable(messages),
        "model": model,
        "params": jsonable(params or {}),
    }


@dataclass(frozen=True)
class BuiltAttempt:
    """The output of :func:`build_attempt_receipt`: receipt + evidence sidecar."""

    receipt: dict[str, Any]
    evidence_doc: dict[str, Any]
    evidence_digest: str
    evidence_uri: str

    @property
    def receipt_id(self) -> str:
        return self.receipt["receipt_id"]


def _write_body(bodies_dir: Path, doc: Any) -> dict[str, str]:
    """Persist a body under its content digest and return the reference."""
    blob = jcs_canon_bytes(jsonable(doc))
    digest = sha256_hex(blob)
    bodies_dir.mkdir(parents=True, exist_ok=True)
    path = bodies_dir / f"{digest}.json"
    if not path.exists():  # content-addressed: rewriting identical bytes is a no-op
        path.write_bytes(blob)
    return {"sha256": digest, "uri": f"bodies/{digest}.json"}


def build_attempt_receipt(
    *,
    policy: EvidencePolicy,
    actor: str,
    call_id: str,
    attempt_index: int,
    is_fallback: bool,
    model: str | None,
    provider: str | None,
    request_doc: Any,
    response_doc: Any = None,
    outcome: Outcome | str = Outcome.PASS,
    rationale: str = "",
    latency_ms: float | None = None,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    finish_reason: str | None = None,
    cost_usd: float | None = None,
    error: dict[str, str] | None = None,
    stream: bool = False,
    mock: bool = False,
    bodies_dir: str | Path | None = None,
    extra: dict[str, Any] | None = None,
) -> BuiltAttempt:
    """Build the receipt + evidence document for one request/attempt.

    The receipt commits to: the request digest, the response digest (when a
    response exists — a failed attempt has none, and the receipt says so by
    omission), the policy identity, and the outcome. Everything operational
    lives in the evidence document. ``cost_usd`` appears only when LiteLLM
    actually provided a cost; unknown tokens stay ``null`` rather than 0,
    because "we did not observe" and "zero" are different claims.
    """
    parsed_outcome = Outcome(outcome)
    request_digest = content_digest(request_doc)
    subjects: list[dict[str, Any]] = [{"name": "request", "sha256": request_digest}]
    response_digest: str | None = None
    if response_doc is not None:
        response_digest = content_digest(response_doc)
        subjects.append({"name": "response", "sha256": response_digest})

    evidence_doc: dict[str, Any] = {
        "kind": EVIDENCE_KIND,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "model": model,
        "provider": provider,
        "call_id": call_id,
        "attempt_index": attempt_index,
        "is_fallback": is_fallback,
        "stream": stream,
        "mock": mock,
        "latency_ms": round(latency_ms, 3) if latency_ms is not None else None,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "finish_reason": finish_reason,
        "request_sha256": request_digest,
        "response_sha256": response_digest,
    }
    if cost_usd is not None and math.isfinite(cost_usd):
        evidence_doc["cost_usd"] = cost_usd
    if error is not None:
        evidence_doc["error"] = {"type": error.get("type", ""), "message": error.get("message", "")}
    if extra:
        evidence_doc["extra"] = jsonable(extra)

    if bodies_dir is not None:
        bodies: dict[str, Any] = {"request": _write_body(Path(bodies_dir), request_doc)}
        if response_doc is not None:
            bodies["response"] = _write_body(Path(bodies_dir), response_doc)
        evidence_doc["bodies"] = bodies

    evidence_bytes = jcs_canon_bytes(jsonable(evidence_doc))
    evidence_digest = sha256_hex(evidence_bytes)
    evidence_uri = f"evidence/{evidence_digest}.json"

    receipt = build_receipt(
        actor=actor or "anonymous",
        action=ACTION_LLM_COMPLETION,
        policy=policy.receipt_policy(),
        outcome=parsed_outcome,
        rationale=rationale,
        subjects=subjects,
        evidence=[{"uri": evidence_uri, "sha256": evidence_digest}],
    )
    return BuiltAttempt(
        receipt=receipt,
        evidence_doc=evidence_doc,
        evidence_digest=evidence_digest,
        evidence_uri=evidence_uri,
    )
