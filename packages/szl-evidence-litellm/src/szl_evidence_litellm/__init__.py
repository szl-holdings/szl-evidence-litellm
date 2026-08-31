"""szl-evidence-litellm — the SZL Evidence Plane plugin for LiteLLM.

A tamper-evident, hash-chained receipt for EVERY LLM request, plugged into
LiteLLM's callback system. Receipts are GovernedAction/v1 documents from the
sibling ``szl_receipts`` trust core: content-addressed identity
(``receipt_id`` = sha256 of the canonical body), DSSE/Ed25519-ready, and
appended to an append-only hash chain (``receipts.jsonl``) that any third
party can re-verify from genesis with ``python -m szl_evidence_litellm
verify --sink PATH``.

Five load-bearing patterns (see README for the full argument):

1. Sign synchronously, persist asynchronously — receipt construction is
   inline and non-blocking; a bounded queue + batched flusher owns the disk.
2. Explicit fail-open vs fail-closed per policy (``modes.FailMode``) — the
   posture is a declared, digested part of every receipt's policy block.
3. Capture via the full callback lifecycle, including per-attempt deployment
   hooks, so retries and fallbacks never escape the evidence trail.
4. OTel-friendly fields — ``otel.py`` maps receipts to the GenAI semantic
   conventions (``gen_ai.request.model``, ``gen_ai.usage.*``) with no OTel
   dependency.
5. One canonical payload per request + a correlation id echoed in
   ``x-szl-receipt-id``; prompt/response bodies are digests by default,
   offloaded to content-addressed files only under SZL_CAPTURE_BODIES=1.

Import surface: everything below is the supported API. LiteLLM itself is an
optional extra — without it, :class:`SZLEvidenceLogger` is a structural
duck-type with identical hook signatures (``LITELLM_AVAILABLE`` is False).
"""

from .modes import EvidencePolicy, FailMode
from .otel import enrich_span, otel_attributes
from .payload import (
    ACTION_LLM_COMPLETION,
    BuiltAttempt,
    actor_from_api_key,
    build_attempt_receipt,
    canonical_request_doc,
    content_digest,
)
from .plugin import LITELLM_AVAILABLE, ReceiptConstructionError, SZLEvidenceLogger
from .sink import (
    CHAIN_LOG_FILE,
    EvidenceBackpressure,
    EvidenceSink,
    PendingReceipt,
    SinkBootError,
    verify_sink,
)

__version__ = "0.1.0"

__all__ = [
    "ACTION_LLM_COMPLETION",
    "CHAIN_LOG_FILE",
    "LITELLM_AVAILABLE",
    "BuiltAttempt",
    "EvidenceBackpressure",
    "EvidencePolicy",
    "EvidenceSink",
    "FailMode",
    "PendingReceipt",
    "ReceiptConstructionError",
    "SZLEvidenceLogger",
    "SinkBootError",
    "__version__",
    "actor_from_api_key",
    "build_attempt_receipt",
    "canonical_request_doc",
    "content_digest",
    "enrich_span",
    "otel_attributes",
    "verify_sink",
]
