# szl-evidence-litellm

**The SZL Evidence Plane plugin for LiteLLM: a tamper-evident, hash-chained,
DSSE-ready receipt for every LLM request** — plugged into LiteLLM's callback
system, invisible to callers until the day you need to *prove* what happened.

No gateway or observability project — not LiteLLM itself, not Kong, Portkey,
Helicone, Langfuse, or Phoenix — ships **tamper-evident** request logs. They
log; they trace; they dashboard. But a log line in a mutable database is an
assertion, not evidence. This plugin adds the missing layer: every request
produces a `GovernedAction/v1` receipt whose identity is the sha256 of its
own canonical (RFC 8785) body, appended to an append-only hash chain that
fails loudly under reorder, truncation, replay, fork, or field-level tamper.

```
pip install -e packages/szl-receipts            # the trust core (sibling)
pip install -e packages/szl-evidence-litellm    # this plugin
pip install -e 'packages/szl-evidence-litellm[litellm,proxy]'   # + extras
```

## The five load-bearing patterns

**1. Sign synchronously, persist asynchronously.** Receipt construction,
canonicalization, and content addressing happen inline on the callback path
(microseconds of sha256, zero IO). The request path then does a synchronous,
non-blocking `put_nowait` onto a **bounded in-process queue** (default
10 000). A single background flusher drains the queue in batches — 64
receipts or 500 ms, whichever comes first — chains them
(`seq`/`prev`/`entry_digest`, `szl_receipts.chain.append` semantics), and
appends to `receipts.jsonl` with an **fsync per batch**. One writer, ever:
no interleaved lines, no sequence races. LiteLLM's sync callbacks can fire
on executor threads with no event loop, so the sink runs two drain lanes
(an asyncio flusher and a stdlib-queue worker thread) that converge on one
serialized persistence path.

**2. Explicit fail-open vs fail-closed, per policy.** The one question an
evidence layer must answer honestly: *what happens to the user's request
when the evidence machinery fails?* This package has two named answers and
refuses to improvise a third — see the matrix below. The posture is part of
the policy document, whose sha256 is embedded in every receipt: an auditor
can tell which regime produced any given receipt.

**3. Full lifecycle capture, including per-attempt deployment hooks.**
`log_pre_api_call` snapshots the canonical request; the terminal
success/failure events emit the logical-call receipt; and the deployment
hooks fire *per attempt*. LiteLLM's retry/fallback machinery re-enters its
call wrapper per attempt, so `async_pre_call_deployment_hook` bumps the
call's `attempt_index` and `async_post_call_success_deployment_hook`
receipts each successful attempt *before* fallbacks collapse to a winner. A
call that failed over three deployments leaves a receipt set, not a receipt
for the survivor. Terminal events dedupe across LiteLLM's sync/async twins,
so exactly one terminal receipt lands per logical call.

**4. OTel-friendly fields.** `otel.py` maps receipt/evidence fields onto the
OpenTelemetry GenAI semantic conventions — `gen_ai.system`,
`gen_ai.request.model`, `gen_ai.response.finish_reasons`,
`gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` — as pure mapping
dicts plus a duck-typed `enrich_span(span, evidence)` (anything with
`set_attribute`). No `opentelemetry` dependency is taken.

**5. One canonical payload per request + a correlation id.** Each request
yields one receipt whose `subjects` are the sha256 of the canonical request
and response — and a correlation id (`receipt_id`, the content address)
echoed to callers in the `x-szl-receipt-id` response header by `proxy.py`.
**Prompt and response bodies are never inlined by default** (privacy by
minimization): the receipt proves *that* a call happened and *what shaped
it* without storing a token of user content. Operators who need bodies for
replay set `SZL_CAPTURE_BODIES=1`; bodies land in `bodies/<digest>.json`,
content-addressed and referenced by digest from the evidence document.

## Fail-open vs fail-closed — the matrix

| Policy | `require_receipt_before_response` | Receipt build/queue fails | Backpressure (queue full) | Posture |
|---|---|---|---|---|
| `fail_closed` | `true` | **Request blocked** — the error raises out of the hook before LiteLLM returns; no receipt, no response | `EvidenceBackpressure` raises; request refused | **Audit-grade** |
| `fail_closed` | `false` | Error raises out of the hook (counts in `stats.blocked`); streaming responses may already have partially emitted | `EvidenceBackpressure` raises | Strict, with an honest streaming caveat |
| `fail_open` | `true` | Counted in `stats.errors`; response proceeds; receipt attached best-effort | Receipt dropped; `dropped_counter` increments; one loud line per drop-streak in `drops.jsonl` | Contradictory on its face — `require` only has teeth under `fail_closed`; accepted but equivalent to the row below |
| `fail_open` | `false` | Counted in `stats.errors`; response proceeds | Dropped + counted + `drops.jsonl` | **Latency-grade** (default) |

A dropped receipt is a **loud** signal — counted, surfaced in
`stats().dropped_counter`, and logged to `drops.jsonl` at the start of every
drop-streak. Silent loss is the one thing an evidence plane may never do.

## Honesty notes

We'd rather you trust the limits than oversell the guarantees:

* **Receipts are hash-chained, not DSSE-signed at rest.** Each receipt is
  *self-identifying* (`receipt_id` = sha256 of its canonical body) and the
  chain makes tampering detectable. Signing envelopes
  (`szl_receipts.sign_bytes` / `write_envelope`) is a deliberate next step —
  the chain already authenticates *content*; signatures would add
  *authorship*. We do not call an unsigned artifact signed.
* **The chain detects tamper; it does not prevent deletion.** An attacker
  with write access to the sink directory can delete the whole directory —
  like any local log. The defense is the checkpoint head (`chain_head.json`)
  published/anchored out-of-band, exactly as `szl_receipts.verify_chain`
  documents: silent tail truncation is only detectable against an external
  anchor.
* **`async_post_call_failure_deployment_hook` is not invoked by LiteLLM
  1.98's core retry loop.** The hook is implemented and correct for hosts
  that wire it (and per-attempt *successes* are captured); per-attempt
  failures surface as one FAIL receipt at the terminal failure event,
  covering the exhausted attempt series. No success and no logical call
  escapes.
* **Sync-path caveat.** LiteLLM fires deployment hooks on its async path.
  The sync path receipts at the terminal event (exactly once, deduped) with
  full request/response digests — the evidence is complete; the per-attempt
  granularity is the async path's feature.
* **The demo backend is not an LLM.** `proxy.py`'s default completion
  callable is a deterministic local echo, labeled as such in every response
  and in the app description. It exists so the whole surface runs offline
  and reproducibly.
* **Restart boot gate.** A sink whose on-disk chain fails verification
  *refuses to boot* (`SinkBootError`) rather than appending fresh receipts
  onto a tampered tail and manufacturing false confidence.

## Wire it into the LiteLLM proxy

```yaml
# examples/litellm_config.yaml
model_list:
  - model_name: gpt-3.5-turbo
    litellm_params:
      model: gpt-3.5-turbo
      api_key: os.environ/OPENAI_API_KEY

litellm_settings:
  callbacks: szl_evidence_litellm.plugin.evidence_logger
  num_retries: 2
  fallbacks: [{ "gpt-3.5-turbo": ["gpt-4o-mini"] }]
```

```bash
SZL_EVIDENCE_LOGGER=1 \
SZL_SINK_DIR=/var/lib/szl/evidence \
SZL_FAIL_MODE=fail_closed \
SZL_REQUIRE_RECEIPT=1 \
litellm --config examples/litellm_config.yaml --port 4000
```

The `evidence_logger` singleton is created **only** when
`SZL_EVIDENCE_LOGGER=1` — importing the package elsewhere never spins up a
sink as an import side effect. Environment knobs: `SZL_SINK_DIR`,
`SZL_FAIL_MODE` (`fail_open`|`fail_closed`), `SZL_REQUIRE_RECEIPT`,
`SZL_CAPTURE_BODIES`, `SZL_QUEUE_MAXSIZE`, `SZL_POLICY_NAME`,
`SZL_POLICY_VERSION`.

## Use it from the SDK

```python
import litellm
from szl_evidence_litellm import EvidencePolicy, EvidenceSink, FailMode, SZLEvidenceLogger

policy = EvidencePolicy(fail_mode=FailMode.FAIL_CLOSED,
                        require_receipt_before_response=True)
sink = EvidenceSink("./evidence", policy=policy)
logger = SZLEvidenceLogger(sink=sink, policy=policy)
litellm.callbacks = [logger]

resp = litellm.completion(model="gpt-3.5-turbo",
                          messages=[{"role": "user", "content": "hi"}])
```

## Demo proxy + verification (fully offline)

```bash
python -m szl_evidence_litellm demo-proxy --port 8420 --sink ./evidence

curl -s -D- -X POST http://127.0.0.1:8420/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model": "demo", "messages": [{"role": "user", "content": "prove it"}]}'
# → x-szl-receipt-id: <64-hex receipt id>

curl -s http://127.0.0.1:8420/receipts/<receipt_id>     # receipt + evidence
curl -s http://127.0.0.1:8420/receipts/verify           # chain report

python -m szl_evidence_litellm verify --sink ./evidence
python -m szl_evidence_litellm stats  --sink ./evidence --json
```

## Layout

```
src/szl_evidence_litellm/
  plugin.py   SZLEvidenceLogger — the CustomLogger (duck-type without litellm)
  sink.py     EvidenceSink — bounded queue, batched fsync, hash chain, verify
  payload.py  canonical request/response digests + evidence document builder
  modes.py    FailMode + EvidencePolicy (fail-open vs fail-closed, digested)
  otel.py     OTel GenAI semconv mapping (pure dicts, no dependency)
  proxy.py    FastAPI demo proxy (x-szl-receipt-id, /receipts/*)
  cli.py      demo-proxy / verify / stats
```

Receipts are `GovernedAction/v1` from `szl_receipts`. The receipt commits to
the sha256 of the canonical request and response; the telemetry (model,
provider, call_id, attempt_index, tokens, latency_ms, finish_reason,
cost_usd when LiteLLM reports it) lives in a content-addressed evidence
document at `evidence/<digest>.json`, referenced from the receipt's
`evidence[]` and re-hashed on every `verify`.
