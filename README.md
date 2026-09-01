# szl-evidence-litellm

**Tamper-evident, hash-chained receipts for every LiteLLM request.**

No gateway or observability project — not LiteLLM itself, not Kong, Portkey,
Helicone, Langfuse, or Phoenix — ships tamper-evident request logs. They log;
they trace; they dashboard. But a log line in a mutable database is an
assertion, not evidence. This plugin adds the missing layer: every request
produces a `GovernedAction/v1` receipt whose identity is the sha256 of its own
canonical (RFC 8785) body, appended to an append-only hash chain that fails
loudly under reorder, truncation, replay, fork, or field-level tamper.

This repository is the standalone distribution of two packages developed in
the SZL Holdings monorepo (`szl-platform`):

| Package | Version | Role |
|---|---|---|
| `szl-receipts` | 14.0.0 | Trust core: RFC 8785 JCS, chunked byte digests, DSSE/in-toto envelopes, Ed25519, hash-chained append-only ledger |
| `szl-evidence-litellm` | 0.1.0 | The LiteLLM callback plugin: synchronous receipt construction, asynchronous bounded-queue persistence, explicit fail-open/fail-closed policy, per-attempt deployment capture, OpenTelemetry mapping |

Provenance: byte-exact mirror of `szl-platform@4f2b5f28f8c35daa81522d1dbc605f373df5b07c`
(2026-08-31). See [PROVENANCE.md](PROVENANCE.md). Development happens in the
monorepo; this repo is the release surface.

## Install

Until the packages land on PyPI, install from this repository:

```bash
git clone https://github.com/szl-holdings/szl-evidence-litellm.git
cd szl-evidence-litellm
pip install -e packages/szl-receipts          # the trust core FIRST (peer dependency)
pip install -e 'packages/szl-evidence-litellm[litellm,proxy]'
```

Or pin a release asset directly (each GitHub Release carries built
`sdist`/`wheel` files with SHA256SUMS and an unsigned receipt manifest, named
`*.unsigned.json` until the estate's production signing lane is enabled).

## Quick start

```python
import litellm
from szl_evidence_litellm import EvidencePolicy, EvidenceSink, FailMode

policy = EvidencePolicy(fail_mode=FailMode.FAIL_OPEN)   # or FAIL_CLOSED
sink = EvidenceSink(policy, path="receipts.jsonl")
litellm.callbacks = [sink.plugin]
```

Every call now leaves a content-addressed receipt; the chain verifies offline:

```bash
python -m szl_receipts verify receipts.jsonl
```

See `packages/szl-evidence-litellm/README.md` for the five load-bearing
patterns, the fail-mode matrix, the receipt schema, and the full configuration
reference.

## Verify the estate's claims about this package

- 163 trust-core tests and the full plugin suite run in CI on every push
  (Python 3.11 and 3.12), offline and hermetic.
- The companion attack harness (19 attacks against this receipt chain — all
  blocked) lives in the SZL estate; this distribution's chain semantics are
  the exact code those attacks run against.

## License

Proprietary — see each package's `pyproject.toml`. Contact SZL Holdings for
licensing. The format specification is published separately as an IETF
individual draft (`draft-lutar-governed-action-receipt`).
