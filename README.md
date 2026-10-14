# szl-evidence-litellm

<!-- szl:header v1 -->
<!-- Native identity: szl-brand@4309f6fce89179331b0b3ed8c99494e76c5be256; Orbit v2 icon. -->
<p>
  <a href="https://github.com/szl-holdings">
    <img src="https://raw.githubusercontent.com/szl-holdings/szl-brand/4309f6fce89179331b0b3ed8c99494e76c5be256/kit/logos/orbit-v2/suite/szl-icon-32.svg" alt="SZL Holdings — Orbit v2" width="32" height="32" />
  </a>
</p>

**Control before action. Evidence after.**

[Product](https://a-11-oy.com) · [Proof](https://a11oy.net) · [GitHub organization](https://github.com/szl-holdings)
<!-- /szl:header -->

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
| `szl-receipts` | 14.0.2 | Trust core: RFC 8785 JCS, chunked byte digests, DSSE/in-toto envelopes, Ed25519, hash-chained append-only ledger |
| `szl-evidence-litellm` | 0.1.2 | The LiteLLM callback plugin: synchronous receipt construction, asynchronous bounded-queue persistence, explicit fail-open/fail-closed policy, per-attempt deployment capture, OpenTelemetry mapping |

Provenance: the last full export was from
`szl-platform@4f2b5f28f8c35daa81522d1dbc605f373df5b07c` (2026-08-31). Later
changes arrived as partial syncs, most recently against `szl-platform@e9ab527c`
(2026-10-14), so the package directories are not a byte-exact copy of any one
`szl-platform` revision. [PROVENANCE.md](PROVENANCE.md) lists each difference.
Development happens in the monorepo; this repo is the release surface.

## Install

Both packages are on PyPI: `szl-receipts` 14.0.2 and `szl-evidence-litellm`
0.1.2, published on 2026-10-01 from the release tags at `cc4ea06`. The plugin
depends on `szl-receipts>=14.0`, so one command installs both:

```bash
pip install 'szl-evidence-litellm[litellm,proxy]'
```

`main` has two plugin fixes from `szl-platform` that are not in 0.1.2 yet:
`flush_sync()` now drains the thread lane or raises (#16), and the ledger file
is replaced crash-atomically (#17). To run `main`, install from this
repository, trust core first:

```bash
git clone https://github.com/szl-holdings/szl-evidence-litellm.git
cd szl-evidence-litellm
pip install -e packages/szl-receipts          # the trust core FIRST (peer dependency)
pip install -e 'packages/szl-evidence-litellm[litellm,proxy]'
```

No GitHub Release has attached files; the distributions are on PyPI. The
original 2026-08-31 build of `v0.1.0` (sdists, wheels, `SHA256SUMS.txt` and an
unsigned manifest, `release-manifest.unsigned.json`) is committed under
`releases/v0.1.0/`. It is not byte-identical to the 0.1.0 and 14.0.0 files
uploaded to PyPI on 2026-09-30, which were rebuilt and have different SHA-256
digests.

## Quick start

```python
import litellm
from szl_evidence_litellm import EvidencePolicy, EvidenceSink, FailMode, SZLEvidenceLogger

policy = EvidencePolicy(fail_mode=FailMode.FAIL_OPEN)   # or FAIL_CLOSED
sink = EvidenceSink("./evidence", policy=policy)        # a directory; the chain is ./evidence/receipts.jsonl
logger = SZLEvidenceLogger(sink=sink, policy=policy)    # the LiteLLM callback
litellm.callbacks = [logger]
```

`EvidenceSink` takes the sink directory as its first argument and the policy
as a keyword. The sink only persists; `SZLEvidenceLogger` is the object you
register with LiteLLM. Synchronous calls (`litellm.completion`) persist
through a background worker thread. Under asyncio (`litellm.acompletion`),
call `await sink.start()` inside the running loop and
`await logger.aclose()` on shutdown to drain the queue. For the LiteLLM proxy,
register `szl_evidence_litellm.plugin.evidence_logger` in the proxy YAML
instead; `packages/szl-evidence-litellm/README.md` shows how.

Each call now leaves a content-addressed receipt. Under `FAIL_OPEN`, a
receipt dropped by backpressure is counted in `stats`, never silently. The
chain verifies offline:

```bash
python -m szl_evidence_litellm verify --sink ./evidence
```

See `packages/szl-evidence-litellm/README.md` for the five load-bearing
patterns, the fail-mode matrix, the receipt schema, and the full configuration
reference.

## Verify the estate's claims about this package

- CI runs the trust-core tests, the full plugin suite and the README
  examples on every push to `main` and every pull request (Python 3.11 and
  3.12), offline and hermetic. The `main` run at `9e6c97b` passed 197
  trust-core tests and 80 plugin tests (1 skipped) on both versions.
- The companion attack harness (19 attacks against this receipt chain — all
  blocked) lives in the SZL estate; this distribution's chain semantics are
  the exact code those attacks run against.

## License

Apache-2.0 (see [LICENSE](LICENSE)); both published packages carry the same
license in their wheel metadata. The receipt format is specified separately in
`draft-lutar-governed-action-receipt-00`, a document in individual
Internet-Draft format kept in `szl-platform` under
[`docs/standards/`](https://github.com/szl-holdings/szl-platform/tree/main/docs/standards).
It has not been submitted to the IETF, and the IETF datatracker has no document
under that name. A copy is deposited on Zenodo as a technical note,
[doi:10.5281/zenodo.22217725](https://doi.org/10.5281/zenodo.22217725).
