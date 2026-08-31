# szl-receipts

The cryptographic receipt core for the SZL Holdings estate. Everything the
estate does — a build, a deploy, a policy decision, an audit — can be reduced
to a **receipt**: a small, canonical, content-addressed JSON document that a
skeptical third party can verify byte-for-byte years later, offline, with
nothing but this package and the standard `cryptography` library.

## What a receipt is

A `GovernedAction/v1` receipt records that **actor** performed **action**
under **policy** (identified by the sha256 of the policy document) with a
decided **outcome**, over concrete **subjects** (files identified by the
sha256 of their *bytes*) and **evidence** (URIs, optionally digested). Every
receipt carries a `receipt_id` that is the sha256 of its own canonical
(RFC 8785) body, so any tampering with any field is detectable by anyone.

Receipts can be wrapped in DSSE envelopes (Ed25519 signatures over a
domain-separated pre-authentication encoding), expressed as in-toto
Statements, and linked into append-only hash chains where each entry commits
to its predecessor — giving the estate a transparency-log-grade audit trail.

## The three doctrine rules

1. **Bytes, not names.** A digest must cover file *bytes* (read in bounded
   chunks, so multi-gigabyte artifacts are fine), never the path or name
   string. A name is a claim; bytes are ground truth.
2. **Honest names.** An empty `signatures` array is *not* a signature.
   Artifacts with no signature are written as `*.unsigned.json`; artifacts
   named `*.json` must carry at least one signature. Renaming a file must
   never change what the world believes about it — the verify side enforces
   this and raises `NamingError` on mismatch.
3. **UNKNOWN is never passing.** The outcome vocabulary is
   `PASS | WARN | FAIL | BLOCKED | UNKNOWN`. Absence of a verdict is not a
   verdict: `is_passing(UNKNOWN)` is `False`, and the promotion gate refuses
   `UNKNOWN` (and `FAIL`/`BLOCKED`) unconditionally. Only `PASS` promotes by
   default; `WARN` requires an explicit `allow_warn=True` override.

## Quickstart

```bash
pip install -e packages/szl-receipts[dev]

# Generate an Ed25519 keypair (operator.pem is chmod 600).
python -m szl_receipts.cli keygen --out keys/operator

# Canonicalize a JSON document per RFC 8785 and print its sha256.
python -m szl_receipts.cli canon build/manifest.json --json

# Sign any file into a DSSE envelope (honest naming picks the suffix).
python -m szl_receipts.cli sign build/manifest.json --key keys/operator.pem

# Verify naming + structure + signature. Exit 0 ok, 2 tamper, 3 usage/io.
python -m szl_receipts.cli verify build/manifest.json.envelope.json \
    --pub keys/operator.pub.pem

# Verify a directory of hash-chained receipt entries.
python -m szl_receipts.cli chain-verify artifacts/chain/ --expected-entries 12
```

Every CLI command accepts `--json` (machine-readable stdout) and
`--emit-receipt PATH` (write a self-receipt of the command's own outcome —
the estate eats its own cooking).

Python API:

```python
from szl_receipts import (
    Outcome, build_receipt, verify_receipt, append, verify_chain,
    generate_keypair, sign_bytes, verify_envelope,
)

receipt = build_receipt(
    actor="ci-runner-7",
    action="build-master-payload",
    policy={"id": "szl.build.v14", "version": "14.0.0",
            "digest_sha256": "…64 hex…"},
    outcome=Outcome.PASS,
    rationale="deterministic rebuild verified byte-identical",
    subjects=[{"name": "dist/SZL_MASTER_PAYLOAD_V14.md", "sha256": "…64 hex…"}],
)
assert verify_receipt(receipt) == []        # no findings

chain = []
append(chain, receipt)                      # seq 1, prev = null (genesis)
report = verify_chain(chain)
assert report.ok
```

## Attack harness

`tests/` is the executable attack harness, not just a test suite:

- `tests/test_chain.py` — builds a 5-entry chain, then detects
  **truncation**, **reorder**, **replay**, **fork**, and **broken-prev-link**
  attacks as separate cases.
- `tests/test_dsse.py` — payload bit-flip, wrong-key substitution, and a
  PAE prefix-collision (type-confusion) attack.
- `tests/test_naming.py` — dishonest renames of signed/unsigned artifacts.
- `tests/test_cli.py` — end-to-end subprocess runs asserting the
  0/2/3 exit-code contract, including exit 2 on tampered envelopes.

A standalone adversarial harness that drives these primitives against the
full estate lives in `packages/szl-attack-harness/` (planned); until it
lands, `python -m pytest packages/szl-receipts` *is* the harness.

## Layout

| Module | Responsibility |
| --- | --- |
| `jcs.py` | RFC 8785 canonical JSON, stdlib-only (UTF-16 key sort, ECMAScript number formatting, minimal escaping) |
| `digests.py` | chunked `sha256_file`, `sha256_bytes`, `sha256_hex` |
| `dsse.py` | PAE, DSSE envelopes, Ed25519 sign/verify, keygen, in-toto Statement v1 |
| `receipt.py` | `GovernedAction/v1` schema: `build_receipt`, `verify_receipt` |
| `chain.py` | append-only receipt chain with prev-digest links, attack-detecting verifier |
| `naming.py` | honest unsigned naming enforcement (`*.unsigned.json`) |
| `outcome.py` | `Outcome` enum, `is_passing`, promotion gate |
| `cli.py` | `canon \| keygen \| sign \| verify \| chain-verify` with `--json` / `--emit-receipt` |
