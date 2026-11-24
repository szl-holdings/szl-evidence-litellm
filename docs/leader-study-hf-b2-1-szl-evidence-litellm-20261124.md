# W27 HF batch-2 audit #1: szl-evidence-litellm leader study (propose-only)

Date: 2026-11-24. OUROBOROS program, HF SZLHOLDINGS space audit batch 2, item 1.
Governing seat ruling nonce: LITEK1-20261124T021720Z (Kimi GO_MERGES for this study doc; plan edits appended verbatim).

Facts (measured 2026-11-24):
- Tamper-evident, hash-chained receipts for every LiteLLM request; standalone
  distribution of szl-receipts + the SZL evidence plugin. Python, 74 files.
- No leader-study card existed (tree scan: zero leader/study files).
- Doctrine v11, fail-closed, Apache-2.0, GitHub=source HF=mirror.

Leaders studied (2026-11-24):
1. LiteLLM 2026: 53k-star unified LLM gateway, 100-140+ providers, cost tracking,
   load balancing, proxy server (eggstriker.com complete guide 2026;
   pythondatabench.com cost-tracking 2026; a2a-mcp.org 2026 review).
2. invariant-systems-ai/inference-receipts (GitHub): a dedicated inference-receipts
   project - a DIRECT domain leader; honest feature comparison required.
3. AEGIS cryptographic audit logs for AI agents: Merkle tree + witness co-signature
   pattern for aggregate integrity (aegistraces.com).
4. Sigstore Rekor transparency-log deep dive 2026 (safuard.sh) and the hash-chains
   vs Merkle-trees vs certificate-transparency primer (reliablecontext.com):
   externally-verifiable append-only log lineage.

Honest gaps (all claims below are open questions until measured):
- Plain hash-chain integrity today vs Merkle/CT lineage + witness co-signatures.
- No receipts-backed feature matrix vs invariant-systems-ai/inference-receipts.
- LiteLLM compatibility claims need version-dated smoke-test receipts (versions drift).

Absorb plan (ratified, Kimi LITEK1-20261124T021720Z):
1. THIS PR: propose-only study doc (text-only; no runtime, deps, CI changes).
2. Later PR: honest feature-matrix receipts vs invariant-systems-ai/inference-receipts
   (version-dated primary sources on both sides; no secondary-source assertions).
3. Later PR (conditional): Merkle-tree aggregation over existing hash chains for range
   proofs + optional Rekor-style external verifiability - benchmark receipts first.
4. Later PR (conditional): LiteLLM version-compat smoke-test matrix receipts.

Governing seat plan edits (verbatim):
- Step 1: Merge this text-only leader-study PR. It must contain zero runtime code changes and must not modify existing receipt behavior, schemas, verification semantics, or compatibility claims.
- Step 2: Keep the invariant-systems-ai/inference-receipts comparison as a separate later PR. Use a version-dated feature matrix with repository URLs, exact commit or release identifiers, and primary-source evidence for every capability claim. Mark unverified items UNKNOWN rather than inferring them from names or descriptions.
- Step 3: Make Merkle aggregation and Rekor-style external verifiability conditional on a written threat model and benchmarks of the current hash-chain implementation. Preserve existing receipt verification and hash-chain linkage; define canonicalization, leaf and node encoding, domain separation, proof format, inclusion and consistency verification, failure behavior, and backward compatibility before implementation.
- Step 4: Treat witness co-signature as a separate optional design item, not as implied coverage from AEGIS. Specify trust anchors, key rotation and revocation, signature verification, availability behavior, and fail-closed semantics before proposing code.
- Step 5: Add the LiteLLM compatibility smoke-test matrix as an independent evidence PR. Record exact LiteLLM versions, Python versions, plugin entry points, request paths, receipt outputs, and verification results. Do not claim broad LiteLLM compatibility from a single version or from documentation alone.
- Step 6: Keep GitHub as the source of truth and Hugging Face as a mirror. The study must not describe the mirror as an independent integrity anchor or external transparency log.

Non-goals: no plugin/runtime changes, no dependency changes, no secrets.
Each implementation step = separate PR + governing review + owner approval.
