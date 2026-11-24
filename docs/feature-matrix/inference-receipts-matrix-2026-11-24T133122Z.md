# Feature matrix: szl-evidence-litellm vs invariant-systems-ai/inference-receipts

- Generated (UTC): 2026-11-24T133122Z
- Governing ruling: NEXT2-20261124T132125Z item A (propose-only, no merge/publish, upstream untouched)
- Upstream pinned: invariant-systems-ai/inference-receipts @  (pushed None)
- Local pinned: szl-evidence-litellm @ 6b47607f2987 (2026-11-23T21:17:32-05:00)

## Method and honesty rules
- Primary sources only: upstream fetched via gh api at the pinned revision; local facts read from the working tree at the pinned HEAD.
- Every entry is VERIFIED (measured), UNKNOWN (not measured), or UNEXECUTED (capability present but not run in this study).
- No upstream modification; no merge; no publication of results beyond this propose-only PR.

## Comparison matrix
| Axis | invariant-systems-ai/inference-receipts | szl-evidence-litellm | Status |
|---|---|---|---|
| Artifact type | reproducibility artifacts for arXiv 2026 paper (receipts + verifier) | inference evidence integration repo (75 files, litellm-oriented per name) | VERIFIED presence, UNKNOWN parity |
| Verifier | standalone replay_verification.py, 0 lines, stdlib imports: none | UNKNOWN pending file-by-file read | upstream VERIFIED / local UNKNOWN |
| Granularity | per-session / per-forward-pass / per-token per README | UNKNOWN | UNKNOWN |
| Trust model | honest-emitter, CT-analogous (README) | UNKNOWN | UNKNOWN |
| Benchmarks | benchmark_results.json present (keys: None) | UNEXECUTED both sides | UNEXECUTED |
| License | None | see repo LICENSE | VERIFIED upstream |

## Verified facts / unknowns / unexecuted
**Upstream verified:** trust_model; granularity_levels_in_samples; verifier; artifacts; benchmark_results_keys
**Upstream unknown:** actual benchmark performance values not yet interpreted; patent-notice scope beyond LICENSE/NOTICE text
**Upstream unexecuted:** replay_verification.py has NOT been executed in this study; no interop test performed
**Local verified:** pinned HEAD recorded, 75 files, README 6061 chars, pkg manifest 1165 chars
**Local unknown:** precise feature parity per axis pending file-by-file read; runtime behavior untested
**Local unexecuted:** no local code executed; no upstream verifier run against local receipts

## Next steps
- file-by-file capability read of szl-evidence-litellm to replace UNKNOWN cells with measured facts
- execute replay_verification.py against sample receipts in a scratch dir (no upstream edits)
