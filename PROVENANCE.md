# Provenance

This repository is a byte-exact standalone mirror of two packages from the
private SZL Holdings monorepo, exported for public distribution.

| Field | Value |
|---|---|
| Source repository | `szl-holdings/szl-platform` (private) |
| Source revision | `16ebbc0cdaf348b95e6ac300cca58b1f0193f0b2` |
| Source paths | `packages/szl-receipts/`, `packages/szl-evidence-litellm/` |
| Exported | 2026-08-31 |
| Export method | `tar` copy excluding `__pycache__/`, `*.egg-info/`, `.pytest_cache/` |
| Mutation policy | Do not edit package code here; changes land in `szl-platform` first and are re-exported with a new revision pin |

Excluded metadata directories are pip build artifacts and contain no source.

The release pipeline (`.github/workflows/ci.yml`) rebuilds distributions from
this mirror and attaches them, with SHA256 sums, to each GitHub Release.
