# Provenance

This repository is the standalone public distribution of two packages from the
SZL Holdings monorepo `szl-holdings/szl-platform`, which is a public
repository. Earlier revisions of this file called it private. That was wrong.

| Field | Value |
|---|---|
| Source repository | `szl-holdings/szl-platform` (public) |
| Source revision | `b8a0e6d287f1bbea314c698b0749a37d06573b31` (partial sync; see "Sync status") |
| Source paths | `packages/szl-receipts/`, `packages/szl-evidence-litellm/` |
| Exported | 2026-10-13 (partial sync). Last full export: 2026-08-31, from `4f2b5f28f8c35daa81522d1dbc605f373df5b07c` |
| Export method | `tar` copy excluding `__pycache__/`, `*.egg-info/`, `.pytest_cache/` |
| Mutation policy | Do not edit package code here; changes land in `szl-platform` first and are re-exported with a new revision pin |

Excluded metadata directories are pip build artifacts and contain no source.

The release pipeline (`.github/workflows/ci.yml`) rebuilds distributions from
this mirror and attaches them, with SHA256 sums, to each GitHub Release.

## Sync status

The two package directories are **not** a byte-exact copy of any single
`szl-platform` revision.

### 2026-10-13 sync

This sync took only the change from `szl-platform` #22 (merge commit
`b8a0e6d2`), which makes `flush_sync()` drain the thread lane or raise:

| File | State against `szl-platform@b8a0e6d2` |
|---|---|
| `packages/szl-evidence-litellm/src/szl_evidence_litellm/plugin.py` | byte-exact |
| `packages/szl-evidence-litellm/tests/test_flush_sync.py` | byte-exact (new file) |
| `packages/szl-evidence-litellm/src/szl_evidence_litellm/sink.py` | #22 diff applied as a patch; still lacks the platform-only flusher hunk listed below |

### Why this was not a full re-export

A full re-export would have overwritten mirror-side changes that
`szl-platform` does not have. It would also have pulled in platform changes
that have not been reviewed for this distribution.

### Mirror-only changes (made here; not in `szl-platform`)

- **Distribution metadata.** These cover the Apache-2.0 relicensing and packaging for PyPI (#5, #7, #8, #9, #10):
  - `packages/*/LICENSE`
  - `packages/*/pyproject.toml`: Apache-2.0 metadata, versions 14.0.2 and 0.1.2, `[project.urls]`, `[tool.szl.release]`
  - `packages/*/README.md` badges
  - `__version__` in both `__init__.py` files
- **Stricter chain verifier (#3).** This verifier checks inner receipts and that the genesis sequence starts at 1. Porting it to `szl-platform` is pending approval. Files:
  - `packages/szl-receipts/src/szl_receipts/chain.py`
  - `packages/szl-receipts/tests/test_chain.py`
  - `packages/szl-receipts/tests/test_cli.py`
  - `packages/szl-evidence-litellm/tests/test_sink.py` (its boot-gate cases)

### `szl-platform`-only changes (not yet exported here)

- `src/szl_evidence_litellm/modes.py` and `tests/test_modes.py`: strict parsing of `SZL_REQUIRE_RECEIPT` (`53c3f3d`).
- `src/szl_evidence_litellm/sink.py` and `tests/test_sink.py`: an enqueue on a running loop now starts the asyncio flusher without needing `start()` (`e5bc48d`).
- Both `pyproject.toml` files: `classifiers = ["Private :: Do Not Upload"]` (`92a5c20`). This must not be exported here, because this repository publishes to PyPI.
