# Changelog

## szl-evidence-litellm 0.1.3 (unreleased)

### Fixed

- Drain the thread persistence lane in `flush_sync()` and replace ledger files
  crash-atomically (#16, #17).
- Preserve evidence-write outcomes and fail-open/fail-closed behavior through
  shutdown and startup races (#21).
- Confine and validate evidence sidecars, and persist the same normalized
  receipt represented by the payload digest (#23, #24).
- Reject duplicate JSON properties in persisted ledger records before
  verification (#28).

## szl-receipts 14.0.3 (unreleased)

### Fixed

- Reject duplicate JSON properties, non-finite constants, and invalid Unicode
  when parsing and canonicalizing receipts (#25).

These are separate distributions. Release the trust core using
`szl-receipts-v14.0.3`, then the plugin using `szl-evidence-litellm-v0.1.3`.
The plugin's existing `szl-receipts>=14.0` compatibility range is unchanged;
upgrade both packages to receive both sets of fixes.
