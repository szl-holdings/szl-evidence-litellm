"""szl-receipts — the cryptographic receipt core of the SZL Holdings estate.

Public API. Import from here, not from submodules: this surface is what the
estate's other packages (payload builder, estate control plane, simulators,
attack harness) are allowed to depend on, and it is versioned as one unit.

Three doctrine rules bind everything below:
  1. Bytes, not names — digests cover file bytes, never path strings.
  2. Honest names — an empty signatures array is not a signature;
     unsigned artifacts are named *.unsigned.json.
  3. UNKNOWN is never passing — no gate promotes what it cannot
     characterize.
"""

from .chain import ChainReport, append, entry_digest_for, verify_chain
from .digests import DEFAULT_CHUNK_SIZE, sha256_bytes, sha256_file, sha256_hex
from .dsse import (
    INTOTO_STATEMENT_V1,
    DsseError,
    generate_keypair,
    keygen,
    load_private_key,
    load_public_key,
    pae,
    sign_bytes,
    statement,
    unwrap_envelope,
    verify_envelope,
)
from .jcs import IJsonError, JcsError, jcs_canon_bytes, jcs_canon_json_text, number_to_js_str
from .naming import NamingError, verify_honest_naming, write_envelope
from .outcome import Outcome, is_passing, promotion_gate
from .receipt import (
    GOVERNED_ACTION_V1,
    build_receipt,
    compute_receipt_id,
    verify_receipt,
)

__version__ = "14.0.0"

__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "GOVERNED_ACTION_V1",
    "INTOTO_STATEMENT_V1",
    "ChainReport",
    "DsseError",
    "IJsonError",
    "JcsError",
    "NamingError",
    "Outcome",
    "__version__",
    "append",
    "build_receipt",
    "compute_receipt_id",
    "entry_digest_for",
    "generate_keypair",
    "is_passing",
    "jcs_canon_bytes",
    "jcs_canon_json_text",
    "keygen",
    "load_private_key",
    "load_public_key",
    "number_to_js_str",
    "pae",
    "promotion_gate",
    "sha256_bytes",
    "sha256_file",
    "sha256_hex",
    "sign_bytes",
    "statement",
    "unwrap_envelope",
    "verify_chain",
    "verify_envelope",
    "verify_honest_naming",
    "verify_receipt",
    "write_envelope",
]
