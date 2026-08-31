"""SHA-256 digests over real bytes — the estate's unit of ground truth.

Doctrine rule 1: **bytes, not names.** When a receipt claims a subject or an
evidence artifact, the digest must cover the artifact's *bytes*, read from
disk, never the path string or filename. A name is metadata an attacker can
rename; bytes are the thing itself. Nothing in the estate should ever call
``sha256_hex("dist/payload.md")`` and believe it hashed the file.

The 1 MiB chunk size keeps memory flat (and cache-friendly) when hashing
multi-gigabyte artifacts; callers may tune it for embedded or CI constraints.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

__all__ = ["sha256_bytes", "sha256_file", "sha256_hex"]

#: 1 MiB per read: large enough that syscall overhead is negligible on
#: multi-GB artifacts, small enough that peak RSS stays flat.
DEFAULT_CHUNK_SIZE = 1 << 20


def sha256_bytes(data: bytes) -> bytes:
    """Raw 32-byte SHA-256 digest of an in-memory byte string."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 digest of an in-memory byte string.

    This accepts ``bytes`` only, on purpose: passing a path *string* here is
    the canonical way to lie about what was hashed. If you mean a file, call
    :func:`sha256_file`.
    """
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Lowercase hex SHA-256 of the file at *path*, read in bounded chunks.

    Reads exactly ``chunk_size`` bytes per ``read`` call so peak memory is
    constant regardless of file size. Raises FileNotFoundError / OSError
    naturally — a missing artifact is a workflow failure the caller should
    see, not something to paper over.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    hasher = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()
