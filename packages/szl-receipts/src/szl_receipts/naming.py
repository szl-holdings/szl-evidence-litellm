"""Honest naming: a file's name must tell the truth about its signature.

Doctrine rule 2: **an empty ``signatures`` array is not a signature.** If a
DSSE envelope with zero signatures is written to ``report.json``, every
downstream consumer that pattern-matches on the extension sees a
"signed-looking" artifact that anyone could have produced. Honest naming
makes the trust state legible from the directory listing:

* signatures present  → ``<base>.json``            (a signed artifact)
* signatures absent   → ``<base>.unsigned.json``   (an unsigned artifact)

The verify side enforces the contract in both directions: a ``*.unsigned.json``
file that contains signatures, or a ``*.json`` artifact that contains none,
is a tampered rename and raises :class:`NamingError`. Renaming forgery stops
being free.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

__all__ = [
    "NamingError",
    "Signedness",
    "classify_unsigned_name",
    "checks_for_name",
    "parse_envelope",
    "signed_name",
    "unsigned_name",
    "verify_honest_naming",
    "write_envelope",
]

_UNSIGNED_SUFFIX = ".unsigned.json"
_SIGNED_SUFFIX = ".json"


class Signedness:
    """Trust classification derived from an envelope's signatures, not its name."""

    __slots__ = ("signatures", "has_signatures")

    def __init__(self, signatures: list[Any]) -> None:
        self.signatures = signatures
        self.has_signatures = bool(signatures)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Signedness(has_signatures={self.has_signatures})"


class NamingError(Exception):
    """Raised when a file's name lies about its signature state."""


def signed_name(path_base: str | Path) -> str:
    """The honest filename for a signed artifact at *path_base*."""
    return str(path_base) + _SIGNED_SUFFIX


def unsigned_name(path_base: str | Path) -> str:
    """The honest filename for an unsigned artifact at *path_base*."""
    return str(path_base) + _UNSIGNED_SUFFIX


def classify_unsigned_name(name: str | Path) -> bool:
    """True if *name* follows the unsigned-artifact convention."""
    return str(name).endswith(_UNSIGNED_SUFFIX)


def checks_for_name(name: str | Path) -> str:
    """Return the trust claim carried by a filename: "signed" or "unsigned"."""
    return "unsigned" if classify_unsigned_name(name) else "signed"


def parse_envelope(envelope: Mapping[str, Any]) -> Signedness:
    """Pull the signatures out of an envelope-shaped mapping.

    A missing or non-list ``signatures`` key is data corruption, not an
    unsigned artifact — absent is different from empty, and conflating them
    is how quiet forgeries pass review.
    """
    if envelope is None or not isinstance(envelope, Mapping):
        raise TypeError("envelope must be a mapping")
    sigs = envelope.get("signatures")
    if sigs is None:
        raise NamingError("envelope has no 'signatures' key: not a DSSE envelope")
    if not isinstance(sigs, list):
        raise NamingError(
            f"envelope 'signatures' must be a list, got {type(sigs).__name__}"
        )
    return Signedness(sigs)


def write_envelope(
    path_base: str | Path,
    envelope: Mapping[str, Any],
    *,
    overwrite: bool = True,
) -> Path:
    """Persist *envelope* under the honest name and return the written path.

    Chooses ``<base>.json`` iff the envelope carries at least one signature,
    else ``<base>.unsigned.json``. The envelope is serialized with its keys
    sorted (via json.dump sort_keys) so the on-disk form is stable for diff
    review; canonical JCS bytes are what gets *hashed*, the file layout is
    for humans.
    """
    signedness = parse_envelope(envelope)
    out_path = Path(
        signed_name(path_base) if signedness.has_signatures else unsigned_name(path_base)
    )
    if out_path.exists() and not overwrite:
        raise NamingError(f"refusing to overwrite existing artifact: {out_path}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh, ensure_ascii=False, sort_keys=True, indent=2)
        fh.write("\n")
    return out_path


def verify_honest_naming(path: str | Path, envelope: Mapping[str, Any] | None = None) -> Path:
    """Assert that *path*'s name matches the signature state of its envelope.

    If *envelope* is not supplied, the file at *path* is read and parsed.
    Returns the validated path. Raises :class:`NamingError` when:

    * an ``*.unsigned.json`` file contains one or more signatures, or
    * any other ``*.json`` file contains zero signatures.
    """
    file_path = Path(path)
    if envelope is None:
        try:
            envelope = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise NamingError(f"cannot read envelope {file_path}: {exc}") from exc
    signedness = parse_envelope(envelope)
    name_is_unsigned = classify_unsigned_name(file_path.name)
    if name_is_unsigned and signedness.has_signatures:
        raise NamingError(
            f"{file_path}: named unsigned but contains "
            f"{len(signedness.signatures)} signature(s) — tampered rename"
        )
    if not name_is_unsigned and not signedness.has_signatures:
        raise NamingError(
            f"{file_path}: named signed but signatures is empty — "
            "an empty signatures array is not a signature"
        )
    return file_path
