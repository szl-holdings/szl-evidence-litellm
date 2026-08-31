"""DSSE (Dead Simple Signing Envelope) over Ed25519, plus in-toto Statements.

Why DSSE instead of signing raw bytes: the bytes being signed must carry
their own *type* so a signature over "a receipt" can never be replayed as a
signature over "an authorization" that happens to share bytes. That is the
classic type-confusion / chosen-protocol attack, and DSSE kills it with
**PAE** — the Pre-Authentication Encoding:

    PAE = b"DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload

(lengths are decimal ASCII, SP is a single space). Because every field is
length-prefixed before concatenation, no pair ``(type, payload)`` can ever
encode to the same bytes as a different pair — the separator positions are
fixed by the lengths, so an attacker cannot smear bytes across the boundary.
The test suite proves this by attempting the collision directly.

Ed25519 is chosen for its small, fixed-size keys/signatures, deterministic
signing (no nonce to leak), and constant-time verification in the
``cryptography`` backend. Strict base64 (``validate=True``) on decode keeps
non-canonical envelopes from passing structural checks.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "INTOTO_STATEMENT_V1",
    "DsseError",
    "SignatureVerificationError",
    "generate_keypair",
    "keygen",
    "load_private_key",
    "load_public_key",
    "pae",
    "private_key_from_pem",
    "public_key_from_pem",
    "sign_bytes",
    "statement",
    "unwrap_envelope",
    "verify_envelope",
]

INTOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"


class DsseError(Exception):
    """Base class for DSSE envelope and key-handling failures."""


class SignatureVerificationError(DsseError):
    """Raised when a signature is structurally present but cryptographically invalid."""


def pae(payload_type: bytes, payload: bytes) -> bytes:
    """Pre-Authentication Encoding per the DSSE spec.

    ``pae(b"a", b"bc")`` == ``b"DSSEv1 1 a 2 bc"``. Both arguments must
    already be bytes; callers pass ``payload_type.encode("utf-8")`` because
    the *type string* is what is length-prefixed, in UTF-8.
    """
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode("ascii")
        + b" "
        + payload_type
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _b64e(data: bytes) -> str:
    """Strict, standard-alphabet base64 as required by the DSSE envelope schema."""
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str, field: str) -> bytes:
    """Strict base64 decode — reject non-canonical padding/alphabet up front."""
    if not isinstance(text, str):
        raise DsseError(f"envelope field {field!r} must be a base64 string")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise DsseError(f"envelope field {field!r} is not valid base64: {exc}") from exc


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair and return (private, public)."""
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def keygen(prefix: str | Path) -> tuple[Path, Path]:
    """Generate a keypair and write ``<prefix>.pem`` / ``<prefix>.pub.pem``.

    The private key is written unencrypted and chmod 600: it is an offline,
    operator-held artifact — encrypting it would add a passphrase-handling
    problem without changing who can read it. Returns (private_path,
    public_path). Creates parent directories; refuses to overwrite an
    existing private key (accidental key rotation is a silent audit gap).
    """
    prefix = Path(prefix)
    priv_path = prefix.with_suffix(".pem")
    pub_path = prefix.with_name(prefix.name + ".pub.pem")
    if priv_path.exists():
        raise DsseError(f"refusing to overwrite existing private key: {priv_path}")
    private, public = generate_keypair()
    prefix.parent.mkdir(parents=True, exist_ok=True)
    priv_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Write-then-chmod via opener would race; open with explicit mode instead
    # so the private key is born 0600.
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(priv_pem)
    finally:
        os.chmod(priv_path, 0o600)  # belt and braces against inherited umask
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


def private_key_from_pem(data: bytes | str) -> Ed25519PrivateKey:
    """Load an unencrypted Ed25519 private key from PEM bytes/text."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise DsseError(f"expected an Ed25519 private key, got {type(key).__name__}")
    return key


def public_key_from_pem(data: bytes | str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes/text."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise DsseError(f"expected an Ed25519 public key, got {type(key).__name__}")
    return key


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    """Read and parse an Ed25519 private key PEM file."""
    return private_key_from_pem(Path(path).read_bytes())


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    """Read and parse an Ed25519 public key PEM file."""
    return public_key_from_pem(Path(path).read_bytes())


def _key_id(public_key: Ed25519PublicKey) -> str:
    """Key identifier: sha256 of the raw 32-byte public key, hex.

    The estate identifies keys by content, not by filename — filenames move;
    bytes don't (doctrine rule 1 applied to keys).
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def sign_bytes(
    payload: bytes,
    payload_type: str,
    key: Ed25519PrivateKey,
    *,
    keyid: str | None = None,
) -> dict[str, Any]:
    """Produce a DSSE envelope carrying one Ed25519 signature over the PAE.

    ``keyid`` defaults to the sha256 of the public key bytes (see _key_id);
    callers may override it to match an external key registry. The payload is
    embedded verbatim (base64) so the envelope is self-contained: anyone can
    verify authenticity *and* read the content from one file.
    """
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("key must be an Ed25519PrivateKey")
    payload_type_bytes = payload_type.encode("utf-8")
    signature = key.sign(pae(payload_type_bytes, payload))
    if keyid is None:
        keyid = _key_id(key.public_key())
    return {
        "payload": _b64e(payload),
        "payloadType": payload_type,
        "signatures": [{"keyid": keyid, "sig": _b64e(signature)}],
    }


def unwrap_envelope(envelope: Mapping[str, Any]) -> tuple[bytes, str, list[dict[str, Any]]]:
    """Structurally validate an envelope and return (payload, type, signatures).

    Raises DsseError on missing keys, non-string payloadType, invalid base64,
    or a non-list signatures member. This checks *shape only* — it never
    asserts the signatures verify; that is :func:`verify_envelope`'s job.
    """
    if not isinstance(envelope, Mapping):
        raise DsseError(f"envelope must be a mapping, got {type(envelope).__name__}")
    payload_type = envelope.get("payloadType")
    if not isinstance(payload_type, str) or not payload_type:
        raise DsseError("envelope payloadType must be a non-empty string")
    payload = _b64d(envelope.get("payload"), "payload")  # type: ignore[arg-type]
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list):
        raise DsseError("envelope signatures must be a list")
    return payload, payload_type, signatures


def verify_envelope(envelope: Mapping[str, Any], pubkey: Ed25519PublicKey) -> bool:
    """True iff at least one signature on *envelope* verifies under *pubkey*.

    Verification is over ``PAE(payloadType, payload)`` exactly as produced by
    the embedded (type, payload) pair — after strict base64 decode and
    structural checks, so a mangled envelope returns False rather than
    exploding inside the verifier. Any malformed signature entry, wrong
    algorithm binding, or cryptographic failure simply fails closed (False);
    the caller's question is boolean: "is this authentic under this key?"
    """
    if not isinstance(pubkey, Ed25519PublicKey):
        raise TypeError("pubkey must be an Ed25519PublicKey")
    try:
        payload, payload_type, signatures = unwrap_envelope(envelope)
    except DsseError:
        return False
    message = pae(payload_type.encode("utf-8"), payload)
    for entry in signatures:
        if not isinstance(entry, Mapping):
            continue
        sig_b64 = entry.get("sig")
        if not isinstance(sig_b64, str):
            continue
        try:
            signature = base64.b64decode(sig_b64.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError):
            continue
        try:
            pubkey.verify(signature, message)
        except (InvalidSignature, ValueError, TypeError):
            # Bad signature bytes or a non-matching signature: fail closed by
            # trying the remaining entries; verification is boolean, not diagnostic.
            continue
        return True
    return False


def statement(
    subjects: Iterable[tuple[str, str]] | None = None,
    predicate_type: str = "",
    predicate: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an in-toto Statement v1 document.

    ``subjects`` is an iterable of ``(name, sha256hex)`` pairs — names are
    labels, digests are identity; the Statement pins each subject to the
    sha256 of its bytes. Low ceremony by design: a Statement you hesitate to
    produce is a Statement that doesn't get produced.
    """
    subject_list: list[dict[str, Any]] = []
    if subjects:
        for name, sha256hex in subjects:
            subject_list.append({"name": name, "digest": {"sha256": sha256hex}})
    return {
        "_type": INTOTO_STATEMENT_V1,
        "subject": subject_list,
        "predicateType": predicate_type,
        "predicate": dict(predicate) if predicate else {},
    }


def extract_subjects(statement_doc: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
    """Return the subject list of an in-toto Statement, or raise DsseError."""
    if statement_doc.get("_type") != INTOTO_STATEMENT_V1:
        raise DsseError(
            f"not an in-toto Statement v1 document: _type={statement_doc.get('_type')!r}"
        )
    subjects = statement_doc.get("subject")
    if not isinstance(subjects, list):
        raise DsseError("in-toto Statement 'subject' must be a list")
    return subjects
