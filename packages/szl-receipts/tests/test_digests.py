"""Digest doctrine tests: bytes, not names — and constant-memory files."""

import hashlib
import os

import pytest
from szl_receipts.digests import sha256_bytes, sha256_file, sha256_hex


def test_sha256_bytes_matches_hashlib():
    data = b"the estate runs on bytes"
    assert sha256_bytes(data) == hashlib.sha256(data).digest()
    assert sha256_hex(data) == hashlib.sha256(data).hexdigest()


def test_sha256_file_multimegabyte_matches_reference(tmp_path):
    # > 1 chunk of the default 1 MiB size, and not a multiple of it, so the
    # chunking loop's boundary handling is exercised for real.
    size = 3 * (1 << 20) + 12345
    rng = os.urandom
    path = tmp_path / "big-artifact.bin"
    path.write_bytes(rng(size))
    assert sha256_file(path) == hashlib.sha256(path.read_bytes()).hexdigest()


def test_sha256_file_small_chunk_size(tmp_path):
    path = tmp_path / "artifact.bin"
    path.write_bytes(os.urandom(100_000))
    assert sha256_file(path, chunk_size=997) == hashlib.sha256(path.read_bytes()).hexdigest()


def test_sha256_file_missing_raises():
    with pytest.raises(OSError):
        sha256_file("/nonexistent/definitely/not/here.bin")


def test_sha256_file_rejects_zero_chunk(tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(b"x")
    with pytest.raises(ValueError, match="chunk_size"):
        sha256_file(path, chunk_size=0)


def test_hashing_a_name_is_not_hashing_the_file(tmp_path):
    # The doctrine violation, demonstrated: the digest of a path STRING is
    # unrelated to the digest of the file's BYTES. Any code conflating them
    # is lying about what it verified.
    path = tmp_path / "payload.bin"
    path.write_bytes(b"real bytes")
    assert sha256_file(path) != sha256_hex(str(path).encode())
