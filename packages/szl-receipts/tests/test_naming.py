"""Honest-naming tests: an empty signatures array is not a signature."""

import json

import pytest
from szl_receipts.dsse import sign_bytes
from szl_receipts.naming import (
    NamingError,
    classify_unsigned_name,
    signed_name,
    unsigned_name,
    verify_honest_naming,
    write_envelope,
)


def _signed_envelope(keypair):
    priv, _ = keypair
    return sign_bytes(b"{}", "application/json", priv)


def _unsigned_envelope():
    return {"payload": "e30=", "payloadType": "application/json", "signatures": []}


class TestWriteHonestNames:
    def test_signed_envelope_gets_signed_name(self, tmp_path, keypair):
        written = write_envelope(tmp_path / "report", _signed_envelope(keypair))
        assert written.name == "report.json"
        assert json.loads(written.read_text())["signatures"]

    def test_unsigned_envelope_gets_unsigned_name(self, tmp_path):
        written = write_envelope(tmp_path / "report", _unsigned_envelope())
        assert written.name == "report.unsigned.json"
        assert json.loads(written.read_text())["signatures"] == []

    def test_path_helpers(self):
        assert signed_name("/a/b") == "/a/b.json"
        assert unsigned_name("/a/b") == "/a/b.unsigned.json"
        assert classify_unsigned_name("x.unsigned.json") is True
        assert classify_unsigned_name("x.json") is False

    def test_no_overwrite_when_disabled(self, tmp_path):
        write_envelope(tmp_path / "report", _unsigned_envelope())
        with pytest.raises(NamingError, match="overwrite"):
            write_envelope(tmp_path / "report", _unsigned_envelope(), overwrite=False)


class TestVerifySideEnforcement:
    def test_honest_signed_file_passes(self, tmp_path, keypair):
        written = write_envelope(tmp_path / "report", _signed_envelope(keypair))
        assert verify_honest_naming(written) == written

    def test_honest_unsigned_file_passes(self, tmp_path):
        written = write_envelope(tmp_path / "report", _unsigned_envelope())
        assert verify_honest_naming(written) == written

    def test_rename_unsigned_to_signed_is_detected(self, tmp_path):
        # The forgery this module exists for: take an artifact nobody signed
        # and rename it so it *looks* signed.
        written = write_envelope(tmp_path / "report", _unsigned_envelope())
        forged = written.with_name("report.json")
        written.rename(forged)
        with pytest.raises(NamingError, match="empty"):
            verify_honest_naming(forged)

    def test_rename_signed_to_unsigned_is_detected(self, tmp_path, keypair):
        written = write_envelope(tmp_path / "report", _signed_envelope(keypair))
        disguised = written.with_name("report.unsigned.json")
        written.rename(disguised)
        with pytest.raises(NamingError, match="tampered rename"):
            verify_honest_naming(disguised)

    def test_tampered_content_is_detected_without_rename(self, tmp_path):
        # Strip the signatures in place; the honest name now lies.
        path = tmp_path / "report.json"
        envelope = _unsigned_envelope()
        path.write_text(json.dumps(envelope))
        with pytest.raises(NamingError):
            verify_honest_naming(path)

    def test_missing_signatures_key_is_corruption_not_unsigned(self, tmp_path):
        path = tmp_path / "report.unsigned.json"
        path.write_text(json.dumps({"payload": "e30=", "payloadType": "application/json"}))
        with pytest.raises(NamingError, match="no 'signatures' key"):
            verify_honest_naming(path)

    def test_unreadable_file_reports_error(self, tmp_path):
        with pytest.raises(NamingError, match="cannot read envelope"):
            verify_honest_naming(tmp_path / "nope.json")
