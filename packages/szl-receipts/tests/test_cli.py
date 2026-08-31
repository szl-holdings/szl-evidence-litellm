"""CLI end-to-end tests: real subprocesses, real files, the 0/2/3 contract.

The CLI is the estate's operational surface, so these tests exercise it the
way operators and CI do — as a separate process — asserting exit codes and
both human and JSON output. No mocking: a mocked CLI test proves nothing
about the tool an auditor runs.
"""

import base64
import json
import subprocess
import sys

from szl_receipts.jcs import jcs_canon_json_text
from szl_receipts.receipt import verify_receipt


def run_cli(*argv):
    # argv is built from literals in this file; running our own CLI as a real
    # subprocess is the point of this suite.
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "szl_receipts.cli", *argv],
        capture_output=True,
        text=True,
        timeout=60,
    )


class TestHelp:
    def test_help_exits_zero(self):
        result = run_cli("--help")
        assert result.returncode == 0
        assert "canon" in result.stdout

    def test_no_args_is_usage_error_3(self):
        assert run_cli().returncode == 3

    def test_unknown_command_is_usage_error_3(self):
        assert run_cli("frobnicate").returncode == 3


class TestCanon:
    def test_canon_writes_canonical_bytes_and_prints_sha256(self, tmp_path):
        src = tmp_path / "doc.json"
        src.write_text(' { "b" : 2 , "a" : [1, 2.5] } ')
        result = run_cli("canon", str(src))
        assert result.returncode == 0, result.stderr
        canon_path = tmp_path / "doc.json.canon.json"
        assert canon_path.read_bytes() == b'{"a":[1,2.5],"b":2}'
        import hashlib

        digest = hashlib.sha256(canon_path.read_bytes()).hexdigest()
        assert digest in result.stdout

    def test_canon_json_mode(self, tmp_path):
        src = tmp_path / "doc.json"
        src.write_text('{"z": "\u00e9", "m": 1e21}')
        result = run_cli("canon", str(src), "--json")
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["command"] == "canon"
        assert payload["canonical_bytes"] == len(
            jcs_canon_json_text(src.read_text()).encode()
        )

    def test_canon_missing_file_is_error_3(self, tmp_path):
        result = run_cli("canon", str(tmp_path / "nope.json"))
        assert result.returncode == 3

    def test_canon_invalid_json_is_error_3(self, tmp_path):
        src = tmp_path / "bad.json"
        src.write_text("{not json")
        result = run_cli("canon", str(src))
        assert result.returncode == 3


class TestKeygenSignVerify:
    def _keygen(self, tmp_path, name="operator"):
        prefix = tmp_path / name
        result = run_cli("keygen", "--out", str(prefix))
        assert result.returncode == 0, result.stderr
        return prefix

    def test_keygen_creates_keypair(self, tmp_path):
        prefix = self._keygen(tmp_path)
        assert (tmp_path / "operator.pem").exists()
        assert (tmp_path / "operator.pub.pem").exists()
        # Second run without --force refuses (exit 3: the operator must say it).
        result = run_cli("keygen", "--out", str(prefix))
        assert result.returncode == 3
        # --force is the deliberate rotation path.
        result = run_cli("keygen", "--out", str(prefix), "--force")
        assert result.returncode == 0

    def test_sign_then_verify_round_trip(self, tmp_path):
        self._keygen(tmp_path)
        payload = tmp_path / "payload.json"
        payload.write_text('{"receipt":"body"}')
        signed = run_cli("sign", str(payload), "--key", str(tmp_path / "operator.pem"))
        assert signed.returncode == 0, signed.stderr
        envelope = tmp_path / "payload.json.envelope.json"
        assert envelope.exists()
        verified = run_cli(
            "verify", str(envelope), "--pub", str(tmp_path / "operator.pub.pem")
        )
        assert verified.returncode == 0, verified.stderr + verified.stdout
        assert "signature verified" in verified.stdout

    def test_verify_without_pub_checks_structure_only(self, tmp_path):
        self._keygen(tmp_path)
        payload = tmp_path / "payload.json"
        payload.write_text("{}")
        run_cli("sign", str(payload), "--key", str(tmp_path / "operator.pem"))
        result = run_cli("verify", str(tmp_path / "payload.json.envelope.json"))
        assert result.returncode == 0
        assert "not checked" in result.stdout

    def test_tampered_envelope_exits_2(self, tmp_path):
        self._keygen(tmp_path)
        payload = tmp_path / "payload.json"
        payload.write_text('{"gold":true}')
        run_cli("sign", str(payload), "--key", str(tmp_path / "operator.pem"))
        envelope_path = tmp_path / "payload.json.envelope.json"
        envelope = json.loads(envelope_path.read_text())
        raw = bytearray(base64.b64decode(envelope["payload"]))
        raw[0] ^= 0x01
        envelope["payload"] = base64.b64encode(bytes(raw)).decode()
        envelope_path.write_text(json.dumps(envelope))
        result = run_cli(
            "verify", str(envelope_path), "--pub", str(tmp_path / "operator.pub.pem")
        )
        assert result.returncode == 2, result.stdout + result.stderr

    def test_wrong_pub_key_exits_2(self, tmp_path):
        self._keygen(tmp_path)
        self._keygen(tmp_path, name="other")
        payload = tmp_path / "payload.json"
        payload.write_text("{}")
        run_cli("sign", str(payload), "--key", str(tmp_path / "operator.pem"))
        result = run_cli(
            "verify",
            str(tmp_path / "payload.json.envelope.json"),
            "--pub",
            str(tmp_path / "other.pub.pem"),
        )
        assert result.returncode == 2

    def test_dishonest_name_exits_2(self, tmp_path):
        # An unsigned envelope renamed to look signed must fail verification.
        envelope = tmp_path / "looks-signed.json"
        envelope.write_text(
            json.dumps({"payload": "e30=", "payloadType": "application/json", "signatures": []})
        )
        result = run_cli("verify", str(envelope))
        assert result.returncode == 2

    def test_missing_key_is_error_3(self, tmp_path):
        payload = tmp_path / "payload.json"
        payload.write_text("{}")
        result = run_cli("sign", str(payload), "--key", str(tmp_path / "nope.pem"))
        assert result.returncode == 3


class TestChainVerify:
    def _write_chain(self, tmp_path, make_receipt, n=5, break_it=None):
        from szl_receipts.chain import append

        chain = []
        for _ in range(n):
            append(chain, make_receipt())
        if break_it == "tamper":
            chain[2]["receipt"]["actor"] = "mallory"
        chain_dir = tmp_path / "chain"
        chain_dir.mkdir()
        for entry in chain:
            (chain_dir / f"entry-{entry['seq']:03d}.json").write_text(json.dumps(entry))
        return chain, chain_dir

    def test_valid_chain_exits_0(self, tmp_path, make_receipt):
        chain, chain_dir = self._write_chain(tmp_path, make_receipt)
        result = run_cli("chain-verify", str(chain_dir))
        assert result.returncode == 0, result.stdout + result.stderr
        assert f"entries: {len(chain)}" in result.stdout

    def test_valid_chain_with_anchor_exits_0(self, tmp_path, make_receipt):
        chain, chain_dir = self._write_chain(tmp_path, make_receipt)
        result = run_cli(
            "chain-verify",
            str(chain_dir),
            "--expected-entries",
            str(len(chain)),
            "--expected-head",
            chain[-1]["entry_digest"],
        )
        assert result.returncode == 0

    def test_tampered_chain_exits_2(self, tmp_path, make_receipt):
        _, chain_dir = self._write_chain(tmp_path, make_receipt, break_it="tamper")
        result = run_cli("chain-verify", str(chain_dir))
        assert result.returncode == 2

    def test_truncated_chain_with_anchor_exits_2(self, tmp_path, make_receipt):
        chain, chain_dir = self._write_chain(tmp_path, make_receipt)
        (chain_dir / f"entry-{len(chain):03d}.json").unlink()
        result = run_cli("chain-verify", str(chain_dir), "--expected-entries", str(len(chain)))
        assert result.returncode == 2

    def test_missing_dir_is_error_3(self, tmp_path):
        assert run_cli("chain-verify", str(tmp_path / "nope")).returncode == 3

    def test_chain_verify_json_mode(self, tmp_path, make_receipt):
        chain, chain_dir = self._write_chain(tmp_path, make_receipt)
        result = run_cli("chain-verify", str(chain_dir), "--json")
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert payload["ok"] is True
        assert payload["length"] == len(chain)
        assert payload["head"] == chain[-1]["entry_digest"]


class TestEmitReceipt:
    def test_canon_emits_valid_self_receipt(self, tmp_path):
        src = tmp_path / "doc.json"
        src.write_text('{"a":1}')
        receipt_path = tmp_path / "canon.receipt.json"
        result = run_cli("canon", str(src), "--emit-receipt", str(receipt_path))
        assert result.returncode == 0, result.stderr
        receipt = json.loads(receipt_path.read_text())
        assert verify_receipt(receipt) == []
        assert receipt["action"] == "canon"
        assert receipt["decision"]["outcome"] == "PASS"

    def test_failed_verify_emits_fail_receipt(self, tmp_path):
        envelope = tmp_path / "forged.json"
        envelope.write_text(
            json.dumps({"payload": "e30=", "payloadType": "application/json", "signatures": []})
        )
        receipt_path = tmp_path / "verify.receipt.json"
        result = run_cli("verify", str(envelope), "--emit-receipt", str(receipt_path))
        assert result.returncode == 2
        receipt = json.loads(receipt_path.read_text())
        assert verify_receipt(receipt) == []
        assert receipt["decision"]["outcome"] == "FAIL"
