"""szl-receipts command line interface — the estate's trust operations desk.

    python -m szl_receipts.cli canon FILE
    python -m szl_receipts.cli keygen --out PREFIX
    python -m szl_receipts.cli sign FILE --key PRIV.pem [--out PATH_BASE]
    python -m szl_receipts.cli verify FILE [--pub PUB.pem]
    python -m szl_receipts.cli chain-verify DIR [--expected-entries N] [--expected-head HEX]

Exit-code contract (stable, scriptable, load-bearing for CI gates):

    0  success / verification passed
    2  verification failed / drift detected (tamper, dishonest naming,
       chain break) — the artifact is *reachable* but *untrustworthy*
    3  usage or I/O error (missing file, bad JSON on input, unwritable
       output, bad arguments) — the operator should fix the invocation

argparse normally exits 2 on usage errors; this CLI reserves 2 for
verification failure, so the parser subclass below remaps usage errors to 3.
Distinguishing "you called it wrong" (3) from "the artifact lied" (2) is the
difference between a retry and an incident.

Every command supports ``--json`` (machine-readable stdout) and
``--emit-receipt PATH`` (write a GovernedAction/v1 receipt of the command's
own outcome — the estate receipts its own tooling, so the verifier's work is
itself auditable).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, NoReturn

from . import __version__
from .chain import verify_chain
from .digests import sha256_file, sha256_hex
from .dsse import (
    DsseError,
    load_private_key,
    load_public_key,
    sign_bytes,
    unwrap_envelope,
    verify_envelope,
)
from .dsse import (
    keygen as dsse_keygen,
)
from .jcs import IJsonError, jcs_canon_bytes, jcs_canon_json_text
from .naming import NamingError, verify_honest_naming, write_envelope
from .outcome import Outcome
from .receipt import GOVERNED_ACTION_V1, build_receipt, verify_receipt

EXIT_OK = 0
EXIT_VERIFY_FAILED = 2
EXIT_USAGE_ERROR = 3

#: Policy identity for self-receipts emitted by this CLI. The digest is the
#: sha256 of the canonical description of the command's contract, so a
#: changed exit contract or version produces a different policy digest.
_CLI_POLICY_ID = "szl.receipts.cli"
_PAYLOAD_TYPE_JSON = "application/json"


class _ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors exit 3, per the CLI contract."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE_ERROR, f"{self.prog}: error: {message}\n")


def _die(message: str) -> int:
    """Report a usage/I/O error and return the contract's exit code 3."""
    print(f"error: {message}", file=sys.stderr)
    return EXIT_USAGE_ERROR


def _policy_digest(command: str) -> str:
    contract = {
        "tool": "szl-receipts",
        "version": __version__,
        "command": command,
        "exit_codes": {
            "ok": EXIT_OK,
            "verify_failed": EXIT_VERIFY_FAILED,
            "error": EXIT_USAGE_ERROR,
        },
    }
    return sha256_hex(jcs_canon_bytes(contract))


def _emit_receipt(
    args: argparse.Namespace,
    *,
    action: str,
    outcome: Outcome,
    rationale: str,
    subjects: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
) -> str | None:
    """Write a GovernedAction/v1 self-receipt when --emit-receipt was given.

    The emitted receipt is validated before writing; an internal inconsistency
    here is a bug, so a failure raises rather than silently skipping.
    """
    path = getattr(args, "emit_receipt", None)
    if not path:
        return None
    receipt = build_receipt(
        actor=f"szl-receipts-cli/{__version__}",
        action=action,
        policy={
            "id": _CLI_POLICY_ID,
            "version": __version__,
            "digest_sha256": _policy_digest(action),
        },
        outcome=outcome,
        rationale=rationale,
        subjects=subjects,
        evidence=evidence,
    )
    findings = verify_receipt(receipt)
    if findings:  # pragma: no cover - guards against our own regressions
        raise RuntimeError(f"self-receipt failed validation: {findings}")
    out_path = Path(path)
    out_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(out_path)


def _report(args: argparse.Namespace, result: dict[str, Any], human_lines: list[str]) -> None:
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for line in human_lines:
            print(line)


def _file_subject(path: Path) -> dict[str, Any]:
    """Subject entry hashing the file's bytes — doctrine rule 1."""
    return {"name": str(path), "sha256": sha256_file(path)}


# --------------------------------------------------------------------------
# canon
# --------------------------------------------------------------------------


def _cmd_canon(args: argparse.Namespace) -> int:
    src = Path(args.file)
    try:
        text = src.read_text(encoding="utf-8")
    except OSError as exc:
        return _die(f"canon: cannot read {src}: {exc}")
    try:
        canon_text = jcs_canon_json_text(text)
    except (json.JSONDecodeError, IJsonError, TypeError) as exc:
        return _die(f"canon: {src} is not canonicalizable JSON: {exc}")
    canon_bytes = canon_text.encode("utf-8", "surrogatepass")
    digest = sha256_hex(canon_bytes)
    canon_path = src.with_name(src.name + ".canon.json")
    try:
        canon_path.write_bytes(canon_bytes)
    except OSError as exc:
        return _die(f"canon: cannot write {canon_path}: {exc}")
    result = {
        "command": "canon",
        "file": str(src),
        "canon_path": str(canon_path),
        "sha256": digest,
        "canonical_bytes": len(canon_bytes),
        "receipt_type": GOVERNED_ACTION_V1,
    }
    receipt_path = _emit_receipt(
        args,
        action="canon",
        outcome=Outcome.PASS,
        rationale=(
            f"canonicalized {src.name} to {len(canon_bytes)} RFC 8785 bytes "
            f"(sha256 {digest[:16]}…)"
        ),
        subjects=[_file_subject(src), _file_subject(canon_path)],
        evidence=[],
    )
    if receipt_path:
        result["self_receipt"] = receipt_path
    _report(args, result, [f"sha256 {digest}", f"wrote {canon_path}"])
    return EXIT_OK


# --------------------------------------------------------------------------
# keygen
# --------------------------------------------------------------------------


def _cmd_keygen(args: argparse.Namespace) -> int:
    prefix = Path(args.out)
    priv_path = prefix.with_suffix(".pem")
    pub_path = prefix.with_name(prefix.name + ".pub.pem")
    if not args.force and (priv_path.exists() or pub_path.exists()):
        return _die(
            f"keygen: {priv_path} (or its public key) already exists; pass --force to rotate"
        )
    if args.force:
        # Deliberate rotation: remove both so dsse.keygen's no-overwrite
        # guard can't trip on a stale private key.
        priv_path.unlink(missing_ok=True)
        pub_path.unlink(missing_ok=True)
    try:
        priv_written, pub_written = dsse_keygen(prefix)
    except (OSError, DsseError) as exc:
        return _die(f"keygen: {exc}")
    result = {
        "command": "keygen",
        "private_key": str(priv_written),
        "public_key": str(pub_written),
        "algorithm": "Ed25519",
    }
    receipt_path = _emit_receipt(
        args,
        action="keygen",
        outcome=Outcome.PASS,
        rationale=f"generated Ed25519 keypair at {prefix}",
        subjects=[_file_subject(pub_written)],
        evidence=[],
    )
    if receipt_path:
        result["self_receipt"] = receipt_path
    _report(
        args,
        result,
        [
            f"private key: {priv_written} (mode 0600 — guard it)",
            f"public key:  {pub_written}",
        ],
    )
    return EXIT_OK


# --------------------------------------------------------------------------
# sign
# --------------------------------------------------------------------------


def _cmd_sign(args: argparse.Namespace) -> int:
    src = Path(args.file)
    try:
        payload = src.read_bytes()
    except OSError as exc:
        return _die(f"sign: cannot read {src}: {exc}")
    try:
        key = load_private_key(args.key)
    except (OSError, ValueError, DsseError) as exc:
        return _die(f"sign: cannot load private key {args.key}: {exc}")
    payload_type = args.payload_type
    envelope = sign_bytes(payload, payload_type, key)
    base = args.out if args.out is not None else str(src) + ".envelope"
    try:
        written = write_envelope(base, envelope)
    except (OSError, NamingError) as exc:
        return _die(f"sign: cannot write envelope: {exc}")
    payload_digest = sha256_hex(payload)
    result = {
        "command": "sign",
        "file": str(src),
        "envelope": str(written),
        "payload_sha256": payload_digest,
        "payload_type": payload_type,
        "signatures": len(envelope["signatures"]),
        "keyid": envelope["signatures"][0]["keyid"],
    }
    receipt_path = _emit_receipt(
        args,
        action="sign",
        outcome=Outcome.PASS,
        rationale=(
            f"signed {src.name} (sha256 {payload_digest[:16]}…) as DSSE envelope "
            f"{written.name}"
        ),
        subjects=[_file_subject(src), _file_subject(written)],
        evidence=[],
    )
    if receipt_path:
        result["self_receipt"] = receipt_path
    _report(
        args,
        result,
        [f"payload sha256 {payload_digest}", f"wrote {written} ({result['signatures']} signature)"],
    )
    return EXIT_OK


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------


def _verify_failure(
    args: argparse.Namespace,
    src: Path,
    stage: str,
    detail: str,
) -> int:
    """A reachable-but-untrustworthy artifact: report, receipt FAIL, exit 2."""
    result = {"command": "verify", "file": str(src), "ok": False, "stage": stage, "detail": detail}
    subjects: list[dict[str, Any]] = []
    try:
        subjects.append(_file_subject(src))
    except OSError:
        pass
    receipt_path = _emit_receipt(
        args,
        action="verify",
        outcome=Outcome.FAIL,
        rationale=f"{stage}: {detail}",
        subjects=subjects,
        evidence=[{"uri": src.as_posix()}],
    )
    if receipt_path:
        result["self_receipt"] = receipt_path
    _report(args, result, [f"FAIL [{stage}] {detail}"])
    return EXIT_VERIFY_FAILED


def _cmd_verify(args: argparse.Namespace) -> int:
    src = Path(args.file)
    try:
        envelope = json.loads(src.read_text(encoding="utf-8"))
    except OSError as exc:
        return _die(f"verify: cannot read {src}: {exc}")
    except json.JSONDecodeError as exc:
        return _die(f"verify: {src} is not JSON: {exc}")
    if not isinstance(envelope, dict):
        return _die(f"verify: {src} must contain a JSON object envelope")

    # Stage 1 — honest naming: the filename must not lie about signatures.
    try:
        verify_honest_naming(src, envelope)
    except NamingError as exc:
        return _verify_failure(args, src, "naming", str(exc))

    # Stage 2 — structure: payload/payloadType/signatures shape and base64.
    try:
        payload, payload_type, signatures = unwrap_envelope(envelope)
    except DsseError as exc:
        return _verify_failure(args, src, "structure", str(exc))

    # Stage 3 — cryptographic verification (only when a public key is given).
    signature_result: bool | None = None
    keyid: str | None = None
    if args.pub is not None:
        try:
            pubkey = load_public_key(args.pub)
        except (OSError, ValueError, DsseError) as exc:
            return _die(f"verify: cannot load public key {args.pub}: {exc}")
        signature_result = verify_envelope(envelope, pubkey)
        keyids = [e.get("keyid") for e in signatures if isinstance(e, dict)]
        keyid = next((k for k in keyids if isinstance(k, str)), None)
        if not signature_result:
            return _verify_failure(
                args, src, "signature", "no signature verifies under the given public key"
            )

    payload_digest = sha256_hex(payload)
    result: dict[str, Any] = {
        "command": "verify",
        "file": str(src),
        "ok": True,
        "naming": "ok",
        "structure": "ok",
        "signature": signature_result,  # None when --pub omitted: structure-only
        "payload_type": payload_type,
        "payload_sha256": payload_digest,
        "signatures": len(signatures),
        "keyid": keyid,
    }
    receipt_path = _emit_receipt(
        args,
        action="verify",
        outcome=Outcome.PASS,
        rationale=(
            f"envelope {src.name} naming+structure sound"
            + (
                f", signature verifies (keyid {keyid})"
                if signature_result
                else ", signature check skipped (no --pub)"
            )
        ),
        subjects=[_file_subject(src)],
        evidence=[],
    )
    if receipt_path:
        result["self_receipt"] = receipt_path
    human = [
        f"naming ok, structure ok — payload sha256 {payload_digest} "
        f"({len(signatures)} signature)"
    ]
    human.append(
        "signature verified" if signature_result else "signature not checked (pass --pub)"
    )
    _report(args, result, human)
    return EXIT_OK


# --------------------------------------------------------------------------
# chain-verify
# --------------------------------------------------------------------------


def _cmd_chain_verify(args: argparse.Namespace) -> int:
    root = Path(args.dir)
    if not root.is_dir():
        return _die(f"chain-verify: {root} is not a directory")
    files = sorted(p for p in root.glob("*.json") if p.is_file())
    entries: list[Any] = []
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return _die(f"chain-verify: cannot load {path}: {exc}")
        if isinstance(data, list):
            entries.extend(data)
        elif isinstance(data, dict):
            entries.append(data)
        else:
            return _die(f"chain-verify: {path} must contain an entry object or list of entries")
    report = verify_chain(
        entries,
        expected_entries=args.expected_entries,
        expected_head=args.expected_head,
    )
    result: dict[str, Any] = {
        "command": "chain-verify",
        "dir": str(root),
        "files": [p.name for p in files],
        **report.to_dict(),
    }
    outcome = Outcome.PASS if report.ok else Outcome.FAIL
    receipt_path = _emit_receipt(
        args,
        action="chain-verify",
        outcome=outcome,
        rationale=f"{report.length} entries, {len(report.findings)} findings in {root}",
        subjects=[_file_subject(p) for p in files],
        evidence=[],
    )
    if receipt_path:
        result["self_receipt"] = receipt_path
    human = [
        f"entries: {report.length}",
        f"head: {report.head}",
        f"ok: {report.ok}",
    ]
    for finding in report.findings:
        human.append(f"  [{finding['code']}] {finding['message']}")
    _report(args, result, human)
    return EXIT_OK if report.ok else EXIT_VERIFY_FAILED


# --------------------------------------------------------------------------
# parser / entry point
# --------------------------------------------------------------------------


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    parser.add_argument(
        "--emit-receipt",
        metavar="PATH",
        help="write a GovernedAction/v1 self-receipt of this command's outcome",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="szl-receipts",
        description=(
            "Cryptographic receipt operations for the SZL estate. "
            "Exit codes: 0 ok, 2 verification failed/drift, 3 usage/io error."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(
        dest="command", required=True, metavar="COMMAND", parser_class=_ArgumentParser
    )

    p = sub.add_parser("canon", help="canonicalize a JSON file (RFC 8785), print its sha256")
    p.add_argument("file", help="JSON file to canonicalize; writes FILE.canon.json")
    p.set_defaults(func=_cmd_canon)
    _add_common(p)

    p = sub.add_parser("keygen", help="generate an Ed25519 keypair: PREFIX.pem / PREFIX.pub.pem")
    p.add_argument("--out", required=True, metavar="PREFIX", help="output path prefix")
    p.add_argument("--force", action="store_true", help="overwrite existing keys (rotation)")
    p.set_defaults(func=_cmd_keygen)
    _add_common(p)

    p = sub.add_parser("sign", help="sign a file into a DSSE envelope (Ed25519)")
    p.add_argument("file", help="payload file (hashed bytes, not its name)")
    p.add_argument("--key", required=True, metavar="PRIV.pem", help="Ed25519 private key PEM")
    p.add_argument(
        "--out",
        metavar="PATH_BASE",
        help="envelope path base (default: FILE.envelope; suffix follows honest naming)",
    )
    p.add_argument(
        "--payload-type",
        default=_PAYLOAD_TYPE_JSON,
        help=f"DSSE payloadType (default: {_PAYLOAD_TYPE_JSON})",
    )
    p.set_defaults(func=_cmd_sign)
    _add_common(p)

    p = sub.add_parser("verify", help="verify a DSSE envelope: naming, structure, signature")
    p.add_argument("file", help="envelope file (*.json or *.unsigned.json)")
    p.add_argument(
        "--pub",
        metavar="PUB.pem",
        help="Ed25519 public key PEM; without it only naming+structure are checked",
    )
    p.set_defaults(func=_cmd_verify)
    _add_common(p)

    p = sub.add_parser("chain-verify", help="verify a directory of receipt-chain entries")
    p.add_argument("dir", help="directory of *.json chain entries (each an entry or a list)")
    p.add_argument(
        "--expected-entries",
        type=int,
        default=None,
        help="external anchor: number of entries the chain must hold",
    )
    p.add_argument(
        "--expected-head",
        default=None,
        help="external anchor: expected digest of the final entry",
    )
    p.set_defaults(func=_cmd_chain_verify)
    _add_common(p)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
