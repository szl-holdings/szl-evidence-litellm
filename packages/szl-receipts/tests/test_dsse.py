"""DSSE envelope tests: round trips, tamper detection, and PAE attacks.

The PAE collision test is the point of the encoding: if a (type, payload)
pair could be repartitioned into a different pair with the same bytes, a
signature over "a receipt" could be replayed as "an authorization" with
different boundary semantics. Length-prefixing makes that provably
impossible, and the test attempts it directly.
"""

import base64
import json

import pytest
from szl_receipts.dsse import (
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

PAYLOAD = b'{"hello":"estate"}'
PTYPE = "application/vnd.szl.test+json"


class TestPae:
    def test_pae_layout(self):
        assert pae(b"a", b"bc") == b"DSSEv1 1 a 2 bc"
        assert pae(b"", b"") == b"DSSEv1 0  0 "

    def test_pae_lengths_are_decimal_ascii_of_bytes(self):
        payload = "héllo".encode()  # 6 bytes, 5 characters
        encoded = pae(b"t", payload)
        assert encoded == b"DSSEv1 1 t 6 " + payload

    def test_pae_prefix_collision_resistance(self):
        # Attempt the type-confusion attack: can (t1,p1) and (t2,p2) with
        # t1 != t2 share an encoding? Length-prefixing fixes every boundary,
        # so any brute-force pair over a small alphabet must differ.
        alphabet = [b"", b"a", b" ", b"1", b"ab", b"1 ", b"a b"]
        encodings = {}
        for t in alphabet:
            for p in alphabet:
                enc = pae(t, p)
                if enc in encodings and encodings[enc] != (t, p):
                    pytest.fail(
                        f"PAE collision: {(t, p)} and {encodings[enc]} encode identically"
                    )
                encodings[enc] = (t, p)
        # And the specific adversarial construction: stuffing a separator into
        # the TYPE still cannot shift the payload boundary, because the type's
        # length prefix accounts for the stuffed bytes.
        assert pae(b"a 1 x", b"y") != pae(b"a", b"1 x y")
        assert pae(b"ab", b"c") != pae(b"a", b"bc")


class TestSignVerify:
    def test_round_trip(self, keypair):
        priv, pub = keypair
        envelope = sign_bytes(PAYLOAD, PTYPE, priv)
        assert envelope["payloadType"] == PTYPE
        assert base64.b64decode(envelope["payload"]) == PAYLOAD
        assert len(envelope["signatures"]) == 1
        assert verify_envelope(envelope, pub) is True

    def test_bitflip_in_payload_breaks_verification(self, keypair):
        priv, pub = keypair
        envelope = sign_bytes(PAYLOAD, PTYPE, priv)
        raw = bytearray(base64.b64decode(envelope["payload"]))
        raw[0] ^= 0x01  # one bit is all it takes
        envelope["payload"] = base64.b64encode(bytes(raw)).decode()
        assert verify_envelope(envelope, pub) is False

    def test_bitflip_in_signature_breaks_verification(self, keypair):
        priv, pub = keypair
        envelope = sign_bytes(PAYLOAD, PTYPE, priv)
        sig = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
        sig[31] ^= 0xFF
        envelope["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
        assert verify_envelope(envelope, pub) is False

    def test_wrong_key_fails_closed(self, keypair):
        priv, _ = keypair
        _, other_pub = generate_keypair()
        envelope = sign_bytes(PAYLOAD, PTYPE, priv)
        assert verify_envelope(envelope, other_pub) is False

    def test_signed_as_one_type_never_verifies_as_another(self, keypair):
        # The attack PAE exists to stop: take an envelope signed for one
        # payloadType and relabel it. The signature covers the type string,
        # so verification over the relabeled envelope must fail.
        priv, pub = keypair
        envelope = sign_bytes(PAYLOAD, "application/octet-stream", priv)
        envelope["payloadType"] = "application/vnd.szl.authorization+json"
        assert verify_envelope(envelope, pub) is False

    def test_mangled_base64_fails_closed(self, keypair):
        priv, pub = keypair
        envelope = sign_bytes(PAYLOAD, PTYPE, priv)
        envelope["payload"] = "!!! not base64 !!!"
        assert verify_envelope(envelope, pub) is False
        envelope = sign_bytes(PAYLOAD, PTYPE, priv)
        envelope["signatures"] = [{"keyid": "x", "sig": "!!!"}]
        assert verify_envelope(envelope, pub) is False

    def test_empty_signatures_is_not_a_signature(self, keypair):
        _, pub = keypair
        envelope = {
            "payload": base64.b64encode(PAYLOAD).decode(),
            "payloadType": PTYPE,
            "signatures": [],
        }
        assert verify_envelope(envelope, pub) is False

    def test_keyid_defaults_to_pubkey_sha256(self, keypair):
        priv, _ = keypair
        envelope = sign_bytes(PAYLOAD, PTYPE, priv)
        assert len(envelope["signatures"][0]["keyid"]) == 64

    def test_unwrap_validates_shape(self, keypair):
        priv, _ = keypair
        envelope = sign_bytes(PAYLOAD, PTYPE, priv)
        payload, ptype, sigs = unwrap_envelope(envelope)
        assert (payload, ptype, len(sigs)) == (PAYLOAD, PTYPE, 1)
        with pytest.raises(DsseError):
            unwrap_envelope({"payloadType": PTYPE})  # no payload
        with pytest.raises(DsseError):
            unwrap_envelope({"payload": envelope["payload"], "payloadType": 7, "signatures": []})


class TestKeygen:
    def test_keygen_writes_loadable_pems(self, tmp_path):
        priv_path, pub_path = keygen(tmp_path / "op" / "operator")
        assert priv_path.name == "operator.pem"
        assert pub_path.name == "operator.pub.pem"
        priv = load_private_key(priv_path)
        pub = load_public_key(pub_path)
        envelope = sign_bytes(b"x", "t/x", priv)
        assert verify_envelope(envelope, pub) is True

    def test_private_key_is_mode_600(self, tmp_path):
        import stat

        priv_path, _ = keygen(tmp_path / "operator")
        assert stat.S_IMODE(priv_path.stat().st_mode) & 0o777 == 0o600

    def test_keygen_refuses_overwrite(self, tmp_path):
        keygen(tmp_path / "operator")
        with pytest.raises(DsseError, match="overwrite"):
            keygen(tmp_path / "operator")


class TestStatement:
    def test_statement_shape(self):
        doc = statement(
            subjects=[("payload.md", "ab" * 32), ("sbom.json", "cd" * 32)],
            predicate_type="https://slsa.dev/provenance/v1",
            predicate={"builder": {"id": "szl-ci"}},
        )
        assert doc["_type"] == INTOTO_STATEMENT_V1
        assert doc["subject"][0] == {"name": "payload.md", "digest": {"sha256": "ab" * 32}}
        assert doc["predicateType"] == "https://slsa.dev/provenance/v1"
        # Statements are plain JSON and canonicalize cleanly.
        json.dumps(doc)

    def test_statement_defaults(self):
        doc = statement()
        assert doc["subject"] == []
        assert doc["predicate"] == {}
