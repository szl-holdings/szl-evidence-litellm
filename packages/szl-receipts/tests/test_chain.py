"""Chain attack harness: build a chain, attack it, name the detection.

Each attack class gets its own test so a regression in one detector points
at the attack it stopped detecting, not at "verify_chain broke".
"""

import copy

import pytest
from szl_receipts.chain import append, entry_digest_for, verify_chain
from szl_receipts.receipt import compute_receipt_id, verify_receipt


def _build_chain(make_receipt, n=5):
    chain = []
    for _ in range(n):
        append(chain, make_receipt())
    return chain


class TestConstruction:
    def test_genesis_has_null_prev_and_seq_1(self, make_receipt):
        chain = _build_chain(make_receipt, 1)
        assert chain[0]["seq"] == 1
        assert chain[0]["prev"] is None
        assert chain[0]["entry_digest"] == entry_digest_for(1, chain[0]["receipt"], None)

    def test_each_entry_links_to_predecessor(self, make_receipt):
        chain = _build_chain(make_receipt)
        for i in range(1, len(chain)):
            assert chain[i]["seq"] == i + 1
            assert chain[i]["prev"] == chain[i - 1]["entry_digest"]

    def test_append_rejects_invalid_receipt(self):
        chain = []
        with pytest.raises(ValueError, match="invalid receipt"):
            append(chain, {"receipt_type": "GovernedAction/v1"})  # missing everything

    def test_clean_chain_verifies_ok(self, make_receipt):
        report = verify_chain(_build_chain(make_receipt))
        assert report.ok is True
        assert report.findings == []
        assert report.length == 5
        assert report.head is not None and len(report.head) == 64


class TestAttacks:
    @pytest.mark.parametrize("index", [0, 1, 2])
    def test_stale_receipt_id_rejects_even_with_recomputed_entry_digest(self, make_receipt, index):
        chain = _build_chain(make_receipt, 3)
        chain[index]["receipt"]["actor"] = "changed-actor"
        # Recompute the outer chain from the edit onward, leaving only the
        # inner receipt identity stale. This is a consistency test, not a
        # bypass of an authoritative external head anchor.
        for i in range(index, len(chain)):
            entry = chain[i]
            entry["prev"] = chain[i - 1]["entry_digest"] if i else None
            entry["entry_digest"] = entry_digest_for(entry["seq"], entry["receipt"], entry["prev"])

        receipt_findings = verify_receipt(chain[index]["receipt"])
        assert len(receipt_findings) == 1 and "receipt_id mismatch" in receipt_findings[0]
        report = verify_chain(chain)
        assert report.ok is False
        assert report.findings == [{
            "code": "invalid-receipt",
            "message": f"seq {index + 1}: {receipt_findings[0]}",
            "seq": index + 1,
            "index": index,
        }]

    @pytest.mark.parametrize("receipt", [None, [], [{}], "receipt", False, True, 7, 7.5])
    def test_well_hashed_non_object_receipt_is_malformed(self, receipt):
        entry = {"seq": 1, "receipt": receipt, "prev": None}
        entry["entry_digest"] = entry_digest_for(1, receipt, None)
        report = verify_chain([entry])
        assert report.ok is False
        assert len(report.findings) == 1
        assert report.findings[0]["code"] == "malformed-entry"
        assert report.findings[0]["index"] == 0
        assert "receipt must be an object" in report.findings[0]["message"]

    @pytest.mark.parametrize("receipt", [{}, {"receipt_type": "GovernedAction/v1"}])
    def test_well_hashed_receipt_with_missing_fields_is_invalid(self, receipt):
        entry = {"seq": 1, "receipt": receipt, "prev": None}
        entry["entry_digest"] = entry_digest_for(1, receipt, None)
        report = verify_chain([entry])
        assert report.ok is False
        expected = verify_receipt(receipt)
        assert len(report.findings) == len(expected)
        assert all(f["code"] == "invalid-receipt" for f in report.findings)
        assert [f["message"] for f in report.findings] == [f"seq 1: {f}" for f in expected]

    @pytest.mark.parametrize("field,value", [
        ("actor", None), ("policy", []), ("decision", False),
        ("subjects", [None]), ("evidence", ["evidence"]),
    ])
    def test_self_consistent_receipt_with_invalid_nested_data_rejects(self, make_receipt, field, value):
        receipt = make_receipt()
        receipt[field] = value
        receipt["receipt_id"] = compute_receipt_id(receipt)
        entry = {"seq": 1, "receipt": receipt, "prev": None}
        entry["entry_digest"] = entry_digest_for(1, receipt, None)
        report = verify_chain([entry])
        assert report.ok is False
        assert all(f["code"] == "invalid-receipt" for f in report.findings)

    @pytest.mark.parametrize("seq", [2, 7, 1000])
    def test_complete_chain_must_start_at_sequence_one(self, make_receipt, seq):
        entry = {"seq": seq, "receipt": make_receipt(), "prev": None}
        entry["entry_digest"] = entry_digest_for(seq, entry["receipt"], None)
        report = verify_chain([entry])
        assert report.ok is False
        assert len(report.findings) == 1
        assert report.findings[0]["code"] == "genesis-seq-not-one"
        assert report.findings[0]["seq"] == seq
        assert report.findings[0]["index"] == 0

    def test_truncation_detected_via_anchor(self, make_receipt):
        chain = _build_chain(make_receipt, 5)
        truncated = chain[:3]  # attacker drops the newest entries
        # Without an anchor, a truncated prefix is a valid shorter chain —
        # honest limit of self-verifying logs, asserted explicitly here.
        assert verify_chain(truncated).ok is True
        # With the estate's external anchor, the truncation is named.
        report = verify_chain(truncated, expected_entries=5)
        assert report.ok is False
        assert any(f["code"] == "truncated" for f in report.findings)

    def test_tail_truncation_detected_via_head_anchor(self, make_receipt):
        chain = _build_chain(make_receipt, 5)
        report = verify_chain(chain[:4], expected_head=chain[-1]["entry_digest"])
        assert report.ok is False
        assert any(f["code"] == "head-mismatch" for f in report.findings)

    def test_reorder_detected(self, make_receipt):
        chain = _build_chain(make_receipt, 5)
        chain[1], chain[2] = chain[2], chain[1]  # swap two entries
        report = verify_chain(chain)
        assert report.ok is False
        assert any(f["code"] == "reorder" for f in report.findings)

    def test_replay_detected(self, make_receipt):
        chain = _build_chain(make_receipt, 5)
        chain.append(copy.deepcopy(chain[1]))  # replay entry 2 at the tail
        report = verify_chain(chain)
        assert report.ok is False
        assert any(f["code"] == "replay" for f in report.findings)

    def test_fork_detected(self, make_receipt):
        chain = _build_chain(make_receipt, 5)
        evil = copy.deepcopy(chain[1])
        evil["receipt"] = make_receipt()  # a genuinely different receipt body
        evil["receipt"]["actor"] = "mallory"
        evil["entry_digest"] = entry_digest_for(evil["seq"], evil["receipt"], evil["prev"])
        chain.insert(2, evil)  # a second entry claiming seq 2
        report = verify_chain(chain)
        assert report.ok is False
        assert any(f["code"] == "fork" for f in report.findings)

    def test_broken_prev_link_detected(self, make_receipt):
        chain = _build_chain(make_receipt, 5)
        chain[3]["prev"] = "0" * 64  # cut the link; digest no longer matches either
        report = verify_chain(chain)
        assert report.ok is False
        codes = {f["code"] for f in report.findings}
        assert "digest-mismatch" in codes or "broken-prev-link" in codes

    def test_surgical_prev_break_with_recomputed_digest(self, make_receipt):
        # A subtler attacker breaks the link AND recomputes the entry's own
        # digest, so only the link check can catch it.
        chain = _build_chain(make_receipt, 5)
        entry = chain[2]
        entry["prev"] = "f" * 64
        entry["entry_digest"] = entry_digest_for(entry["seq"], entry["receipt"], entry["prev"])
        report = verify_chain(chain)
        assert report.ok is False
        assert any(f["code"] == "broken-prev-link" for f in report.findings)

    def test_gap_detected(self, make_receipt):
        chain = _build_chain(make_receipt, 5)
        del chain[2]  # middle truncation: seq jumps 2 -> 4
        report = verify_chain(chain)
        assert report.ok is False
        assert any(f["code"] == "gap" for f in report.findings)

    def test_genesis_prev_must_be_null(self, make_receipt):
        chain = _build_chain(make_receipt, 3)
        entry = chain[0]
        entry["prev"] = "0" * 64
        entry["entry_digest"] = entry_digest_for(entry["seq"], entry["receipt"], entry["prev"])
        report = verify_chain(chain)
        assert report.ok is False
        assert any(f["code"] == "genesis-prev-not-null" for f in report.findings)

    def test_field_tamper_detected_as_digest_mismatch(self, make_receipt):
        chain = _build_chain(make_receipt, 5)
        chain[2]["receipt"]["actor"] = "mallory"  # receipt_id AND entry digest now stale
        report = verify_chain(chain)
        assert report.ok is False
        assert any(f["code"] == "digest-mismatch" for f in report.findings)

    def test_malformed_entry_named(self):
        report = verify_chain([{"seq": 1}])
        assert report.ok is False
        assert any(f["code"] == "malformed-entry" for f in report.findings)

    def test_not_a_list_named(self):
        report = verify_chain("definitely a chain")
        assert report.ok is False
        assert any(f["code"] == "not-a-list" for f in report.findings)

    def test_empty_chain_is_vacuously_ok(self):
        report = verify_chain([])
        assert report.ok is True
        assert report.length == 0
        assert report.head is None

    def test_empty_chain_fails_nonempty_external_anchors(self, make_receipt):
        chain = _build_chain(make_receipt, 1)
        report = verify_chain([], expected_entries=1, expected_head=chain[0]["entry_digest"])
        assert report.ok is False
        assert {f["code"] for f in report.findings} == {"truncated", "head-mismatch"}
