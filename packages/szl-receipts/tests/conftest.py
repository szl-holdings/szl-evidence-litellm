"""Shared fixtures for the szl-receipts test harness.

Everything here is offline and hermetic: temp files only, no network, no
fixtures that depend on the host machine. The harness is part of the
estate's evidence trail — a test that depends on the environment is a test
that cannot be re-derived by an auditor.
"""

from __future__ import annotations

import pytest
from szl_receipts.dsse import generate_keypair
from szl_receipts.outcome import Outcome
from szl_receipts.receipt import build_receipt

POLICY = {
    "id": "szl.test.policy",
    "version": "14.0.0",
    "digest_sha256": "a" * 64,
}


@pytest.fixture()
def keypair():
    """A fresh Ed25519 (private, public) pair per test — keys are cheap."""
    return generate_keypair()


@pytest.fixture()
def make_receipt():
    """Factory building distinct, always-valid receipts (unique actions)."""
    counter = {"n": 0}

    def _make(**overrides):
        counter["n"] += 1
        kwargs = {
            "actor": "pytest-harness",
            "action": f"test-action-{counter['n']}",
            "policy": dict(POLICY),
            "outcome": Outcome.PASS,
            "rationale": "constructed by the test harness",
            "subjects": [],
            "evidence": [],
        }
        kwargs.update(overrides)
        return build_receipt(**kwargs)

    return _make
