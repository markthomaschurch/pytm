"""Verification of assumptions, and requireVerifiedAssumptions."""

import datetime
import random

import pytest
from pydantic import ValidationError

from pytm import TM, Actor, Assumption, Dataflow, Server, Threat


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


class TestAssumptionFields:
    def test_defaults(self):
        a = Assumption("Patched")

        assert (a.verified, a.verifier, a.verifiedOn) == (False, "", None)

    def test_verified_on_is_a_date(self):
        a = Assumption(
            "Patched", verified=True, verifier="Ana", verifiedOn="2026-11-01"
        )

        assert a.verifiedOn == datetime.date(2026, 11, 1)

    def test_verified_on_needs_verified(self):
        with pytest.raises(ValidationError, match="verifiedOn but is not verified"):
            Assumption("Patched", verifiedOn="2026-11-01")

    def test_excludes(self):
        unverified = Assumption("a", exclude=["X1"])
        verified = Assumption("b", exclude=["X1"], verified=True)

        assert unverified.excludes("X1") and verified.excludes("X1")
        assert not unverified.excludes("X1", require_verified=True)
        assert verified.excludes("X1", require_verified=True)
        assert not verified.excludes("X2", require_verified=True)


def _model(require):
    tm = TM(
        "verify tm",
        description="d",
        requireVerifiedAssumptions=require,
        assumptions=[
            Assumption("Model, unverified", exclude={"T2"}, verifier="Bo"),
            Assumption("Model, verified", exclude={"T3"}, verified=True, verifier="Cy"),
        ],
    )
    web = Server(
        "Web",
        assumptions=[
            Assumption("Element, unverified", exclude={"T1"}, verifier="Ana"),
            Assumption("Element, verified", exclude={"T4"}, verified=True),
        ],
    )
    Dataflow(Actor("User"), web, "Login")
    TM._threats[:] = [
        Threat(SID=sid, target="Server", description=sid, condition="True")
        for sid in ("T1", "T2", "T3", "T4")
    ]
    tm.resolve()
    return tm


def test_by_default_every_assumption_suppresses():
    tm = _model(require=False)

    assert [f.threat_id for f in tm.findings] == []
    assert sorted(f.threat_id for f in tm.excluded_findings) == ["T1", "T2", "T3", "T4"]


def test_required_verification_keeps_unverified_findings():
    tm = _model(require=True)

    assert sorted(f.threat_id for f in tm.findings) == ["T1", "T2"]
    assert {f.threat_id: f.assumption.name for f in tm.excluded_findings} == {
        "T3": "Model, verified",
        "T4": "Element, verified",
    }
