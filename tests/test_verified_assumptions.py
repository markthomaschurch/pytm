"""Verification of assumptions, and requireVerifiedAssumptions."""

import datetime
import random
import re
import shutil
import subprocess

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


# ---------------------------------------------------------------------------
# In the built-in report
# ---------------------------------------------------------------------------


def _report(tm):
    pytest.importorskip("jinja2")
    return tm.report("report.md.j2", {"pandoc_metadata": "no"})


def _section(report, heading):
    return report.split(heading)[1].split("\n## ")[0]


def test_verification_section_lists_who_has_to_verify_what():
    tm = _model(require=True)

    section = _section(_report(tm), "## Assumption Verification")

    assert "This model requires assumptions to be verified" in section
    unverified = section.split("### Unverified")[1].split("### Verified")[0]
    rows = [r for r in unverified.splitlines() if r.startswith("| ") and "[" in r]
    # Ordered by who is responsible.
    assert [r.split(" | ")[0] for r in rows] == ["| Ana", "| Bo"]
    assert (
        "| Ana | [Element, unverified](#server-web-assumption-element-unverified) | "
        "[Web](#server-web) | would suppress 1 finding |" in unverified
    )
    assert (
        "| Bo | [Model, unverified](#assumption-model-unverified) | the whole model |"
        in (unverified)
    )
    verified = section.split("### Verified assumptions")[1]
    assert (
        "| [Model, verified](#assumption-model-verified) | the whole model | Cy |  | "
        "suppresses 1 finding |" in verified
    )


def test_unassigned_assumptions_come_last():
    tm = TM(
        "unassigned tm",
        description="d",
        assumptions=[Assumption("Nobody"), Assumption("Someone", verifier="Zed")],
    )
    tm.resolve()

    section = _section(_report(tm), "## Assumption Verification")

    assert section.index("| Zed |") < section.index("| *No one* |")


def test_assumption_entries_show_their_verification():
    tm = _model(require=True)

    report = _report(tm)
    web = _section(report, "### Web {#server-web}").split("\n### ")[0]

    assert "    - Not verified; to be verified by Ana" in web
    assert re.search(
        r"    - Would suppress \[T1\]\(#threat-t1\) on \[Web\]\(#server-web\) "
        r"\(\[finding \d+\]\(#finding-\d+\)\) once verified",
        web,
    )
    assert "    - Verified\n" in web  # verified, no one recorded
    assert re.search(
        r"\| \[Unverified assumptions\]\(#section-unverified-assumptions\) \| 2 \|",
        report,
    )


def test_findings_say_which_assumption_is_pending():
    tm = _model(require=True)

    report = _report(tm)
    t1 = report.split(": T1 {#finding-")[1].split("\n### ")[0]

    assert (
        "**Pending verification:** [Element, unverified]"
        "(#server-web-assumption-element-unverified) would suppress this finding "
        "once it is verified. Not verified; to be verified by Ana." in t1
    )


def test_suppressed_findings_show_their_verification():
    tm = _model(require=False)
    tm.assumptions[1] = Assumption(
        "Model, verified",
        exclude={"T3"},
        verified=True,
        verifier="Cy",
        verifiedOn="2026-11-01",
    )
    tm.resolve()

    report = _report(tm)

    assert "Assumptions suppress the threats they exclude whether or not" in report
    assert "| Verification | Verified by Cy on 2026-11-01 |" in report
    assert "| Verification | Not verified; to be verified by Bo |" in report


@pytest.mark.skipif(shutil.which("pandoc") is None, reason="needs pandoc")
def test_every_link_has_a_target():
    tm = _model(require=True)

    html = subprocess.run(
        ["pandoc", "-f", "markdown", "-t", "html"],
        input=_report(tm),
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    ids = set(re.findall(r'id="([^"]+)"', html))
    targets = set(re.findall(r'href="#([^"]+)"', html))
    assert targets and targets <= ids, sorted(targets - ids)
