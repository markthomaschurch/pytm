"""The action report (pytm:actions.md.j2) and the helpers behind it."""

import random
import re
import shutil
import subprocess

import pytest

from pytm import TM, Actor, Assumption, Dataflow, Finding, Server, Threat
from pytm.jinja_report import drop_dangling_links, findings_by_severity

pytest.importorskip("jinja2")


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _model(require=True):
    tm = TM(
        "action tm",
        description="d",
        requireVerifiedAssumptions=require,
        assumptions=[
            # At stake: one Very High (5).
            Assumption("Hardened", exclude={"VH1"}, verifier="Bo"),
            # At stake: High + Medium on Web (7), the most.
            Assumption("Behind the WAF", exclude={"H1", "M1"}, verifier="Ana"),
            Assumption("Nothing at stake"),
            Assumption("Done", exclude={"H2"}, verified=True, verifier="Cy"),
        ],
    )
    web = Server(
        "Web",
        assumptions=[Assumption("Patched", exclude={"L1"}, verifier="Ana")],
    )
    Dataflow(Actor("User"), web, "Login")
    TM._threats[:] = [
        Threat(SID=sid, target="Server", description=f"{sid} threat", severity=sev)
        for sid, sev in [
            ("L1", "Low"),
            ("M1", "Medium"),
            ("VH1", "Very High"),
            ("H1", "High"),
            ("H2", "High"),
        ]
    ]
    tm.resolve()
    return tm


def _report(tm):
    return tm.report("actions.md.j2", {"pandoc_metadata": "no"})


def _section(report, heading):
    return report.split(heading)[1].split("\n## ")[0]


class TestHelpers:
    def test_findings_by_severity(self):
        web = Server("Web")
        findings = [
            Finding(
                web,
                id=str(i),
                threat=Threat(
                    SID=f"T{i}", target="Server", description="x", severity=sev
                ),
            )
            for i, sev in [
                (10, "Low"),
                (2, "Critical"),
                (3, "High"),
                (1, "Very High"),
                (4, "Low"),
            ]
        ]

        groups = findings_by_severity(findings)

        assert [(name, [f.id for f in group]) for name, group in groups] == [
            ("Very High", ["1", "2"]),  # "Critical" counts as Very High
            ("High", ["3"]),
            ("Low", ["4", "10"]),
        ]

    def test_drop_dangling_links(self):
        text = (
            "## A {#a}\n### B { #b }\n- [**C**]{#c}\n"
            "[to a](#a) [to b](#b) [to c](#c) [gone](#x) [Web \\[prod\\]](#y) "
            "![image](img.png) [site](https://example.com)"
        )

        result = drop_dangling_links(text).splitlines()[-1]

        assert result == (
            "[to a](#a) [to b](#b) [to c](#c) gone Web \\[prod\\] "
            "![image](img.png) [site](https://example.com)"
        )


class TestReport:
    def test_sections_in_order(self):
        report = _report(_model())
        headings = re.findall(r"^## (.+?) \{", report, re.M)

        assert headings == [
            "Dataflow Diagram",
            "Sequence Diagram",
            "Threats by Severity",
            "Assumptions to Verify",
            "Assumptions to Verify, by Person",
        ]

    def test_threats_are_sorted_by_severity(self):
        report = _report(_model())
        section = _section(report, "## Threats by Severity")

        assert re.findall(r"^### (.+?) \(\d+\)", section, re.M) == [
            "Very High",
            "High",
            "Medium",
            "Low",
        ]
        threats = re.findall(r"^\| Threat \| (\w+) \|$", section, re.M)
        assert threats == ["VH1", "H1", "M1", "L1"]  # H2 is suppressed

    def test_assumptions_to_verify_by_combined_severity(self):
        section = _section(_report(_model()), "## Assumptions to Verify {")

        rows = re.findall(r"^\| (\d+) \| \[([^\]]+)\]", section, re.M)
        assert rows == [
            ("1", "Behind the WAF"),  # High + Medium = 7
            ("2", "Hardened"),  # Very High = 5
            ("3", "Patched"),  # Low = 2
        ]
        # Affects no finding, or verified: nothing to do.
        assert "Nothing at stake" not in section and "Done" not in section
        assert "| Ana | 2 findings (1 High, 1 Medium) |" in section
        # The findings at stake link to their entries above, most severe first.
        waf = section.split("### Behind the WAF")[1].split("\n### ")[0]
        assert re.findall(r"\]\(#finding-\d+\) on Web: (\w+)", waf) == ["H1", "M1"]
        assert "| Combined severity | 7 |" in waf

    def test_assumptions_grouped_by_person(self):
        section = _section(_report(_model()), "## Assumptions to Verify, by Person")

        people = re.findall(r"^### (.+?) \((\d+)\)$", section, re.M)
        assert people == [("Ana", "2"), ("Bo", "1")]
        ana = section.split("### Ana (2)")[1].split("\n### ")[0]
        assert (
            "[Behind the WAF](#assumption-behind-the-waf), about the whole model" in ana
        )
        assert (
            "[Patched](#server-web-assumption-patched), about Web: would suppress "
            "1 finding (1 Low)" in ana
        )

    def test_links_to_left_out_sections_become_text(self):
        report = _report(_model())

        assert "| Target | Web |" in report  # no element sections here
        assert "](#server-web)" not in report
        assert "](#threat-" not in report  # no threat library either
        assert "](#finding-" in report and "](#assumption-" in report

    def test_unassigned_assumptions_come_last(self):
        tm = _model()
        tm.assumptions.append(Assumption("Unowned", exclude={"H2"}))
        tm.assumptions[3] = Assumption("Done", verified=True)  # H2 now applies
        tm.resolve()

        section = _section(_report(tm), "## Assumptions to Verify, by Person")

        people = re.findall(r"^### (.+?) \((\d+)\)$", section, re.M)
        assert people[-1] == ("No one assigned", "1")
        assert "[Unowned](#assumption-unowned), about the whole model" in section

    def test_suppressed_findings_are_not_shown(self):
        report = _report(_model(require=False))

        assert "uppressed" not in report.replace("would suppress", "")
        assert "Set\n`tm.requireVerifiedAssumptions = True`" in report
        assert "No one: there are no assumptions to verify." in report
        assert "H1 threat" not in report and "VH1 threat" not in report

    def test_nothing_to_do(self):
        tm = TM("empty tm", description="d")
        tm.resolve()

        report = _report(tm)

        assert "No threats apply to this model." in report
        assert "No one: there are no assumptions to verify." in report

    @pytest.mark.skipif(shutil.which("pandoc") is None, reason="needs pandoc")
    def test_every_link_has_a_target(self):
        html = subprocess.run(
            ["pandoc", "-f", "markdown", "-t", "html"],
            input=_report(_model()),
            capture_output=True,
            text=True,
            check=True,
        ).stdout

        ids = set(re.findall(r'id="([^"]+)"', html))
        targets = set(re.findall(r'href="#([^"]+)"', html))
        assert targets and targets <= ids, sorted(targets - ids)
