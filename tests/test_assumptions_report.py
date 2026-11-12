"""Assumptions, and the threats they suppress, in the built-in report."""

import random
import re
import shutil
import subprocess

import pytest

from pytm import TM, Actor, Assumption, Boundary, Data, Dataflow, Server
from pytm.relations import Relations

pytest.importorskip("jinja2")


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _model():
    tm = TM(
        "assumption tm",
        description="d",
        assumptions=[
            Assumption(
                "Internal network",
                exclude={"AA01", "XX99"},
                description="Only reachable over the VPN",
            ),
            "Users are trained",  # a plain statement, excludes nothing
        ],
    )
    zone = Boundary("Zone", assumptions=[Assumption("Monitored")])
    web = Server(
        "Web",
        inBoundary=zone,
        assumptions=[
            Assumption(
                "Patched", exclude={"DO01", "SC02", "INP02"}, description="Weekly"
            )
        ],
    )
    Dataflow(Actor("User"), web, "Login")
    tm.resolve()
    return tm, web


def _report(tm):
    return tm.report("report.md.j2", {"pandoc_metadata": "no"})


class TestRelations:
    def test_assumptions_and_what_they_suppressed(self):
        tm, web = _model()
        rel = Relations({"tm": tm})

        [internal, trained] = rel.assumptions()
        [patched] = rel.assumptions(web)

        assert internal.anchor == "assumption-internal-network"
        assert patched.anchor == "server-web-assumption-patched"
        assert {f.threat_id for f in patched.suppressed} == {"DO01", "SC02"}
        assert patched.unused == ("INP02",)  # doesn't apply to Web
        assert internal.unknown == ("XX99",)  # not in the threat library
        assert internal.suppressed and {f.threat_id for f in internal.suppressed} == {
            "AA01"
        }
        assert trained.exclude == [] and trained.suppressed == ()

    def test_suppressed_findings_and_their_assumption(self):
        tm, web = _model()
        rel = Relations({"tm": tm})

        on_web = rel.suppressed(web)

        assert {f.threat_id for f in on_web} >= {"DO01", "SC02"}
        assert all(f.anchor.startswith("suppressed-finding-") for f in on_web)
        do01 = next(f for f in on_web if f.threat_id == "DO01")
        assert rel.assumption_of(do01).name == "Patched"
        assert "DO01" in {t.id for t in rel.reported_threats()}
        assert "DO01" not in {t.id for t in rel.fired_threats()}

    def test_same_name_assumptions_get_their_own_anchors(self):
        tm = TM("dup tm", description="d", assumptions=["Same", "Same"])
        assert [a.anchor for a in Relations({"tm": tm}).assumptions()] == [
            "assumption-same",
            "assumption-same-2",
        ]


class TestReport:
    def test_model_assumptions_section(self):
        tm, _ = _model()

        report = _report(tm)
        section = report.split("## Assumptions")[1].split("\n## ")[0]

        assert (
            "[**Internal network**]{#assumption-internal-network}: Only reachable"
            in (section)
        )
        assert re.search(r"- Suppresses \[AA01\]\(#threat-aa01\) on \[", section)
        assert "Excludes XX99, which is not in the threat library" in section
        assert "[**Users are trained**]{#assumption-users-are-trained}" in section
        # Element assumptions are only in their element's section.
        assert "Patched" not in section and "Monitored" not in section

    def test_element_section_shows_its_assumptions_and_suppressed_threats(self):
        tm, _ = _model()

        report = _report(tm)
        web = report.split("### Web {#server-web}")[1].split("\n### ")[0]

        assert "[**Patched**]{#server-web-assumption-patched}: Weekly" in web
        assert "Excludes INP02, which suppressed no finding" in web
        assert "**Suppressed threats:**" in web
        assert re.search(
            r"- \[DO01\]\(#threat-do01\) .* \(.*, \[suppressed finding \d+\]"
            r"\(#suppressed-finding-\d+\)\), by \[Patched\]"
            r"\(#server-web-assumption-patched\)",
            web,
        )

    def test_boundary_section_shows_its_assumptions(self):
        tm, _ = _model()

        zone = _report(tm).split("### Zone {#boundary-zone}")[1].split("\n### ")[0]

        assert "[**Monitored**]{#boundary-zone-assumption-monitored}" in zone

    def test_suppressed_findings_section_summary_and_library(self):
        tm, _ = _model()

        report = _report(tm)

        assert "## Suppressed Findings { #section-suppressed-findings }" in report
        assert re.search(r"\| Suppressed findings \| \d+ \|", report)
        assert "| Assumption about | the whole model |" in report
        assert "| Suppressed by | [Patched](#server-web-assumption-patched) |" in report
        library = report.split("## Threat Library")[1]
        assert "{#threat-do01}" in library  # suppressed only, still in the library
        assert "**Suppressed findings:**" in library

    def test_data_dictionary_lists_suppressed_findings_on_its_flows(self):
        tm, web = _model()
        token = Data("Token")
        flow = next(f for f in TM._flows if f.name == "Login")
        flow.data = token
        flow.assumptions = [Assumption("Encrypted", exclude={"DE01", "DE02"})]
        tm.resolve()

        section = _report(tm).split("### Token {#data-token}")[1].split("\n## ")[0]

        assert "**Suppressed threats** (on the dataflows that carry it):" in section
        assert re.search(
            r"^- \[Suppressed finding (\d+)\]\(#suppressed-finding-\1\) on "
            r"\[Login\]\(#dataflow-login\): \[DE0[12]\]\(#threat-de0[12]\) .*, by "
            r"\[Encrypted\]\(#dataflow-login-assumption-encrypted\)$",
            section,
            re.M,
        )

    def test_threats_left_out_with_exclude(self):
        tm, _ = _model()
        TM._threatsExcluded = ["AC01", "NOPE1"]
        tm.resolve()

        section = _report(tm).split("### Threats left out of the analysis")[1]

        assert re.search(r"- AC01: \S", section)
        assert "- NOPE1 (not in the threat library)" in section

    def test_nothing_extra_without_assumptions(self):
        tm = TM("plain tm", description="d")
        Dataflow(Actor("User"), Server("Web"), "Login")
        tm.resolve()

        report = _report(tm)

        assert "## Assumptions" not in report
        assert "Suppressed" not in report
        assert "**Assumptions:**" not in report

    @pytest.mark.skipif(shutil.which("pandoc") is None, reason="needs pandoc")
    def test_every_link_has_a_target(self):
        tm, _ = _model()

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
