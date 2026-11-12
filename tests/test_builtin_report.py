import random
import re
import shutil
import subprocess
import sys

import pytest

pytest.importorskip("jinja2")

from pytm import (  # noqa: E402
    TM,
    Actor,
    Boundary,
    Data,
    Dataflow,
    Datastore,
    Server,
    Threat,
)
from pytm.report_templates import PACKAGED_DIR, resolve_template  # noqa: E402
from pytm.tm import UIError  # noqa: E402

REPORT = "pytm:report.md.j2"

LINK = re.compile(r"\]\(#([^)\s]+)\)")
HEADING_ID = re.compile(r"\{ ?#([^}\s]+) ?\}")


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _model():
    tm = TM("Report *tm*", description="A model for **report** tests.")
    internet = Boundary("Internet")
    dmz = Boundary("DMZ")
    user = Actor("User", inBoundary=internet)
    web = Server("Web [prod]", inBoundary=dmz, protocol="HTTPS", port=443)
    db = Datastore("Data Dictionary")  # name collides with a section title
    token = Data("Token", isCredentials=True, description="Session token")
    login = Dataflow(user, web, "Login", data=token, protocol="HTTPS", dstPort=443)
    Dataflow(web, db, "Store", data=token)
    Dataflow(web, user, "Reply", responseTo=login)
    tm.check()
    TM._threats[:] = [
        Threat(
            SID="T1",
            target="Server",
            description="<script>alert(1)</script>",
            severity="High",
            condition="target.controls.sanitizesInput is False",
        ),
        Threat(SID="T2", target="Dataflow", description="Sniffing", severity="Low"),
        Threat(SID="T3", target="Actor", description="Never", condition="False"),
    ]
    tm.resolve()
    return tm


def _links_resolve(markdown):
    assert "[](" not in markdown, "link with no visible text"
    assert not re.search(r"^#+ +\{", markdown, re.M), "heading with no text"
    ids = HEADING_ID.findall(markdown)
    assert len(ids) == len(set(ids)), "duplicate heading ids"
    broken = set(LINK.findall(markdown)) - set(ids)
    assert not broken, f"links without a target: {sorted(broken)}"


def test_sections_and_cross_links():
    tm = _model()

    report = tm.report(REPORT)

    for heading in [
        "# Report \\*tm\\* { #section-title }",
        "## Summary { #section-summary }",
        "## Dataflow Diagram { #section-dataflow-diagram }",
        "## Sequence Diagram { #section-sequence-diagram }",
        "## Data Dictionary { #section-data-dictionary }",
        "## Actors { #section-actors }",
        "## Dataflows { #section-dataflows }",
        "## Assets { #section-assets }",
        "## Trust Boundaries { #section-boundaries }",
        "## Threats { #section-threats }",
        "## Threat Library { #section-threat-library }",
        "### Web \\[prod\\] {#server-web-prod}",
        "### Data Dictionary {#datastore-data-dictionary}",
        "### Token {#data-token}",
        "### Finding 1: &lt;script&gt;alert(1)&lt;/script&gt; {#finding-1}",
        "### T1: &lt;script&gt;alert(1)&lt;/script&gt; {#threat-t1}",
    ]:
        assert heading + "\n" in report, heading
    assert "<script>" not in report
    assert (
        "**Handled by:**\n\n- [User](#actor-user)\n- [Web \\[prod\\]](#server-web-prod)\n"
    ) in report
    assert "| Destination port | 443 |" in report
    assert (
        "1. On [Web \\[prod\\]](#server-web-prod), set `controls.sanitizesInput` "
        "to `True` (currently `False`)\n"
    ) in report
    # T2 has no condition: it cannot be resolved by changing values.
    assert "no change to the model's values removes it" in report
    # Only threats that fired are in the library.
    assert "{#threat-t2}" in report and "{#threat-t3}" not in report
    _links_resolve(report)


def test_diagram_paths_can_be_changed_or_omitted():
    tm = _model()

    report = tm.report(REPORT, {"dfd_image": "img/dfd.svg", "seq_image": ""})

    # Inline image (trailing "\\ "), not a floating figure.
    assert "![Dataflow diagram](img/dfd.svg)\\ \n" in report
    assert "Sequence Diagram" not in report


def test_thumbnails_are_included_when_rendered():
    tm = _model()
    TM._thumbnails["server-web-prod"] = "thumbs/server-web-prod.png"

    report = tm.report(REPORT)

    # The trailing "\ " keeps it inline: not a floating, captioned figure.
    assert "![Web \\[prod\\]](thumbs/server-web-prod.png)\\ \n" in report
    assert report.count("](thumbs/") == 1


def test_sections_can_be_overridden_next_to_a_custom_template(tmp_path):
    tm = _model()
    (tmp_path / "sections").mkdir()
    (tmp_path / "sections" / "title.md.j2").write_text(
        "# Custom title\n", encoding="utf-8"
    )
    custom = tmp_path / "custom.md.j2"
    custom.write_text(
        '{% import "_macros.md.j2" as m %}'
        '{% include "sections/title.md.j2" %}'
        '{{ m.link_list("Assets", assets) }}',
        encoding="utf-8",
    )

    report = tm.report(str(custom))

    assert report == (
        "# Custom title\n**Assets:**\n\n"
        "- [Web \\[prod\\]](#server-web-prod)\n"
        "- [Data Dictionary](#datastore-data-dictionary)\n\n"
    )


def test_unknown_builtin_template():
    tm = _model()

    with pytest.raises(UIError):
        tm.report("pytm:missing.md.j2")


def test_builtin_templates_are_shipped():
    assert resolve_template(REPORT) == PACKAGED_DIR / "report.md.j2"
    names = sorted(
        p.relative_to(PACKAGED_DIR).as_posix() for p in PACKAGED_DIR.rglob("*.j2")
    )
    assert names == [
        "_macros.md.j2",
        "report.md.j2",
        "sections/actors.md.j2",
        "sections/assets.md.j2",
        "sections/boundaries.md.j2",
        "sections/data_dictionary.md.j2",
        "sections/dataflows.md.j2",
        "sections/diagrams.md.j2",
        "sections/legend.md.j2",
        "sections/suppressed.md.j2",
        "sections/threat_library.md.j2",
        "sections/threats.md.j2",
        "sections/title.md.j2",
    ]


@pytest.mark.skipif(shutil.which("pandoc") is None, reason="needs pandoc")
def test_pandoc_html_has_a_target_for_every_link():
    tm = _model()

    html = subprocess.run(
        ["pandoc", "-f", "markdown", "-t", "html"],
        input=tm.report(REPORT),
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    ids = re.findall(r'id="([^"]+)"', html)
    assert len(ids) == len(set(ids))
    assert set(re.findall(r'href="#([^"]+)"', html)) <= set(ids)
    assert "<script>" not in html


CLI_MODEL = """
from pytm import TM, Server
tm = TM("cli", description="d")
Server("Web Server")
tm.process()
"""


def _cli(tmp_path, *args):
    model = tmp_path / "model.py"
    model.write_text(CLI_MODEL, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(model), *args],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )


def test_cli_builtin_report_with_variables(tmp_path):
    result = _cli(tmp_path, "--report", REPORT, "--report-var", "dfd_image=out/dfd.png")

    assert result.returncode == 0, result.stderr
    assert "![Dataflow diagram](out/dfd.png)" in result.stdout
    assert "### Web Server {#server-web-server}" in result.stdout


def test_cli_rejects_malformed_report_variable(tmp_path):
    result = _cli(tmp_path, "--report", REPORT, "--report-var", "no-equals-sign")

    assert result.returncode == 127
    assert "expected KEY=VALUE" in result.stderr


def test_pandoc_metadata_block_makes_pdf_links_visible():
    TM.reset()
    tm = TM('Name with "quotes": and colon', description="d")
    Server("Web Server")
    tm.check()

    report = tm.report(REPORT)
    plain = tm.report(REPORT, {"pandoc_metadata": "no"})

    assert report.startswith(
        "---\n"
        'pagetitle: "Name with \\"quotes\\": and colon"\n'
        "colorlinks: true\n"
        "geometry: margin=0.75in\n"
        "maxwidth: 52em\n"
        "header-includes:\n"
        "  - '`\\IfFileExists{xurl.sty}{\\usepackage{xurl}}{}`{=latex}'\n"
        "  - '`\\raggedright`{=latex}'\n"
        "---\n"
    )
    assert plain.startswith("# Name with")


@pytest.mark.skipif(shutil.which("pandoc") is None, reason="needs pandoc")
def test_pandoc_latex_output_colours_links():
    tm = _model()

    latex = subprocess.run(
        ["pandoc", "-s", "-f", "markdown", "-t", "latex"],
        input=tm.report(REPORT),
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    assert "colorlinks=true" in latex
    assert "hidelinks" not in latex
    # A finding's target is a real (now visible) link to the element.
    assert "\\hyperlink{server-web-prod}" in latex


def test_unnamed_objects_get_visible_link_text():
    # e.g. mittenup_tm.py: every dataflow is created with name "".
    TM.reset()
    tm = TM("unnamed tm", description="d")
    user = Actor("User")
    web = Server("Web Server")
    Dataflow(user, web, "", data=Data(""))
    Dataflow(web, user, "")
    tm.check()
    tm.resolve()

    report = tm.report(REPORT)

    assert "### User to Web Server {#dataflow-user-to-web-server}" in report
    assert "| Target | [User to Web Server](#dataflow-user-to-web-server) |" in report
    assert "### (unnamed Data) {#data-item}" in report
    _links_resolve(report)


def test_layout_keeps_lines_short():
    tm = _model()
    flow = next(f for f in TM._flows if f.name == "Store")
    flow.note = "first line\nsecond line"
    TM._threats[0].references = "https://a.example/1, https://b.example/2"

    report = tm.report(REPORT)

    # A line break in a value would end the table row.
    assert "| Note | first line second line |" in report
    assert "- <https://a.example/1>\n- <https://b.example/2>\n" in report
    assert "```python\ntarget.controls.sanitizesInput is False\n```" in report


def test_lists_have_one_item_per_line():
    tm = _model()

    report = tm.report(REPORT)

    # No "**Label:** [a](#a), [b](#b), ..." runs: lists are bullets.
    assert not re.search(r"^\*\*[^*]+:\*\* \[.*\]\(#.*\), \[", report, re.M)
    assert "**Findings:**\n\n- [Finding 1](#finding-1) on [Web \\[prod\\]]" in report
    assert "**Inside:**\n\n- [User](#actor-user)\n" in report
    # Empty lists stay on one line.
    assert "**Controls in place:** None\n" in report


def test_data_dictionary_links_the_findings_on_its_dataflows():
    report = _model().report("report.md.j2", {"pandoc_metadata": "no"})

    token = report.split("### Token {#data-token}")[1].split("\n## ")[0]
    found = re.findall(
        r"^- \[Finding (\d+)\]\(#finding-\1\) on \[(\w+)\]\(#dataflow-\w+\): "
        r"\[T2\]\(#threat-t2\) Sniffing \(Low\)$",
        token,
        re.M,
    )

    # The flows that carry the token, not the reply.
    assert sorted(flow for _, flow in found) == ["Login", "Store"]
    _links_resolve(report)
