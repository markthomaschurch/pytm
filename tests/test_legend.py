import random
import re
import shutil
import subprocess
import sys

import pytest

from pytm import LLM, TM, Actor, Agent, Boundary, Dataflow, Datastore, Lambda, Server
from pytm.element import sev_to_color
from pytm.legend import legend_dot, legend_entries, severity_entries


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _model():
    tm = TM("legend tm", description="d")
    zone = Boundary("Zone")
    user = Actor("User")
    web = Server("Web", inBoundary=zone)
    Dataflow(user, web, "Login")
    Dataflow(web, Datastore("DB"), "Query")
    Agent("Bot")
    LLM("Model")
    tm.check()
    return tm


def test_entries_cover_the_types_in_the_model_grouped_by_shape():
    _model()

    entries = [(e.shape, e.types) for e in legend_entries()]

    assert entries == [
        ("square", ("Actor",)),
        ("circle", ("Server",)),
        ("cylinder", ("Datastore",)),
        ("hexagon", ("Agent", "LLM")),
    ]


def test_samples_are_drawn_by_the_element_classes():
    _model()
    Lambda("Fn")

    samples = {e.types: e.sample.dfd() for e in legend_entries()}

    assert "shape = square;" in samples[("Actor",)]
    assert "shape = rectangle; style=rounded;" in samples[("Lambda",)]
    # Samples are not part of the model.
    assert all(
        not isinstance(e.sample, Lambda) or e.sample not in TM._elements
        for e in legend_entries()
    )


def test_legend_does_not_change_the_model_or_random_state():
    _model()
    before = (len(TM._elements), random.getstate())

    legend_dot(colormap=True)

    assert (len(TM._elements), random.getstate()) == before


def test_severity_entries_follow_sev_to_color():
    entries = severity_entries()

    named = [s for e in entries for s in e.severities]
    assert named[:6] == ["Very High", "High", "Medium", "Low", "Very Low", "Info"]
    for entry in entries:
        assert entry.declaration == sev_to_color(
            {
                "Very High": 5,
                "High": 4,
                "Medium": 3,
                "Low": 2,
                "Very Low": 1,
                "Info": 0,
                "No findings": 0,
            }[entry.severities[0]],
            **({"has_findings": False} if entry.severities == ("No findings",) else {}),
        )
    assert entries[0].colour_name == "red"


def test_standalone_legend():
    tm = _model()

    plain = tm.legend()
    coloured = legend_dot(colormap=True)

    assert plain.startswith("digraph legend {")
    assert "shape = hexagon;" in plain  # real sample shapes
    assert "legend_severity_1" not in plain  # colours only with colormap
    assert "legend_severity_1" in coloured


@pytest.mark.skipif(shutil.which("dot") is None, reason="needs Graphviz")
def test_graphviz_renders_the_legend():
    _model()

    result = subprocess.run(
        ["dot", "-Tsvg"],
        input=legend_dot(colormap=True),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Trust boundary" in result.stdout
    assert "Agent, LLM" in result.stdout


def test_report_legend(tmp_path):
    pytest.importorskip("jinja2")
    tm = _model()
    tm.resolve()

    plain = tm.report("report.md.j2", {"pandoc_metadata": "no"})
    coloured = tm.report(
        "report.md.j2", {"pandoc_metadata": "no", "dfd_colormap": "yes"}
    )

    assert "| hexagon | Agent, LLM |" in plain
    assert "| Colour | Severity |" not in plain
    assert re.search(r"^\| red \| Very High \|$", coloured, re.M)


def test_cli_legend(tmp_path):
    model = tmp_path / "model.py"
    model.write_text(
        "from pytm import TM, Actor, Server, Dataflow\n"
        "tm = TM('cli', description='d')\n"
        "Dataflow(Actor('User'), Server('Web'), 'Login')\n"
        "tm.process()\n",
        encoding="utf-8",
    )

    def run(*args):
        return subprocess.run(
            [sys.executable, str(model), *args],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )

    result = run("--legend", "--colormap")

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("digraph legend {")
    assert "legend_severity_1" in result.stdout


def test_rows_never_hide_their_nodes():
    # A row with a single item must not become "name [style = invis;]".
    for count in range(1, 10):
        TM.reset()
        TM("rows tm", description="d")
        for cls in (Actor, Server, Lambda, Datastore, Agent)[: count % 5 + 1]:
            cls(cls.__name__)

        for line in legend_dot(colormap=True).splitlines():
            assert not re.match(r"^\s*\w+ \[style = invis;\];$", line), line


@pytest.mark.skipif(shutil.which("dot") is None, reason="needs Graphviz")
def test_legend_images_are_rendered_and_used_by_the_report(tmp_path):
    pytest.importorskip("jinja2")
    from pytm.legend import BOUNDARY_KEY, DATAFLOW_KEY, render_legend_images

    tm = _model()
    Lambda("Fn")  # its HTML-like label must stay valid when blank
    tm.resolve()

    written = render_legend_images(tmp_path / "img", link_prefix="img")

    keys = {e.key for e in legend_entries()} | {e.key for e in severity_entries()}
    assert set(written) == keys | {BOUNDARY_KEY, DATAFLOW_KEY}
    for path in written.values():
        assert path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    report = tm.report("report.md.j2", {"pandoc_metadata": "no", "dfd_colormap": "yes"})
    assert (
        "| ![hexagon](img/legend-shape-hexagon.png){ height=0.2in } | Agent, LLM |"
        in (report)
    )
    assert "](img/legend-colour-firebrick3.png){ height=0.2in } | Very High |" in report


def test_report_legend_falls_back_to_text_without_images():
    pytest.importorskip("jinja2")
    tm = _model()
    tm.resolve()

    report = tm.report("report.md.j2", {"pandoc_metadata": "no"})

    assert "| hexagon | Agent, LLM |" in report
    assert "legend-shape-" not in report
