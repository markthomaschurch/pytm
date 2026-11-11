import os
import random
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

from pytm import TM, Actor, Boundary, Data, Dataflow, Datastore, Server, thumbnails
from pytm.report_util import ReportUtils
from pytm.thumbnails import (
    HIGHLIGHT_STROKE,
    SVG_NS,
    Box,
    ThumbnailError,
    _Layout,
    _ops_box,
    _select,
    _thumbnail_svg,
    render_thumbnails,
)

needs_dot = pytest.mark.skipif(shutil.which("dot") is None, reason="needs Graphviz")
needs_rsvg = pytest.mark.skipif(
    shutil.which("rsvg-convert") is None, reason="needs rsvg-convert"
)


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _model(**tm_kwargs):
    """User -> Web (in DMZ) -> DB, plus an unrelated Admin -> Web flow."""
    tm = TM("thumb tm", description="test", **tm_kwargs)
    dmz = Boundary("DMZ")
    user = Actor("User")
    admin = Actor("Admin")
    web = Server("Web Server", inBoundary=dmz)
    db = Datastore("DB")
    token = Data("Token")
    login = Dataflow(user, web, "Login", data=token)
    reply = Dataflow(web, user, "Reply", responseTo=login)
    query = Dataflow(web, db, "Query", data=token)
    manage = Dataflow(admin, web, "Manage")
    tm.check()
    return tm, locals()


# ---------------------------------------------------------------------------
# Geometry helpers (no external tools)
# ---------------------------------------------------------------------------


class TestOpsBox:
    def test_ellipse_polygon_and_bezier(self):
        box = _ops_box(
            [
                {"op": "e", "rect": [10, 10, 5, 3]},
                {"op": "p", "points": [[0, 20], [30, 25]]},
                {"op": "b", "points": [[-4, 0], [2, 2]]},
            ]
        )

        assert (box.x0, box.y0, box.x1, box.y1) == (-4, 0, 30, 25)

    @pytest.mark.parametrize(
        "align, expected_x", [("c", (40, 60)), ("l", (50, 70)), ("r", (30, 50))]
    )
    def test_text_alignment_and_font_size(self, align, expected_x):
        box = _ops_box(
            [
                {"op": "F", "size": 12.0, "face": "Arial"},
                {"op": "T", "pt": [50, 100], "align": align, "width": 20},
            ]
        )

        assert (box.x0, box.x1) == expected_x
        assert (box.y0, box.y1) == (97, 112)

    def test_no_geometry(self):
        assert _ops_box([{"op": "c", "color": "#000"}]) is None


def _layout():
    """Hand-built layout matching _model()'s shape."""
    return _Layout(
        graph=Box(0, 0, 400, 300),
        nodes={
            "actor-user": Box(0, 250, 40, 290),
            "actor-admin": Box(300, 250, 340, 290),
            "server-web-server": Box(150, 120, 210, 180),
            "datastore-db": Box(150, 0, 210, 40),
        },
        edges={
            "dataflow-login": (
                "actor-user",
                "server-web-server",
                Box(20, 170, 160, 260),
            ),
            "dataflow-query": (
                "server-web-server",
                "datastore-db",
                Box(170, 30, 190, 130),
            ),
            "dataflow-manage": (
                "actor-admin",
                "server-web-server",
                Box(200, 170, 320, 260),
            ),
        },
        clusters={"boundary-dmz": (Box(140, 110, 220, 200), {"server-web-server"})},
    )


class TestSelect:
    def test_node_selects_connected_flows_and_neighbours(self):
        _, m = _model()

        selection = _select(m["db"], _layout())

        assert selection.highlight == {"datastore-db"}
        assert selection.nodes == {"datastore-db", "server-web-server"}
        assert selection.edges == {"dataflow-query"}

    def test_dataflow_selects_its_edge_and_ends(self):
        _, m = _model()

        selection = _select(m["login"], _layout())

        assert selection.highlight == {"dataflow-login"}
        assert selection.nodes == {"actor-user", "server-web-server"}

    def test_merged_response_uses_the_request_edge(self):
        _, m = _model()

        # "dataflow-reply" is not in the layout (merged into the request).
        assert _select(m["reply"], _layout()).highlight == {"dataflow-login"}

    def test_boundary_selects_members_and_outside_neighbours(self):
        _, m = _model()

        selection = _select(m["dmz"], _layout())

        assert selection.highlight == {"boundary-dmz"}
        assert selection.clusters == {"boundary-dmz"}
        assert selection.nodes == {
            "server-web-server",
            "actor-user",
            "actor-admin",
            "datastore-db",
        }

    def test_data_highlights_every_flow_that_carries_it(self):
        _, m = _model()

        selection = _select(m["token"], _layout())

        assert selection.highlight == {"dataflow-login", "dataflow-query"}
        assert selection.nodes == {"actor-user", "server-web-server", "datastore-db"}

    def test_not_drawn_returns_none(self):
        _, m = _model()
        layout = _layout()
        del layout.nodes["datastore-db"]

        assert _select(m["db"], layout) is None
        assert _select(Data("Unused"), layout) is None


def test_thumbnail_svg_highlights_dims_and_crops():
    _, m = _model()
    svg = ET.fromstring(
        f'<svg xmlns="{SVG_NS}" width="400pt" height="300pt" viewBox="0 0 400 300">'
        '<g id="graph0" class="graph" transform="scale(1 1) rotate(0) translate(4 304)">'
        '<g id="datastore-db" class="node"><path fill="none" stroke="black"/></g>'
        '<g id="server-web-server" class="node"><ellipse fill="none" stroke="black"/></g>'
        '<g id="actor-admin" class="node"><polygon fill="none" stroke="black"/></g>'
        '<g id="dataflow-query" class="edge"><path stroke="black"/></g>'
        '<g id="dataflow-manage" class="edge"><path stroke="black"/></g>'
        "</g></svg>"
    )
    layout = _layout()
    selection = _select(m["db"], layout)

    result = _thumbnail_svg(svg, layout, selection, Box(140, -10, 220, 190), dim=0.25)

    groups = {g.get("id"): g for g in result.iter(f"{{{SVG_NS}}}g")}
    db_shape = groups["datastore-db"][0]
    assert db_shape.get("stroke") == HIGHLIGHT_STROKE
    assert groups["server-web-server"].get("opacity") is None
    assert groups["dataflow-query"].get("opacity") is None
    assert groups["actor-admin"].get("opacity") == "0.25"
    assert groups["dataflow-manage"].get("opacity") == "0.25"
    # x = 140 + 4, y = 304 - 190 (SVG y grows downwards).
    assert result.get("viewBox") == "144.00 114.00 80.00 200.00"
    assert result.get("width") == "80pt"
    # The source tree is left untouched.
    assert svg[0][0][0].get("stroke") == "black"


# ---------------------------------------------------------------------------
# Rendering with Graphviz / rsvg-convert
# ---------------------------------------------------------------------------


@needs_dot
def test_render_svg_thumbnails(tmp_path):
    tm, m = _model(mergeResponses=True)

    written = render_thumbnails(tm, tmp_path, fmt="svg")

    assert set(written) == {
        "actor-user",
        "actor-admin",
        "server-web-server",
        "datastore-db",
        "boundary-dmz",
        "dataflow-login",
        "dataflow-reply",
        "dataflow-query",
        "dataflow-manage",
        "data-token",
    }
    root = ET.parse(written["datastore-db"]).getroot()
    full = ET.parse(written["boundary-dmz"]).getroot()
    groups = {g.get("id"): g for g in root.iter(f"{{{SVG_NS}}}g")}
    assert any(
        child.get("stroke") == HIGHLIGHT_STROKE for child in groups["datastore-db"]
    )
    assert groups["actor-admin"].get("opacity") == "0.3"
    assert float(root.get("viewBox").split()[3]) < float(full.get("viewBox").split()[3])


@needs_dot
def test_levels_filter_skips_elements_not_drawn(tmp_path):
    tm, m = _model()
    m["db"].levels = {1}

    written = render_thumbnails(tm, tmp_path, fmt="svg", levels=[0])

    assert "datastore-db" not in written
    assert "server-web-server" in written


@needs_dot
def test_main_dfd_still_works_after_thumbnails(tmp_path):
    tm, _ = _model()
    before = tm.dfd()

    render_thumbnails(tm, tmp_path, fmt="svg")

    assert tm.dfd() == before


@needs_dot
@needs_rsvg
def test_render_png_thumbnails(tmp_path):
    tm, _ = _model()

    written = render_thumbnails(tm, tmp_path, zoom=2)

    data = written["server-web-server"].read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    width, height = struct.unpack(">II", data[16:24])
    assert 0 < width and 0 < height


def test_missing_tools_raise(tmp_path, monkeypatch):
    tm, _ = _model()
    monkeypatch.setattr(thumbnails.shutil, "which", lambda tool: None)

    with pytest.raises(ThumbnailError, match="rsvg-convert"):
        render_thumbnails(tm, tmp_path)
    with pytest.raises(ThumbnailError, match="dot"):
        render_thumbnails(tm, tmp_path, fmt="svg")


def test_unsupported_format(tmp_path):
    tm, _ = _model()

    with pytest.raises(ValueError):
        render_thumbnails(tm, tmp_path, fmt="gif")


# ---------------------------------------------------------------------------
# Links for report templates
# ---------------------------------------------------------------------------


class TestTemplateLinks:
    def test_no_thumbnail_rendered(self):
        _, m = _model()

        assert ReportUtils.getThumbnail(m["web"]) == ""
        assert ReportUtils.getThumbnailMarkdown(m["web"]) == ""
        assert ReportUtils.getThumbnail("not a model object") == ""

    def test_markdown_escapes_name_and_wraps_links_with_spaces(self):
        TM("links tm", description="test")
        web = Server("Web [prod]")
        TM._thumbnails["server-web-prod"] = "my thumbs/server-web-prod.png"

        assert ReportUtils.getThumbnailMarkdown(web) == (
            "![Web \\[prod\\]](<my thumbs/server-web-prod.png>)"
        )

    def test_reset_clears_links(self):
        TM._thumbnails["server-x"] = "x.png"
        TM.reset()

        assert TM._thumbnails == {}

    @needs_dot
    def test_render_registers_links(self, tmp_path):
        tm, m = _model()

        render_thumbnails(tm, tmp_path / "out", fmt="svg")
        default = ReportUtils.getThumbnail(m["web"])
        render_thumbnails(tm, tmp_path / "out", fmt="svg", link_prefix="thumbs/")

        assert default == f"{(tmp_path / 'out').as_posix()}/server-web-server.svg"
        assert ReportUtils.getThumbnail(m["web"]) == "thumbs/server-web-server.svg"
        assert ReportUtils.getThumbnailMarkdown(m["token"]) == (
            "![Token](thumbs/data-token.svg)"
        )

    @needs_dot
    def test_report_copies_resolve_to_the_same_links(self, tmp_path):
        tm, m = _model()
        tm.resolve()
        render_thumbnails(tm, tmp_path, fmt="svg", link_prefix="t")
        template = tmp_path / "template.md"
        template.write_text(
            "{assets:repeat:{{item:call:getThumbnailMarkdown}}\n}", encoding="utf-8"
        )

        report = tm.report(str(template))

        assert report.splitlines() == [
            "![Web Server](t/server-web-server.svg)",
            "![DB](t/datastore-db.svg)",
        ]


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

CLI_MODEL = """
from pytm import TM, Actor, Server, Dataflow
tm = TM("cli tm", description="test")
Dataflow(Actor("User"), Server("Web Server"), "Login")
tm.process()
"""


def _run_cli(tmp_path, *args, env=None):
    model = tmp_path / "model.py"
    model.write_text(CLI_MODEL, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(model), *args],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
    )


@needs_dot
def test_cli_writes_thumbnails_and_report_links(tmp_path):
    template = tmp_path / "template.md"
    template.write_text(
        "{assets:repeat:{{item:call:getThumbnailMarkdown}}\n}", encoding="utf-8"
    )

    result = _run_cli(
        tmp_path,
        "--thumbnails",
        "out/thumbs",
        "--thumbnail-format",
        "svg",
        "--thumbnail-prefix",
        "thumbs",
        "--report",
        str(template),
    )

    assert result.returncode == 0, result.stderr
    written = (tmp_path / "out/thumbs").iterdir()
    assert sorted(p.name for p in written if not p.name.startswith("legend-")) == [
        "actor-user.svg",
        "dataflow-login.svg",
        "server-web-server.svg",
    ]
    assert result.stdout.strip() == "![Web Server](thumbs/server-web-server.svg)"


def test_cli_reports_missing_graphviz(tmp_path):
    env = dict(os.environ, PATH=str(tmp_path / "empty-path"))

    result = _run_cli(
        tmp_path, "--thumbnails", "out", "--thumbnail-format", "svg", env=env
    )

    assert result.returncode == 127
    assert "while writing thumbnails to out" in result.stderr
    assert "dot is required" in result.stderr
