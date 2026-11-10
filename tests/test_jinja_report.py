import random
import subprocess
import sys

import pytest

pytest.importorskip("jinja2")

from pytm import (
    TM,
    Actor,
    Data,
    Dataflow,
    Datastore,
    Finding,
    Server,
    Threat,
)  # noqa: E402
from pytm.jinja_report import (  # noqa: E402
    heading_id,
    is_jinja_template,
    link,
    md_escape,
    threat_anchor,
)
from pytm.tm import UIError  # noqa: E402


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _model():
    tm = TM("jinja tm", description="test")
    user = Actor("User")
    web = Server("Web [prod]")
    db = Datastore("DB")
    token = Data("Token")
    Dataflow(user, web, "Login", data=token)
    Dataflow(web, db, "Query", data=token)
    tm.check()
    tm.resolve()
    return tm


def _render(tm, tmp_path, text, name="report.md.j2"):
    template = tmp_path / name
    template.write_text(text, encoding="utf-8")
    return tm.report(str(template))


class TestHelpers:
    @pytest.mark.parametrize(
        "name, expected",
        [
            ("report.md.j2", True),
            ("report.j2", True),
            ("report.jinja", True),
            ("REPORT.MD.J2", True),
            ("report.md", False),
            ("j2/report.md", False),
        ],
    )
    def test_is_jinja_template(self, name, expected):
        assert is_jinja_template(name) is expected

    def test_md_escape(self):
        assert md_escape("Web *prod* [v1.2] a|b $5 <x> C:\\tmp") == (
            "Web \\*prod\\* \\[v1.2\\] a\\|b \\$5 \\<x\\> C:\\\\tmp"
        )
        assert md_escape(None) == ""

    def test_link_heading_id_and_threat_anchor(self):
        web = Server("Web [prod]")
        threat = Threat(SID="INP01", target="Server", description="x")
        finding = Finding(web, id="1", threat=threat)

        assert link(web) == "[Web \\[prod\\]](#server-web-prod)"
        assert link(web, "the server") == "[the server](#server-web-prod)"
        assert heading_id(web) == "{#server-web-prod}"
        assert threat_anchor(finding) == "threat-inp01"
        assert threat_anchor(threat) == "threat-inp01"


class TestRendering:
    def test_same_variables_as_format_string_templates(self, tmp_path):
        tm = _model()

        jinja = _render(
            tm,
            tmp_path,
            "{{ tm.name }}|{% for a in assets %}{{ a.name }},{% endfor %}"
            "|{% for f in dataflows %}{{ f.name }},{% endfor %}"
            "|{% for d in data %}{{ d.name }},{% endfor %}"
            "|{{ findings | length > 0 }}",
        )
        classic = _render(
            tm,
            tmp_path,
            "{tm.name}|{assets:repeat:{{item.name}},}|{dataflows:repeat:{{item.name}},}"
            "|{data:repeat:{{item.name}},}|True",
            name="report.md",
        )

        assert jinja == classic == "jinja tm|Web [prod],DB,|Login,Query,|Token,|True"

    def test_helpers_and_report_util_filters(self, tmp_path):
        tm = _model()
        TM._thumbnails["datastore-db"] = "thumbs/datastore-db.png"

        output = _render(
            tm,
            tmp_path,
            "{% for a in assets %}"
            "## {{ a.name | md_escape }} {{ heading_id(a) }}\n"
            "{{ a | getElementType }} {{ a | getFindingCount }} [{{ thumbnail(a) }}]\n"
            "{% endfor %}"
            "{{ 'Café Ünïcode' | slugify }}",
        )

        lines = output.splitlines()
        assert lines[0] == "## Web \\[prod\\] {#server-web-prod}"
        assert lines[1].startswith("Server ") and lines[1].endswith(" []")
        assert lines[2] == "## DB {#datastore-db}"
        assert lines[3].startswith("Datastore ")
        assert lines[3].endswith(" [thumbs/datastore-db.png]")
        assert lines[4] == "cafe-unicode"

    def test_include_from_template_directory(self, tmp_path):
        tm = _model()
        (tmp_path / "_asset.md.j2").write_text(
            "* {{ link(asset) }}\n", encoding="utf-8"
        )

        output = _render(
            tm,
            tmp_path,
            "{% for asset in assets %}{% include '_asset.md.j2' %}{% endfor %}",
        )

        assert output == "* [Web \\[prod\\]](#server-web-prod)\n* [DB](#datastore-db)\n"

    def test_format_string_templates_are_unchanged(self, tmp_path):
        tm = _model()

        # Jinja syntax in a .md template is left alone.
        assert _render(tm, tmp_path, "{{{{ x }}}}", name="report.md") == "{{ x }}"


class TestErrors:
    def test_undefined_variable(self, tmp_path):
        tm = _model()

        with pytest.raises(UIError) as info:
            _render(tm, tmp_path, "{{ asets }}")

        assert "while rendering the report template" in info.value.context
        assert "asets" in str(info.value.error)

    def test_syntax_error_reports_line(self, tmp_path):
        tm = _model()

        with pytest.raises(UIError) as info:
            _render(tm, tmp_path, "line 1\n## {{ tm.name }} {#{{ tm.name }}}\n")

        assert info.value.context.endswith("report.md.j2:2)")

    def test_missing_template(self, tmp_path):
        tm = _model()

        with pytest.raises(UIError) as info:
            tm.report(str(tmp_path / "missing.md.j2"))

        assert "missing.md.j2" in info.value.context

    def test_jinja2_not_installed(self, tmp_path, monkeypatch):
        tm = _model()
        monkeypatch.setitem(sys.modules, "jinja2", None)

        with pytest.raises(UIError) as info:
            _render(tm, tmp_path, "{{ tm.name }}")

        assert "pip install 'pytm[jinja]'" in str(info.value.error)


def test_cli_renders_jinja_template(tmp_path):
    (tmp_path / "report.md.j2").write_text(
        "{% for a in assets %}{{ link(a) }}\n{% endfor %}", encoding="utf-8"
    )
    model = tmp_path / "model.py"
    model.write_text(
        "from pytm import TM, Server\n"
        "tm = TM('cli', description='d')\n"
        "Server('Web Server')\n"
        "tm.process()\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(model), "--report", "report.md.j2"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[Web Server](#server-web-server)"
