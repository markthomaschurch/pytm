import shutil
import subprocess
import sys

import pytest

from pytm import TM, Server
from pytm.report_templates import (
    PACKAGED_DIR,
    TemplateNotFound,
    packaged_templates,
    resolve_template,
)


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    yield
    TM.reset()


@pytest.fixture
def elsewhere(tmp_path, monkeypatch):
    """Run from a directory that is not the source checkout."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_packaged_templates():
    names = packaged_templates()

    assert {"basic_template.md", "advanced_template.md", "report.md.j2"} <= set(names)
    assert "_macros.md.j2" not in names  # a partial, not a report
    assert "sections" not in names


@pytest.mark.parametrize("name", ["basic_template.md", "report.md.j2"])
def test_packaged_template_by_name(elsewhere, name):
    assert resolve_template(name) == PACKAGED_DIR / name


def test_old_docs_path_still_finds_the_packaged_template(elsewhere):
    assert resolve_template("docs/basic_template.md") == (
        PACKAGED_DIR / "basic_template.md"
    )


def test_a_file_in_the_current_directory_wins(elsewhere):
    (elsewhere / "basic_template.md").write_text("mine\n", encoding="utf-8")

    assert resolve_template("basic_template.md").read_text() == "mine\n"
    # pytm:NAME always means the packaged one.
    assert resolve_template("pytm:basic_template.md") == (
        PACKAGED_DIR / "basic_template.md"
    )


def test_paths_are_used_as_given(elsewhere):
    custom = elsewhere / "reports" / "custom.md"
    custom.parent.mkdir()
    custom.write_text("x", encoding="utf-8")

    assert resolve_template("reports/custom.md") == custom.relative_to(elsewhere)
    assert resolve_template(custom) == custom


@pytest.mark.parametrize("name", ["pytm:../tm.py", "../tm.py", "pytm:../../README"])
def test_cannot_escape_the_packaged_templates(elsewhere, name):
    with pytest.raises(TemplateNotFound):
        resolve_template(name)


def test_not_found_lists_where_it_looked(elsewhere):
    with pytest.raises(TemplateNotFound) as info:
        resolve_template("nope.md")

    message = str(info.value)
    assert "nope.md" in message
    assert str(PACKAGED_DIR) in message


def test_report_by_name_from_another_directory(elsewhere):
    pytest.importorskip("jinja2")
    tm = TM("name tm", description="d")
    Server("Web Server")
    tm.check()
    tm.resolve()

    basic = tm.report("basic_template.md")
    builtin = tm.report("report.md.j2", {"pandoc_metadata": "no"})

    assert "Web Server" in basic
    assert builtin.startswith("# name tm { #section-title }")


def test_cli_list_templates(tmp_path):
    model = tmp_path / "model.py"
    model.write_text(
        "from pytm import TM\nTM('cli', description='d').process()\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(model), "--list-templates"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == packaged_templates()


class TestStylesheet:
    def _report(self, variables=None):
        tm = TM("css tm", description="d")
        Server("Web Server")
        tm.check()
        tm.resolve()
        return tm.report("basic_template.md", variables)

    def test_shipped_and_not_listed_as_a_template(self):
        assert (PACKAGED_DIR / "Stylesheet.css").is_file()
        assert "Stylesheet.css" not in packaged_templates()

    def test_packaged_stylesheet_by_default(self, elsewhere):
        report = self._report()

        expected = (PACKAGED_DIR / "Stylesheet.css").resolve().as_uri()
        assert report.startswith(f'<link href="{expected}" rel="stylesheet">')

    def test_a_stylesheet_in_the_current_directory_wins(self, elsewhere):
        (elsewhere / "Stylesheet.css").write_text("body {}", encoding="utf-8")

        report = self._report()

        expected = (elsewhere / "Stylesheet.css").resolve().as_uri()
        assert report.startswith(f'<link href="{expected}" rel="stylesheet">')

    def test_report_variable_overrides_it(self, elsewhere):
        report = self._report({"stylesheet": "css/site.css"})

        assert report.startswith('<link href="css/site.css" rel="stylesheet">')

    @pytest.mark.skipif(shutil.which("pandoc") is None, reason="needs pandoc")
    def test_pandoc_embeds_the_stylesheet(self, elsewhere):
        css = (PACKAGED_DIR / "Stylesheet.css").read_text(encoding="utf-8")
        first_rule = next(line for line in css.splitlines() if "{" in line)

        html = subprocess.run(
            [
                "pandoc",
                "-f",
                "markdown",
                "-s",
                "--embed-resources",
                "-t",
                "html",
                "--metadata",
                "title=t",
            ],
            input=self._report(),
            capture_output=True,
            text=True,
            check=True,
        ).stdout

        assert first_rule.strip() in html
        assert "file://" not in html
