"""The Docker image's Makefile (docker/Makefile), checked with dry runs."""

import shutil
import subprocess
from pathlib import Path

import pytest

MAKEFILE = Path(__file__).resolve().parent.parent / "docker" / "Makefile"

pytestmark = pytest.mark.skipif(shutil.which("make") is None, reason="needs make")


def make(cwd, *args):
    return subprocess.run(
        ["make", "--no-print-directory", "-n", "-f", str(MAKEFILE), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def project(tmp_path):
    for name in ("payments_tm.py", "auth_tm.py", "helpers.py"):
        (tmp_path / name).write_text("", encoding="utf-8")
    return tmp_path


def test_builds_every_model_into_its_own_directory(project):
    result = make(project)

    assert result.returncode == 0, result.stderr
    for model in ("payments_tm", "auth_tm"):
        assert f"{model}.py --dfd --colormap | dot -Tpng -o {model}/dfd.png" in (
            result.stdout
        )
        assert f"-tpng -pipe > {model}/seq.png" in result.stdout
        assert (
            f"--thumbnails {model}/thumbnails/report "
            "--thumbnail-prefix thumbnails/report" in result.stdout
        )
        assert f"cd {model} && pandoc report.md" in result.stdout
    assert "helpers" not in result.stdout
    assert "--report pytm:report.md.j2 --report-var dfd_colormap=yes" in result.stdout
    assert "-o report.html" in result.stdout and "-o report.pdf" in result.stdout


def test_falls_back_to_tm_py(tmp_path):
    (tmp_path / "tm.py").write_text("", encoding="utf-8")

    result = make(tmp_path, "dfd")

    assert "tm.py --dfd --colormap | dot -Tpng -o tm/dfd.png" in result.stdout


def test_options(project):
    result = make(
        project,
        "MODELS=auth_tm.py",
        "OUT=build",
        "FORMATS=md",
        "COLORMAP=no",
        "REPORTS=mine.md.j2",
    )

    assert result.returncode == 0, result.stderr
    assert "payments" not in result.stdout
    assert "auth_tm.py --dfd | dot -Tpng -o build/auth_tm/dfd.png" in result.stdout
    assert (
        "--report mine.md.j2 --report-var dfd_colormap=no > build/auth_tm/mine.md"
        in (result.stdout)
    )
    assert "pandoc" not in result.stdout


def test_several_reports(project):
    result = make(
        project, "MODELS=auth_tm.py", "REPORTS=pytm:report.md.j2 pytm:actions.md.j2"
    )

    assert result.returncode == 0, result.stderr
    for name in ("report", "actions"):
        assert (
            f"--thumbnails auth_tm/thumbnails/{name} --thumbnail-prefix thumbnails/{name} "
            f"--report pytm:{name}.md.j2 --report-var dfd_colormap=yes > auth_tm/{name}.md"
            in result.stdout
        )
        assert f"cd auth_tm && pandoc {name}.md" in result.stdout
        assert f"-o {name}.html" in result.stdout and f"-o {name}.pdf" in result.stdout


def test_reports_with_the_same_name_are_an_error(project):
    result = make(project, "REPORTS=pytm:report.md.j2 report.md")

    assert result.returncode != 0
    assert "same name" in result.stderr


def test_theme(project, tmp_path_factory):
    theme = tmp_path_factory.mktemp("theme")
    (theme / "html.yaml").write_text("", encoding="utf-8")

    html = make(project, f"THEME={theme}", "html")
    pdf = make(project, f"THEME={theme}", "pdf")

    assert f"--defaults {theme}/html.yaml" in html.stdout
    assert "--embed-resources" not in html.stdout  # the theme decides
    assert pdf.returncode != 0
    assert "has no pdf.yaml" in pdf.stdout + pdf.stderr


def test_no_models_is_an_error(tmp_path):
    result = make(tmp_path)

    assert result.returncode != 0
    assert "No models" in result.stderr
