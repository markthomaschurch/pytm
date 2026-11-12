import subprocess
import sys

import pytest

from pytm import TM, Server


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    yield
    TM.reset()


def test_variables_reach_the_template(tmp_path):
    template = tmp_path / "t.md"
    template.write_text("{tm.name} {dfd_image}", encoding="utf-8")
    tm = TM("vars tm", description="d")
    Server("Web Server")
    tm.check()

    assert tm.report(str(template), {"dfd_image": "img/dfd.png"}) == (
        "vars tm img/dfd.png"
    )


def test_variables_can_override_model_data(tmp_path):
    template = tmp_path / "t.md"
    template.write_text("{threats}", encoding="utf-8")
    tm = TM("vars tm", description="d")
    tm.check()

    assert tm.report(str(template), {"threats": "none"}) == "none"


def _cli(tmp_path, *args):
    (tmp_path / "t.md").write_text("[{dfd_image}]", encoding="utf-8")
    model = tmp_path / "model.py"
    model.write_text(
        "from pytm import TM\nTM('cli', description='d').process()\n",
        encoding="utf-8",
    )
    return subprocess.run(
        [sys.executable, str(model), "--report", "t.md", *args],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )


def test_cli_report_var(tmp_path):
    result = _cli(tmp_path, "--report-var", "dfd_image=a=b.png")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[a=b.png]"


def test_cli_rejects_a_malformed_report_var(tmp_path):
    result = _cli(tmp_path, "--report-var", "no-equals-sign")

    assert result.returncode == 127
    assert "expected KEY=VALUE" in result.stderr
