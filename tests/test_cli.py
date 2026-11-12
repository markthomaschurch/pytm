import os
import subprocess
import sys
from pathlib import Path

import pytest

from pytm import TM
from pytm.cli import main

MODEL = """
import sys
import helper  # a module next to the model, as "python model.py" would find

print("argv:", sys.argv[1:])
print("name:", __name__)
print("helper:", helper.VALUE)
"""


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    yield
    TM.reset()


@pytest.fixture
def model(tmp_path, monkeypatch):
    (tmp_path / "helper.py").write_text("VALUE = 42\n", encoding="utf-8")
    path = tmp_path / "model.py"
    path.write_text(MODEL, encoding="utf-8")
    # main() changes sys.argv and sys.path, as running a script does.
    monkeypatch.setattr(sys, "argv", list(sys.argv))
    monkeypatch.setattr(sys, "path", list(sys.path))
    return path


def test_runs_model_as_main_with_its_own_arguments(model, capsys):
    assert main([str(model), "--dfd", "--levels", "0"]) == 0

    out = capsys.readouterr().out
    assert "argv: ['--dfd', '--levels', '0']" in out
    assert "name: __main__" in out
    assert "helper: 42" in out


def test_missing_model(tmp_path, capsys):
    with pytest.raises(SystemExit) as info:
        main([str(tmp_path / "missing.py")])

    assert info.value.code == 2
    assert "model not found" in capsys.readouterr().err


def test_model_exit_status_is_kept(model):
    model.write_text("import sys\nsys.exit(3)\n", encoding="utf-8")

    with pytest.raises(SystemExit) as info:
        main([str(model)])

    assert info.value.code == 3


def test_version(capsys):
    with pytest.raises(SystemExit) as info:
        main(["--version"])

    assert info.value.code == 0
    assert capsys.readouterr().out.startswith("pytm ")


def test_real_model_through_the_command_line(tmp_path):
    sample = Path(__file__).resolve().parent.parent / "tm.py"
    model = tmp_path / "model.py"
    model.write_text(sample.read_text(encoding="utf-8"), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "pytm.cli", str(model), "--dfd"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parent.parent)},
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("digraph tm {")
