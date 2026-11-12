"""Loading threats from more than one file (TM.extraThreatsFiles)."""

import json
import os
import random
import subprocess
import sys

import pytest

from pytm import TM
from pytm.tm import UIError

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _threat(sid, **extra):
    return {
        "SID": sid,
        "target": ["Server"],
        "description": f"{sid} threat",
        "details": "",
        "Likelihood Of Attack": "Low",
        "severity": "Medium",
        "condition": "True",
        "prerequisites": "",
        "mitigations": "",
        "example": "",
        "references": "",
        **extra,
    }


def _write(path, *threats):
    path.write_text(json.dumps(list(threats)), encoding="utf-8")
    return str(path)


def _ids():
    return [t.id for t in TM._threats]


def test_by_default_only_the_library_is_loaded():
    TM("lib tm")
    library = _ids()

    assert library and "EXT1" not in library


def test_extra_files_are_added_after_the_library_in_order(tmp_path):
    TM("lib tm")
    library = _ids()
    TM.reset()
    first = _write(tmp_path / "a.json", _threat("EXT1"), _threat("OLD1", DEPRECATED=1))
    second = _write(tmp_path / "b.json", _threat("EXT2"))

    TM("extra tm", extraThreatsFiles=[first, second])

    assert _ids() == library + ["EXT1", "EXT2"]  # deprecated threats skipped


def test_a_single_path_is_accepted(tmp_path):
    tm = TM("extra tm", extraThreatsFiles=_write(tmp_path / "a.json", _threat("EXT1")))

    assert tm.extraThreatsFiles == [str(tmp_path / "a.json")]
    assert "EXT1" in _ids()


def test_duplicate_threat_ids_are_an_error_naming_both_files(tmp_path):
    library = os.path.join(ROOT, "pytm", "threatlib", "threats.json")
    first = _write(tmp_path / "a.json", _threat("EXT1"))
    clash = _write(tmp_path / "b.json", _threat("EXT1"))
    shadow = _write(tmp_path / "c.json", _threat("INP01"))

    with pytest.raises(UIError) as between_extras:
        TM("dup tm", extraThreatsFiles=[first, clash])
    TM.reset()
    with pytest.raises(UIError) as with_library:
        TM("dup tm", threatsFile=library, extraThreatsFiles=[shadow])

    assert between_extras.value.context == (
        f"while loading threats: EXT1 is in both {first} and {clash}."
    )
    assert f"INP01 is in both {library} and {shadow}" in with_library.value.context


def test_setting_extra_files_after_construction_reloads_the_threats(tmp_path):
    tm = TM("extra tm")
    library = _ids()

    tm.extraThreatsFiles = [_write(tmp_path / "a.json", _threat("EXT1"))]

    assert _ids() == library + ["EXT1"]


def test_a_failed_change_keeps_the_previous_files_and_threats(tmp_path):
    good = _write(tmp_path / "a.json", _threat("EXT1"))
    tm = TM("extra tm", extraThreatsFiles=[good])
    before = _ids()

    with pytest.raises(UIError):
        tm.extraThreatsFiles = [str(tmp_path / "missing.json")]

    assert tm.extraThreatsFiles == [good]
    assert _ids() == before


def test_relative_paths_are_found_next_to_the_model(tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    _write(models / "project_threats.json", _threat("EXT1"))
    _write(tmp_path / "cwd_threats.json", _threat("EXT2"))
    (models / "model_tm.py").write_text(
        "from pytm import TM\n"
        "tm = TM('rel tm', extraThreatsFiles=['project_threats.json',"
        " 'cwd_threats.json'])\n"
        "print(' '.join(t.id for t in TM._threats if t.id.startswith('EXT')))\n",
        encoding="utf-8",
    )

    # Run from the parent directory: the first file is next to the model,
    # the second only in the current directory.
    result = subprocess.run(
        [sys.executable, os.path.join("models", "model_tm.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": ROOT},
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["EXT1", "EXT2"]
