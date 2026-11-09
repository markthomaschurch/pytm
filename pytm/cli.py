"""The ``pytm`` command: run a threat model script.

A pytm model is a Python script that builds a :class:`pytm.TM` and calls
``tm.process()``. ``pytm MODEL.py [OPTIONS]`` runs it with the Python that
pytm is installed in, so the model works even when pytm lives in its own
environment (for example after ``pipx install pytm``), where
``python MODEL.py`` could not import it::

    pytm tm.py --dfd | dot -Tpng -o dfd.png
    pytm tm.py --report docs/basic_template.md > report.md

The options after the model are the model's own (``--dfd``, ``--seq``,
``--report``, ...; see ``pytm MODEL.py --help``).
"""

from __future__ import annotations

import argparse
import os
import runpy
import sys
from importlib.metadata import PackageNotFoundError, version


def _version() -> str:
    try:
        return version("pytm")
    except PackageNotFoundError:  # running from a source checkout
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pytm",
        description="Run a pytm threat model script.",
        epilog="Options after MODEL are passed to the model, for example "
        "'pytm tm.py --dfd'. Run 'pytm MODEL --help' to list them.",
    )
    parser.add_argument("--version", action="version", version=f"pytm {_version()}")
    parser.add_argument("model", metavar="MODEL", help="the model script, e.g. tm.py")
    parser.add_argument(
        "model_args",
        nargs=argparse.REMAINDER,
        metavar="...",
        help="options for the model (--dfd, --seq, --report, ...)",
    )
    args = parser.parse_args(argv)

    if not os.path.isfile(args.model):
        parser.error(f"model not found: {args.model}")

    # Run it the way "python MODEL ..." would: as __main__, with the model's
    # directory first on sys.path and its own arguments in sys.argv.
    model = os.path.abspath(args.model)
    sys.argv = [args.model, *args.model_args]
    sys.path.insert(0, os.path.dirname(model))
    # A SystemExit raised by the model (tm.process() on errors, --help, ...)
    # propagates unchanged, so exit codes and messages match "python MODEL".
    runpy.run_path(model, run_name="__main__")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
