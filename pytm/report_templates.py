"""Finding report templates: the user's own files first, then pytm's.

``--report NAME`` (and :meth:`pytm.TM.report`) looks for the template in
this order:

1. ``NAME`` as a path, relative to the current directory (or absolute);
2. a template shipped with pytm called ``NAME``, e.g. ``basic_template.md``
   or ``report.md.j2``;
3. a template shipped with pytm with the same file name, so the paths used
   before the templates were packaged (``docs/basic_template.md``) keep
   working.

``pytm:NAME`` skips the first step and always uses the shipped template.

Files the templates use, such as ``Stylesheet.css``, are found the same way
(:func:`find_resource`).
"""

from __future__ import annotations

from pathlib import Path

PACKAGED_PREFIX = "pytm:"
PACKAGED_DIR = Path(__file__).resolve().parent / "templates"

# Partials included by other templates; not reports on their own.
_PARTIALS = ("_macros.md.j2",)
# Files used by templates, shipped alongside them but not templates.
_RESOURCE_SUFFIXES = (".css",)
STYLESHEET = "Stylesheet.css"


class TemplateNotFound(FileNotFoundError):
    """No template with the given name or path exists."""

    def __init__(self, name: str, searched: list[Path]):
        self.name = name
        self.searched = searched
        places = ", ".join(str(p) for p in searched)
        super().__init__(f"report template not found: {name} (looked for {places})")


def packaged_templates() -> list[str]:
    """Names of the report templates shipped with pytm, e.g. ``report.md.j2``."""
    return sorted(
        path.name
        for path in PACKAGED_DIR.iterdir()
        if path.is_file()
        and path.name not in _PARTIALS
        and path.suffix.lower() not in _RESOURCE_SUFFIXES
    )


def find_resource(name: str) -> Path:
    """Find a file used by templates (e.g. ``Stylesheet.css``) like a template:
    in the current directory first, then among the files shipped with pytm.
    """
    return resolve_template(name)


def stylesheet_uri() -> str:
    """``file://`` URI of the report stylesheet (``Stylesheet.css``).

    A URI rather than a relative path, so the link works wherever the HTML
    report is written; ``pandoc --embed-resources`` inlines it.
    """
    return find_resource(STYLESHEET).resolve().as_uri()


def _is_packaged(path: Path) -> bool:
    """True if *path* is inside the packaged templates (no "../" escapes)."""
    return path.resolve().is_relative_to(PACKAGED_DIR)


def resolve_template(name: str | Path) -> Path:
    """Return the template file for *name* (see the module docstring).

    Raises:
        TemplateNotFound: if neither a file nor a shipped template matches.
    """
    text = str(name)
    if text.startswith(PACKAGED_PREFIX):
        candidate = PACKAGED_DIR / text[len(PACKAGED_PREFIX) :]
        if candidate.is_file() and _is_packaged(candidate):
            return candidate
        raise TemplateNotFound(text, [candidate])

    searched = [Path(name)]
    if searched[0].is_file():
        return searched[0]
    for candidate in (PACKAGED_DIR / text, PACKAGED_DIR / Path(text).name):
        if candidate not in searched:
            searched.append(candidate)
        if candidate.is_file() and _is_packaged(candidate):
            return candidate
    raise TemplateNotFound(text, searched)
