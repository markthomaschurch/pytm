"""Render report templates with Jinja2.

Templates whose name ends in ``.j2`` or ``.jinja`` (``report.md.j2``) are
rendered with Jinja2 instead of pytm's format-string templates. Jinja2 is an
optional dependency: ``pip install pytm[jinja]``.

Templates receive the same variables as format-string templates (``tm``,
``elements``, ``assets``, ``actors``, ``boundaries``, ``dataflows``, ``data``,
``threats``, ``findings``) plus these helpers:

Functions
    ``anchor(obj)``, ``label(obj)`` (name, or a stand-in for unnamed objects),
    ``heading_id(obj)``, ``threat_anchor(finding_or_threat)``,
    ``link(obj, text=None)``, ``thumbnail(obj)``, ``controls_in_place(obj)``,
    ``legend_entries()``, ``severity_entries()``, ``legend_image(key)``
    (see :mod:`pytm.legend`)

Cross-references (see :mod:`pytm.relations`)
    ``flows_of(element, direction=None)``, ``data_of(element)``,
    ``handlers_of(data)``, ``carriers_of(data)``, ``data_findings_of(data)``,
    ``members_of(boundary)``, ``findings_of(element)``,
    ``threats_of(element)``, ``fired_threats()``, ``findings_for(threat)``,
    ``remedies_of(finding)``

Filters
    ``slugify``, ``md_escape``, ``anchor``, ``label``, ``format_condition``
    (lay a condition out over short lines), ``split_references``,
    ``breakable`` (let PDF output wrap long unbroken tokens), and every
    :class:`pytm.report_util.ReportUtils` method, e.g.
    ``{{ asset | getFindingCount }}``

Pandoc heading IDs (``## Web Server {#server-web-server}``) clash with Jinja2's
comment syntax ``{# ... #}``; write ``## {{ obj.name }} {{ heading_id(obj) }}``
(or pandoc's spaced form ``{ #id }``) instead.

``{% include %}`` and ``{% import %}`` look in the template's own directory,
then in pytm's built-in templates (``pytm/templates``); select a built-in
report with ``pytm:report.md.j2``. Blocks are trimmed (``trim_blocks`` and
``lstrip_blocks``), so ``{% ... %}`` lines leave no blank lines behind.
Undefined variables raise an error instead of rendering as empty text.
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

from .report_templates import PACKAGED_DIR, PACKAGED_PREFIX, resolve_template

JINJA_SUFFIXES = (".j2", ".jinja")


# Characters with an inline meaning in Markdown or pandoc's extensions
# (emphasis, code, links, raw HTML, tables, math, sub/superscript, attributes)
# that should appear literally when they come from model data.
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>|$~^#])")


def is_jinja_template(template_path: str | Path) -> bool:
    """True if *template_path* should be rendered with Jinja2."""
    text = str(template_path)
    if text.startswith(PACKAGED_PREFIX):
        text = text[len(PACKAGED_PREFIX) :]
    return Path(text).suffix.lower() in JINJA_SUFFIXES


def controls_in_place(obj: Any) -> list[str]:
    """Names of the boolean controls that are enabled on *obj*."""
    controls = getattr(obj, "controls", None)
    if controls is None:
        return []
    return [
        name
        for name in type(controls).model_fields
        if getattr(controls, name, None) is True
    ]


def md_escape(text: Any) -> str:
    """Backslash-escape Markdown special characters in *text*."""
    return _MD_SPECIAL.sub(r"\\\1", "" if text is None else str(text))


_URL = re.compile(r"^(https?|ftp)://\S+$")

_LONG_TOKEN = re.compile(r"\S{31,}")
# A line-break opportunity for LaTeX/PDF output only; other formats drop it.
_LATEX_BREAK = "`\\allowbreak{}`{=latex}"
_BREAK_AFTER = set("/?&=;,.+-_)]")


def breakable(text: Any, every: int = 20) -> str:
    """Let PDF output wrap very long unbroken tokens in *text*.

    Threat examples contain base64 payloads, URLs and scripts that LaTeX
    cannot break, so they run off the page. Tokens longer than 30
    characters get LaTeX-only break points after punctuation such as ``/``
    or ``=``, or every *every* characters. HTML entities (``&amp;``) are kept
    whole, and HTML output is unchanged (browsers wrap long words already).
    """

    def split(match: re.Match) -> str:
        token, out, run, i = match.group(0), [], 0, 0
        while i < len(token):
            end = token.find(";", i) if token[i] == "&" else -1
            if 0 < end - i <= 8:  # an HTML entity such as &amp; or &#x27;
                piece, i = token[i : end + 1], end + 1
            else:
                piece, i = token[i], i + 1
            out.append(piece)
            run += 1
            if i < len(token) and (piece[-1] in _BREAK_AFTER or run >= every):
                out.append(_LATEX_BREAK)
                run = 0
        return "".join(out)

    return _LONG_TOKEN.sub(split, "" if text is None else str(text))


def split_references(text: Any) -> list[str]:
    """Split a threat's comma-separated references into Markdown items.

    URLs become autolinks (``<https://...>``), which wrap at slashes in PDF
    output; anything else (e.g. ``CVE-1999-0906``) is escaped text. Accepts
    pytm's HTML-escaped report text.
    """
    items = []
    for part in html.unescape("" if text is None else str(text)).split(","):
        part = part.strip()
        if part:
            items.append(f"<{part}>" if _URL.match(part) else md_escape(part))
    return items


def heading_id(obj: Any) -> str:
    """Pandoc heading attribute for *obj*: ``{#server-web-server}``.

    Use it instead of writing ``{#...}`` in a template, which Jinja2 would
    read as the start of a comment.
    """
    from .anchors import anchor

    return "{#" + anchor(obj) + "}"


def link(obj: Any, text: Any = None) -> str:
    """Markdown link to *obj*'s section: ``[Web Server](#server-web-server)``."""
    from .anchors import anchor, label

    text = label(obj) if text is None else text
    return f"[{md_escape(text)}](#{anchor(obj)})"


def threat_anchor(obj: Any) -> str:
    """Anchor of a threat, or of the threat behind a finding."""
    from .anchors import anchor_for_threat_id
    from .finding import Finding

    if isinstance(obj, Finding):
        return anchor_for_threat_id(obj.threat_id)
    return anchor_for_threat_id(getattr(obj, "id", obj))


def thumbnail(obj: Any) -> str:
    """Link to *obj*'s thumbnail, or "" if none was rendered."""
    from .report_util import ReportUtils

    return ReportUtils.getThumbnail(obj)


def _relation_functions() -> dict[str, Any]:
    """Template functions that look up the report's cross-references."""
    from .relations import current

    return {
        "flows_of": lambda element, direction=None: current().flows(element, direction),
        "data_of": lambda element: current().data(element),
        "handlers_of": lambda datum: current().handlers(datum),
        "carriers_of": lambda datum: current().carriers(datum),
        "data_findings_of": lambda datum: current().data_findings(datum),
        "members_of": lambda boundary: current().members(boundary),
        "findings_of": lambda element: current().findings(element),
        "threats_of": lambda element: current().threats(element),
        "fired_threats": lambda: current().fired_threats(),
        "findings_for": lambda threat: current().findings_for(threat),
        "remedies_of": lambda finding: current().remedies(finding),
    }


def _environment(template_dir: Path):
    try:
        import jinja2
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(
            "Jinja2 templates need the jinja2 package: pip install 'pytm[jinja]'"
        ) from exc

    from .anchors import anchor, label, slugify
    from .legend import legend_entries, legend_image, severity_entries
    from .relations import format_condition
    from .report_util import ReportUtils

    # The template's own directory comes first, so a report can override
    # any of pytm's sub-templates by providing a file with the same name.
    # (pytm's own templates are in PACKAGED_DIR, so when the report itself is
    # a packaged one, both entries point there.)
    loader = jinja2.ChoiceLoader(
        [
            jinja2.FileSystemLoader(str(template_dir)),
            jinja2.FileSystemLoader(str(PACKAGED_DIR)),
        ]
    )
    env = jinja2.Environment(
        loader=loader,
        undefined=jinja2.StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    for name in dir(ReportUtils):
        if not name.startswith("_"):
            env.filters[name] = getattr(ReportUtils, name)
    env.filters.update(
        slugify=slugify,
        md_escape=md_escape,
        anchor=anchor,
        label=label,
        format_condition=lambda text: format_condition(html.unescape(str(text))),
        split_references=split_references,
        breakable=breakable,
    )
    env.globals.update(_relation_functions())
    env.globals.update(
        anchor=anchor,
        label=label,
        heading_id=heading_id,
        threat_anchor=threat_anchor,
        link=link,
        thumbnail=thumbnail,
        controls_in_place=controls_in_place,
        legend_entries=legend_entries,
        severity_entries=severity_entries,
        legend_image=legend_image,
    )
    return env


def render_jinja(template_path: str | Path, context: dict[str, Any]) -> str:
    """Render the Jinja2 template at *template_path* with *context*.

    Raises:
        UIError: if Jinja2 is not installed, or the template is missing or
            has an error (the message includes the template name and line).
    """
    from .tm import UIError

    path = Path(template_path)
    if not path.is_file():
        path = resolve_template(template_path)
    try:
        env = _environment(path.parent)
    except ImportError as exc:
        raise UIError(exc, f"while rendering the report template ({path})")

    import jinja2

    try:
        return env.get_template(path.name).render(**context)
    except jinja2.TemplateNotFound as exc:
        raise UIError(
            exc, f"while trying to open the report template file ({template_path})."
        )
    except jinja2.TemplateSyntaxError as exc:
        where = f"{exc.filename or exc.name or path}:{exc.lineno}"
        raise UIError(exc, f"in the report template ({where})")
    except jinja2.UndefinedError as exc:
        raise UIError(exc, f"while rendering the report template ({path})")
