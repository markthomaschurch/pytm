"""Stable, unique link anchors for threat model objects.

Reports link between sections (an asset to its dataflows, a finding to its
threat, ...). These helpers turn model objects into identifiers that are:

- readable: ``server-web-server``, ``dataflow-login``, ``threat-inp01``;
- valid in HTML, pandoc Markdown heading attributes (``{#id}``) and LaTeX;
- unique within a model: a second element with the same type and name gets
  ``-2``, ``-3``, ... in the order the elements were created;
- stable across runs of the same model, and the same for an element and the
  copies that :meth:`pytm.TM.report` hands to templates.

Each model class decides how it is named (``_anchor_base()`` and
``display_label()``, overridden where needed, e.g. by unnamed dataflows);
elements and data reserve their unique anchor when they are created.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def slugify(text: Any, fallback: str = "item") -> str:
    """Convert *text* to a lowercase, hyphen-separated ASCII slug.

    Accented characters are reduced to their base letter (``Café`` becomes
    ``cafe``). Characters with no ASCII equivalent are dropped; if nothing is
    left, *fallback* is returned.

    >>> slugify("Web Server (v2)")
    'web-server-v2'
    """
    normalized = unicodedata.normalize("NFKD", str(text))
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii").lower()
    slug = _NON_ALNUM.sub("-", ascii_text).strip("-")
    return slug or fallback


def type_prefix(obj: Any) -> str:
    """``ExternalEntity`` -> ``external-entity``, ``LLM`` -> ``llm``."""
    return _CAMEL_BOUNDARY.sub("-", type(obj).__name__).lower()


def register_anchor(base: str) -> str:
    """Reserve a unique anchor in the current model, starting from *base*.

    The first object to ask for ``server-web-server`` gets it; later ones get
    ``server-web-server-2``, ``-3``, ... Called once per element and piece of
    data, when it is created; ``TM.reset()`` starts a new set.
    """
    from .tm import TM

    used = TM._get_state().anchors
    candidate, counter = base, 2
    while candidate in used:
        candidate = f"{base}-{counter}"
        counter += 1
    used.add(candidate)
    return candidate


def anchor(obj: Any) -> str:
    """Return the link anchor of a model object (its ``anchor`` attribute).

    Elements, dataflows, boundaries and data get theirs when they are
    created; threats and findings derive theirs from their ids. Copies (such
    as the ones :meth:`pytm.TM.report` hands to templates) keep the anchor of
    the original.

    Raises:
        TypeError: if *obj* has no anchor.
    """
    value = getattr(obj, "anchor", None)
    if not isinstance(value, str):
        raise TypeError(f"anchor() does not support {type(obj).__name__} objects")
    return value


def label(obj: Any) -> str:
    """Text to show for *obj* in a report: its name, or a readable stand-in.

    Unnamed dataflows are shown as "<source> to <sink>" (matching their
    anchor), and other unnamed objects as "(unnamed <Type>)", so links and
    headings are never empty.
    """
    display = getattr(obj, "display_label", None)
    if callable(display):
        return display()
    name = str(getattr(obj, "name", "") or "").strip()
    return name or f"(unnamed {type(obj).__name__})"


def anchor_for_threat_id(threat_id: str) -> str:
    """Return the anchor for the threat with SID *threat_id*."""
    return f"threat-{slugify(threat_id)}"
