"""A legend for the data flow diagram.

The legend explains the shapes the DFD uses for each type of element, and,
with ``colormap``, what each severity colour means. Everything in it is
taken from the code that draws the DFD (each class's own ``dfd()`` and
:func:`pytm.element.sev_to_color`), so it can't disagree with the diagram:
change a shape or a colour and the legend follows.

It is available as a standalone DOT diagram (:func:`legend_dot`,
``--legend``), as data for report templates (:func:`legend_entries`,
:func:`severity_entries`), and as one small image per item for report
legends (:func:`render_legend_images`).
"""

from __future__ import annotations

import inspect
import uuid
from dataclasses import dataclass
from pathlib import Path
from textwrap import indent
from typing import Any

# Element types in the order they are listed.
_TYPE_ORDER = (
    "Actor",
    "ExternalEntity",
    "Server",
    "Process",
    "Lambda",
    "Datastore",
    "Agent",
    "LLM",
)
_SHAPE_NAMES = {"rectangle; style=rounded": "rounded rectangle"}
# Plain names for the Graphviz colours the colormap uses (for reports).
_COLOUR_NAMES = {
    "firebrick3": "red",
    "darkorange2": "orange",
    "gold": "yellow",
    "darkgreen": "green",
    "gray50": "grey",
    "black": "black",
}
_SEVERITY_NAMES = {
    5: "Very High",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "Very Low",
    0: "Info",
}


@dataclass(frozen=True)
class ShapeEntry:
    """One shape in the legend and the element types drawn with it."""

    shape: str  # e.g. "circle"
    types: tuple[str, ...]  # e.g. ("Server", "Process")
    sample: Any  # an (unregistered) element drawn as the legend's sample

    @property
    def key(self) -> str:
        """Name of this entry's legend image, e.g. ``legend-shape-circle``."""
        from .anchors import slugify

        return f"legend-shape-{slugify(self.shape)}"


@dataclass(frozen=True)
class SeverityEntry:
    """One colormap colour and the severities drawn with it."""

    colour: str  # Graphviz colour name, e.g. "firebrick3"
    declaration: str  # the full declaration sev_to_color() returns
    severities: tuple[str, ...]  # e.g. ("Low", "Very Low", "Info")

    @property
    def key(self) -> str:
        """Name of this entry's legend image, e.g. ``legend-colour-firebrick3``."""
        from .anchors import slugify

        return f"legend-colour-{slugify(self.colour)}"

    @property
    def colour_name(self) -> str:
        """A plain name for the colour, e.g. "red" for firebrick3."""
        return _COLOUR_NAMES.get(self.colour, self.colour)


def _model_types() -> list[type]:
    """Element classes used in the current model, in legend order."""
    import pytm

    from .tm import TM

    present = {type(e) for e in TM._elements}
    ordered = [getattr(pytm, name) for name in _TYPE_ORDER]
    known = [cls for cls in ordered if cls in present]
    # Subclasses users define appear under their own name.
    extra = sorted(
        (cls for cls in present if cls not in ordered and _is_node_type(cls)),
        key=lambda cls: cls.__name__,
    )
    return known + extra


def _is_node_type(cls: type) -> bool:
    from .boundary import Boundary
    from .dataflow import Dataflow

    return not issubclass(cls, (Boundary, Dataflow))


def legend_entries() -> list[ShapeEntry]:
    """Shapes used in the current model, with the element types drawn so."""
    groups: dict[str, list[type]] = {}
    for cls in _model_types():
        # model_construct() skips __init__ (no registration with the model);
        # a fixed uuid keeps the uuid factory from drawing random numbers.
        sample = cls.model_construct(name=cls.__name__, uuid=uuid.UUID(int=0))
        groups.setdefault(sample._shape(), []).append(cls)
    entries = []
    for number, (shape, classes) in enumerate(groups.items(), 1):
        names = tuple(cls.__name__ for cls in classes)
        sample = classes[0].model_construct(
            name=", ".join(names),
            # A fixed uuid: legend nodes get stable names, and no random
            # numbers are drawn (they give model elements their uuids).
            uuid=uuid.UUID(int=number),
        )
        entries.append(ShapeEntry(_SHAPE_NAMES.get(shape, shape), names, sample))
    return entries


def severity_entries() -> list[SeverityEntry]:
    """Colormap colours, with the severities (and "No findings") they mean."""
    from .element import sev_to_color

    entries: list[SeverityEntry] = []
    for severity in sorted(_SEVERITY_NAMES, reverse=True):
        declaration = sev_to_color(severity)
        name = _SEVERITY_NAMES[severity]
        if entries and entries[-1].declaration == declaration:
            last = entries.pop()
            entries.append(
                SeverityEntry(last.colour, declaration, last.severities + (name,))
            )
        else:
            colour = declaration.split(";")[0].strip()
            entries.append(SeverityEntry(colour, declaration, (name,)))
    if "has_findings" in inspect.signature(sev_to_color).parameters:
        declaration = sev_to_color(0, has_findings=False)
        colour = declaration.split(";")[0].strip()
        entries.append(SeverityEntry(colour, declaration, ("No findings",)))
    return entries


_ROW_LENGTH = 4


def _rows(names: list[str]) -> list[list[str]]:
    """*names* split into rows of at most _ROW_LENGTH."""
    return [names[i : i + _ROW_LENGTH] for i in range(0, len(names), _ROW_LENGTH)]


def _row(names: list[str]) -> str:
    """Keep *names* on one row, in order (invisible edges between them)."""
    if not names:
        return ""
    same = "; ".join(names)
    row = f"{{ rank = same; {same}; }}\n"
    if len(names) > 1:  # a lone "name [style = invis;]" would hide the node
        row += " -> ".join(names) + " [style = invis;];\n"
    return row


def _body(colormap: bool) -> str:
    """Nodes and edges of the legend, without the surrounding graph.

    Shapes, the trust boundary and the dataflow sample come first, then,
    with *colormap*, the severity colours, in rows of at most four, one
    below the other.
    """
    entries = legend_entries()
    parts = [entry.sample.dfd() for entry in entries]
    # Drawn like a boundary cluster, but as a node so it can sit in the row
    # (Graphviz can't put a cluster's nodes in a rank=same row).
    parts.append("""legend_boundary [
    shape = box;
    style = dashed;
    color = firebrick2;
    fontsize = 10;
    label = <<i>Trust boundary</i>>;
];
""")
    parts.append("""legend_flow_from [shape = point; width = 0.05;];
legend_flow_to [shape = point; width = 0.05;];
legend_flow_from -> legend_flow_to [
    color = black;
    fontcolor = black;
    label = "Dataflow";
];
""")
    items = [entry.sample._uniq_name() for entry in entries]
    items += ["legend_boundary", "legend_flow_from"]
    rows = _rows(items)
    parts.append("{ rank = same; legend_flow_from; legend_flow_to; }\n")
    if colormap:
        second = []
        for number, entry in enumerate(severity_entries(), 1):
            name = f"legend_severity_{number}"
            second.append(name)
            label = ", ".join(entry.severities)
            parts.append(f"""{name} [
    shape = box;
    color = {entry.declaration};
    fontcolor = black;
    label = "{label}";
];
""")
        rows += _rows(second)
    parts.extend(_row(row) for row in rows)
    # Each row below the previous one.
    parts.extend(
        f"{above[0]} -> {below[0]} [style = invis;];\n"
        for above, below in zip(rows, rows[1:])
    )
    return "\n".join(parts)


def legend_dot(colormap: bool = False) -> str:
    """The legend as a standalone DOT graph."""
    return (
        "digraph legend {\n"
        "    graph [\n"
        "        fontname = Arial;\n"
        "        fontsize = 10;\n"
        "        nodesep = 0.15;\n"
        "        ranksep = 0.15;\n"
        "        pad = 0.05;\n"
        "    ]\n"
        "    node [\n"
        "        fontname = Arial;\n"
        "        fontsize = 10;\n"
        "        width = 0.3;\n"
        "        height = 0.3;\n"
        '        margin = "0.06,0.03";\n'
        "    ]\n"
        "    edge [\n"
        "        fontname = Arial;\n"
        "        fontsize = 9;\n"
        "    ]\n\n"
        f"{indent(_body(colormap), '    ')}"
        "}\n"
    )


# ---------------------------------------------------------------------------
# Legend images for reports
# ---------------------------------------------------------------------------

BOUNDARY_KEY = "legend-boundary"
DATAFLOW_KEY = "legend-dataflow"

_IMAGE_GRAPH = """digraph legend_item {{
    graph [pad = 0.02; dpi = 150;]
    node [fontname = Arial; fontsize = 10; width = 0.45; height = 0.3;]
{body}
}}
"""


def _image_sources() -> dict[str, str]:
    """DOT for one small image per legend item, keyed by its image name.

    Shapes are drawn by the element classes (without a label, so the image
    shows only the shape); colours by the colormap's own declarations.
    """
    sources = {}
    for number, entry in enumerate(legend_entries(), 1):
        blank = type(entry.sample).model_construct(
            name="", uuid=uuid.UUID(int=100 + number)
        )
        # An empty HTML-like label ("<b></b>", Lambda) is a Graphviz syntax
        # error; a non-breaking space keeps it valid and invisible.
        node = blank.dfd().replace("<b></b>", "<b>&nbsp;</b>")
        sources[entry.key] = _IMAGE_GRAPH.format(body=indent(node, "    "))
    sources[BOUNDARY_KEY] = _IMAGE_GRAPH.format(
        body='    b [shape = box; style = dashed; color = firebrick2; label = "";];'
    )
    sources[DATAFLOW_KEY] = _IMAGE_GRAPH.format(
        # Invisible ends as tall as the other samples, so the image scales
        # to the same height without blowing up the arrow.
        body=(
            "    rankdir = LR;\n"
            "    ranksep = 0.3;\n"
            '    a [shape = plaintext; label = ""; width = 0.01; height = 0.3;];\n'
            '    b [shape = plaintext; label = ""; width = 0.01; height = 0.3;];\n'
            "    a -> b [color = black;];"
        )
    )
    for entry in severity_entries():
        sources[entry.key] = _IMAGE_GRAPH.format(
            body=(
                f"    s [shape = box; width = 0.6; height = 0.22; "
                f'color = {entry.declaration}; label = "";];'
            )
        )
    return sources


def render_legend_images(
    out_dir: str | Path, fmt: str = "png", link_prefix: str | None = None
) -> dict[str, Path]:
    """Render the legend's shapes and colour swatches as small images.

    Writes ``<out_dir>/<key>.<fmt>`` for each legend item (see the ``key``
    of :class:`ShapeEntry` and :class:`SeverityEntry`, plus
    :data:`BOUNDARY_KEY` and :data:`DATAFLOW_KEY`) and registers their
    links for report templates (:func:`legend_image`), so a report's legend
    shows exactly what the DFD draws. ``link_prefix`` works as for
    thumbnails. Needs Graphviz ``dot``.
    """
    import shutil
    import subprocess

    from .tm import TM

    dot = shutil.which("dot")
    if dot is None:
        from .thumbnails import ThumbnailError

        raise ThumbnailError("dot is required to draw legend images but was not found")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    prefix = (out.as_posix() if link_prefix is None else link_prefix).rstrip("/")
    written = {}
    for key, source in _image_sources().items():
        path = out / f"{key}.{fmt}"
        subprocess.run(
            [dot, f"-T{fmt}", "-o", str(path)], input=source, text=True, check=True
        )
        written[key] = path
        TM._legend_images[key] = f"{prefix}/{path.name}" if prefix else path.name
    return written


def legend_image(key: str) -> str:
    """Link to the legend image *key*, or "" if none was rendered."""
    from .tm import TM

    return TM._legend_images.get(key, "")
