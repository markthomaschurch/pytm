"""Element thumbnails: the main DFD cropped around one element.

For every element (and every piece of data) a thumbnail shows the same
layout as the full data flow diagram, with the element highlighted in blue,
cropped to the element and the elements directly connected to it. Elements
that fall inside the crop but are not connected are faded out.

The DFD is laid out once: Graphviz writes SVG and JSON from the same run, the
JSON gives the coordinates of every node, edge and boundary, and each
thumbnail is an edited copy of the SVG (colours, opacity and ``viewBox``).
PNG thumbnails are converted from the SVG with ``rsvg-convert``.

Requires Graphviz ``dot`` on ``PATH`` (and ``rsvg-convert`` for PNG).
"""

from __future__ import annotations

import copy
import json
import logging
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"
ET.register_namespace("", SVG_NS)
ET.register_namespace("xlink", XLINK_NS)

HIGHLIGHT_STROKE = "#1f6feb"
HIGHLIGHT_FILL = "#dbeafe"
HIGHLIGHT_WIDTH = "3"

# Warn when a thumbnail would show more than this share of the whole diagram.
LARGE_CROP_RATIO = 0.7

_SHAPES = {"ellipse", "polygon", "path", "polyline"}


class ThumbnailError(RuntimeError):
    """Raised when thumbnails cannot be rendered (e.g. a tool is missing)."""


@dataclass
class Box:
    """Axis-aligned box in Graphviz layout coordinates (points, y up)."""

    x0: float
    y0: float
    x1: float
    y1: float

    def union(self, other: Box | None) -> Box:
        if other is None:
            return self
        return Box(
            min(self.x0, other.x0),
            min(self.y0, other.y0),
            max(self.x1, other.x1),
            max(self.y1, other.y1),
        )

    def padded(self, padding: float) -> Box:
        return Box(
            self.x0 - padding, self.y0 - padding, self.x1 + padding, self.y1 + padding
        )

    def clamped(self, limit: Box) -> Box:
        return Box(
            max(self.x0, limit.x0),
            max(self.y0, limit.y0),
            min(self.x1, limit.x1),
            min(self.y1, limit.y1),
        )

    @property
    def area(self) -> float:
        return max(0.0, self.x1 - self.x0) * max(0.0, self.y1 - self.y0)


def _union(boxes: Iterable[Box | None]) -> Box | None:
    result = None
    for box in boxes:
        if box is not None:
            result = box if result is None else result.union(box)
    return result


def _ops_box(ops: Iterable[dict]) -> Box | None:
    """Bounding box of Graphviz xdot drawing operations."""
    xs: list[float] = []
    ys: list[float] = []
    font_size = 14.0
    for op in ops:
        kind = op.get("op")
        if kind == "F":
            font_size = float(op.get("size", font_size))
        elif kind in ("e", "E"):
            cx, cy, rx, ry = op["rect"]
            xs += [cx - rx, cx + rx]
            ys += [cy - ry, cy + ry]
        elif "points" in op:
            for x, y in op["points"]:
                xs.append(x)
                ys.append(y)
        elif kind == "T":
            x, y = op["pt"]
            width = float(op.get("width", 0))
            start = {"l": x, "r": x - width}.get(op.get("align"), x - width / 2)
            xs += [start, start + width]
            ys += [y - 0.25 * font_size, y + font_size]
    if not xs:
        return None
    return Box(min(xs), min(ys), max(xs), max(ys))


def _parse_box(text: str) -> Box:
    x0, y0, x1, y1 = (float(v) for v in text.split(","))
    return Box(x0, y0, x1, y1)


@dataclass
class _Layout:
    """Positions of every drawn node, edge and cluster, keyed by DOT id."""

    graph: Box
    nodes: dict[str, Box] = field(default_factory=dict)
    edges: dict[str, tuple[str, str, Box]] = field(default_factory=dict)
    clusters: dict[str, tuple[Box, set[str]]] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: dict) -> _Layout:
        layout = cls(graph=_parse_box(data["bb"]))
        gvid_to_id: dict[int, str] = {}
        objects = data.get("objects", [])
        for obj in objects:
            if "bb" in obj or "id" not in obj:
                continue
            gvid_to_id[obj["_gvid"]] = obj["id"]
            layout.nodes[obj["id"]] = _union(
                [_ops_box(obj.get("_draw_", [])), _ops_box(obj.get("_ldraw_", []))]
            )
        for obj in objects:
            if "bb" not in obj or "id" not in obj:
                continue
            members = {gvid_to_id[g] for g in obj.get("nodes", []) if g in gvid_to_id}
            layout.clusters[obj["id"]] = (_parse_box(obj["bb"]), members)
        for edge in data.get("edges", []):
            if "id" not in edge:
                continue
            box = _union(
                _ops_box(edge.get(key, []))
                for key in ("_draw_", "_hdraw_", "_tdraw_", "_ldraw_")
            )
            layout.edges[edge["id"]] = (
                gvid_to_id.get(edge["tail"], ""),
                gvid_to_id.get(edge["head"], ""),
                box,
            )
        return layout


@dataclass
class _Selection:
    """What a thumbnail highlights and which objects stay fully visible."""

    highlight: set[str]
    nodes: set[str]
    edges: set[str]
    clusters: set[str] = field(default_factory=set)


def _edge_for_flow(flow: Any, layout: _Layout) -> str | None:
    """DOT id of the edge a dataflow is drawn on (merged responses share one)."""
    from .anchors import anchor

    for candidate in (flow, flow.responseTo, flow.response):
        if candidate is not None and anchor(candidate) in layout.edges:
            return anchor(candidate)
    return None


def _select(obj: Any, layout: _Layout) -> _Selection | None:
    from .anchors import anchor
    from .boundary import Boundary
    from .data import Data
    from .dataflow import Dataflow
    from .tm import TM

    def around_edges(edge_ids: set[str], highlight: set[str]) -> _Selection:
        nodes = set()
        for edge_id in edge_ids:
            tail, head, _ = layout.edges[edge_id]
            nodes |= {tail, head}
        return _Selection(highlight, nodes - {""}, edge_ids)

    if isinstance(obj, Data):
        flows = [f for f in TM._flows if obj in f.data]
        edge_ids = {e for e in (_edge_for_flow(f, layout) for f in flows) if e}
        return around_edges(edge_ids, set(edge_ids)) if edge_ids else None

    if isinstance(obj, Dataflow):
        edge_id = _edge_for_flow(obj, layout)
        return around_edges({edge_id}, {edge_id}) if edge_id else None

    target = anchor(obj)

    if isinstance(obj, Boundary):
        if target not in layout.clusters:
            return None
        _, members = layout.clusters[target]
        edge_ids = {
            e for e, (tail, head, _) in layout.edges.items() if {tail, head} & members
        }
        selection = around_edges(edge_ids, {target})
        selection.nodes |= members
        selection.clusters.add(target)
        return selection

    if target not in layout.nodes:
        return None
    edge_ids = {
        e for e, (tail, head, _) in layout.edges.items() if target in (tail, head)
    }
    selection = around_edges(edge_ids, {target})
    selection.nodes.add(target)
    return selection


def _crop(selection: _Selection, layout: _Layout, padding: float) -> Box:
    boxes = [layout.nodes.get(n) for n in selection.nodes]
    boxes += [layout.edges[e][2] for e in selection.edges]
    boxes += [layout.clusters[c][0] for c in selection.clusters]
    box = _union(boxes) or layout.graph
    return box.padded(padding).clamped(layout.graph.padded(padding))


def _style_highlight(group: ET.Element, kind: str) -> None:
    for child in group.iter():
        tag = child.tag.rsplit("}", 1)[-1]
        if tag in _SHAPES:
            child.set("stroke", HIGHLIGHT_STROKE)
            child.set("stroke-width", HIGHLIGHT_WIDTH)
            if kind == "node":
                child.set("fill", HIGHLIGHT_FILL)
                child.attrib.pop("fill-opacity", None)
            elif kind == "edge" and tag == "polygon":
                child.set("fill", HIGHLIGHT_STROKE)
        elif tag == "text" and kind == "edge":
            child.set("fill", HIGHLIGHT_STROKE)


def _graph_transform(graph: ET.Element) -> tuple[float, float, float]:
    """Return (scale, tx, ty) from Graphviz's top-level group transform."""
    transform = graph.get("transform", "")
    scale = re.search(r"scale\(([-\d.]+)", transform)
    translate = re.search(r"translate\(([-\d.]+)[ ,]+([-\d.]+)\)", transform)
    s = float(scale.group(1)) if scale else 1.0
    tx, ty = (float(v) for v in translate.groups()) if translate else (0.0, 0.0)
    return s, tx, ty


def _thumbnail_svg(
    root: ET.Element, layout: _Layout, selection: _Selection, crop: Box, dim: float
) -> ET.Element:
    svg = copy.deepcopy(root)
    graph = svg.find(f"{{{SVG_NS}}}g")
    if graph is None:
        raise ThumbnailError("unexpected Graphviz SVG: no top-level group")

    visible_clusters = set(selection.clusters)
    for cluster_id, (_, members) in layout.clusters.items():
        if members & selection.nodes:
            visible_clusters.add(cluster_id)

    for group in graph.findall(f"{{{SVG_NS}}}g"):
        group_id = group.get("id", "")
        kind = group.get("class", "")
        if group_id in selection.highlight:
            _style_highlight(group, kind)
            continue
        visible = (
            (kind == "node" and group_id in selection.nodes)
            or (kind == "edge" and group_id in selection.edges)
            or (kind == "cluster" and group_id in visible_clusters)
        )
        if kind in ("node", "edge", "cluster") and not visible:
            group.set("opacity", f"{dim:g}")

    scale, tx, ty = _graph_transform(graph)
    x = (crop.x0 + tx) * scale
    y = (ty - crop.y1) * scale
    width = (crop.x1 - crop.x0) * scale
    height = (crop.y1 - crop.y0) * scale
    svg.set("viewBox", f"{x:.2f} {y:.2f} {width:.2f} {height:.2f}")
    svg.set("width", f"{width:.0f}pt")
    svg.set("height", f"{height:.0f}pt")
    return svg


def _require(tool: str, purpose: str) -> str:
    path = shutil.which(tool)
    if path is None:
        raise ThumbnailError(f"{tool} is required to {purpose} but was not found")
    return path


def _render_layout(dot_source: str) -> tuple[ET.Element, _Layout]:
    dot = _require("dot", "lay out the DFD for thumbnails")
    with tempfile.TemporaryDirectory() as tmp:
        svg_path = Path(tmp, "dfd.svg")
        json_path = Path(tmp, "dfd.json")
        result = subprocess.run(
            [dot, "-Tsvg", "-o", str(svg_path), "-Tjson", "-o", str(json_path)],
            input=dot_source,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ThumbnailError(f"dot failed: {result.stderr.strip()}")
        root = ET.parse(svg_path).getroot()
        layout = _Layout.from_json(json.loads(json_path.read_text(encoding="utf-8")))
    return root, layout


def render_thumbnails(
    tm: Any,
    out_dir: str | Path,
    fmt: str = "png",
    dim: float = 0.3,
    padding: float = 16.0,
    zoom: float = 1.0,
    link_prefix: str | None = None,
    **dfd_kwargs: Any,
) -> dict[str, Path]:
    """Render a thumbnail for every element and piece of data in *tm*.

    Args:
        tm: The threat model (after ``check()``; ``resolve()`` too when
            passing ``colormap=True``).
        out_dir: Directory for the files, created if needed. Each file is
            named after the object's :func:`pytm.anchors.anchor`, e.g.
            ``server-web-server.png``.
        fmt: ``"png"`` (default) or ``"svg"``.
        dim: Opacity of unrelated elements inside the crop (0 to 1).
        padding: Space around the cropped area, in points.
        zoom: PNG scale factor passed to ``rsvg-convert``.
        link_prefix: How report templates should refer to *out_dir*, e.g.
            ``"thumbnails"`` when the report is written next to that
            directory. Defaults to *out_dir* itself. Links are registered so
            ``ReportUtils.getThumbnail`` can return them.
        **dfd_kwargs: Passed to :meth:`TM.dfd`, e.g. ``colormap=True`` or
            ``levels=[0]``, so thumbnails match the main diagram.

    Returns:
        Mapping from anchor to the written file. Objects that are not drawn
        in the DFD (filtered out by ``levels``, or data not carried by any
        dataflow) get no thumbnail.

    Raises:
        ThumbnailError: if ``dot`` (or ``rsvg-convert`` for PNG) is missing or
            fails.
    """
    from .anchors import anchor
    from .tm import TM

    if fmt not in ("png", "svg"):
        raise ValueError(f"unsupported thumbnail format: {fmt!r}")
    rsvg = _require("rsvg-convert", "write PNG thumbnails") if fmt == "png" else None

    dfd_kwargs["ids"] = True
    root, layout = _render_layout(tm.dfd(**dfd_kwargs))

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    prefix = (out.as_posix() if link_prefix is None else link_prefix).rstrip("/")
    written: dict[str, Path] = {}
    seen: set[str] = set()
    for obj in [*TM._elements, *TM._data]:
        name = anchor(obj)
        if name in seen:
            continue
        seen.add(name)
        selection = _select(obj, layout)
        if selection is None:
            continue
        crop = _crop(selection, layout, padding)
        full = layout.graph.padded(padding).area
        # A boundary's thumbnail must show the whole boundary, so only warn
        # for elements whose neighbours happen to be far apart.
        if not selection.clusters and crop.area > LARGE_CROP_RATIO * full:
            logger.warning(
                "thumbnail for %s covers %.0f%% of the DFD; its connected "
                "elements are far apart",
                name,
                100 * crop.area / full,
            )
        svg = ET.tostring(
            _thumbnail_svg(root, layout, selection, crop, dim), encoding="unicode"
        )
        path = out / f"{name}.{fmt}"
        if rsvg is None:
            path.write_text(svg, encoding="utf-8")
        else:
            result = subprocess.run(
                [rsvg, "-f", "png", "-z", f"{zoom:g}", "-o", str(path)],
                input=svg.encode("utf-8"),
                capture_output=True,
            )
            if result.returncode != 0:
                raise ThumbnailError(
                    f"rsvg-convert failed for {name}: "
                    f"{result.stderr.decode(errors='replace').strip()}"
                )
        written[name] = path
        TM._thumbnails[name] = f"{prefix}/{path.name}" if prefix else path.name
    return written
