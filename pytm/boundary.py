"""Boundary model - represents trust boundaries in the threat model."""

from typing import List, TYPE_CHECKING
from textwrap import indent

from .element import Element

if TYPE_CHECKING:
    pass


class Boundary(Element):
    """Trust boundary groups elements and data with the same trust level."""

    def __init__(self, name: str = None, **data):
        super().__init__(name, **data)
        # Register with TM boundaries
        self._register_with_tm_boundaries()

    def _register_with_tm_boundaries(self):
        """Register this boundary with the TM class."""
        try:
            from .tm import TM

            if self.name not in TM._boundaries:
                TM._boundaries.append(self)
        except ImportError:
            pass

    def _dfd_template(self) -> str:
        """Template for DFD representation."""
        return """subgraph cluster_{uniq_name} {{
    graph [
{id}        fontsize = 10;
        fontcolor = black;
        style = dashed;
        color = {color};
        label = <<i>{label}</i>>;
    ]

{edges}
}}
"""

    def dfd(self, **kwargs) -> str:
        """Generate DFD representation of this boundary and its members.

        Members include nested boundaries, which draw their own members.
        Dataflows whose id is in ``kwargs["skip"]`` are left out.
        """
        skip = kwargs.get("skip", ())
        edges = []
        try:
            from .tm import TM

            for e in TM._elements:
                if e.inBoundary is not self or id(e) in skip:
                    continue
                edges.append(e.dfd(**kwargs))
        except ImportError:
            pass

        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            id=self._dfd_id(indent="        ", **kwargs),
            label=self._html_label(),
            color=self._color(**kwargs),
            edges=indent("\n".join(edges), "    "),
        )

    def _color(self, **kwargs) -> str:
        """Get color for DFD representation."""
        if kwargs.get("colormap", False):
            return "black"
        else:
            return "firebrick2"

    def parents(self) -> List["Boundary"]:
        """Get parent boundaries, raising ValueError for a cyclic hierarchy."""
        result = []
        visited = {id(self)}
        parent = self.inBoundary
        while parent is not None:
            if id(parent) in visited:
                raise ValueError(f"Cyclic trust boundary hierarchy at {parent.name!r}")
            visited.add(id(parent))
            result.append(parent)
            parent = parent.inBoundary
        return result
