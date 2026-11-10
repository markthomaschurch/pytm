"""Cross-references between model objects, for report templates.

Answers the questions a report needs to link its sections together: which
dataflows touch an element, which data it produces or consumes, which
elements handle a piece of data, which threats fired against an element (and
in the model as a whole).

During :meth:`pytm.TM.report` the helpers return the same (copied and
HTML-escaped) objects the template iterates over, so names, links and threat
text are rendered consistently. Outside a report they return the model's own
objects. Relationships are always computed from the model itself and matched
by ``uuid``, so a helper accepts either an original object or its copy.
"""

from __future__ import annotations

from typing import Any


def _uuid(obj: Any) -> str | None:
    value = getattr(obj, "uuid", None)
    return None if value is None else str(value)


class Relations:
    """Index of the model's relationships, optionally for one report."""

    def __init__(self, context: dict[str, Any] | None = None):
        from .tm import TM

        context = context or {}
        self._originals = {_uuid(e): e for e in TM._elements}
        self._flows = list(TM._flows)
        self._elements = list(TM._elements)
        self._data = list(TM._data)
        self._display: dict[str | None, Any] = {}
        for key in ("elements", "assets", "actors", "boundaries", "dataflows"):
            for obj in context.get(key) or []:
                self._display.setdefault(_uuid(obj), obj)
        self._threat_library = list(TM._threats)
        self._threats = list(context.get("threats") or TM._threats)
        if "findings" in context:
            self._findings = list(context["findings"])
        else:
            self._findings = [f for e in self._elements for f in e.findings]

    # -- helpers ----------------------------------------------------------

    def _original(self, obj: Any) -> Any:
        return self._originals.get(_uuid(obj), obj)

    def _show(self, obj: Any) -> Any:
        return self._display.get(_uuid(obj), obj)

    def _data_in(self, collection: Any) -> list[Any]:
        """Model data contained in *collection*, in model order."""
        if not collection or isinstance(collection, str):
            return []
        items = list(collection)
        return [d for d in self._data if any(d == item for item in items)]

    # -- elements and dataflows -------------------------------------------

    def flows(self, element: Any, direction: str | None = None) -> list[Any]:
        """Dataflows attached to *element*: all, ``"in"`` (sink) or ``"out"``."""
        if direction not in (None, "in", "out"):
            raise ValueError(f"direction must be None, 'in' or 'out': {direction!r}")
        uid = _uuid(element)
        result = []
        for flow in self._flows:
            is_source = _uuid(flow.source) == uid
            is_sink = _uuid(flow.sink) == uid
            if (direction in (None, "out") and is_source) or (
                direction in (None, "in") and is_sink
            ):
                result.append(self._show(flow))
        return result

    def data(self, element: Any) -> list[Any]:
        """Data produced or consumed by *element* (or carried by a dataflow)."""
        from .dataflow import Dataflow

        original = self._original(element)
        if isinstance(original, Dataflow):
            return self._data_in(original.data)
        own = getattr(original, "data", None)
        collected = [] if not own or isinstance(own, str) else list(own)
        uid = _uuid(original)
        for flow in self._flows:
            if uid in (_uuid(flow.source), _uuid(flow.sink)):
                collected.extend(flow.data)
        return self._data_in(collected)

    # -- data -------------------------------------------------------------

    def carriers(self, datum: Any) -> list[Any]:
        """Dataflows that carry *datum*."""
        return [self._show(f) for f in self._flows if datum in f.data]

    def handlers(self, datum: Any) -> list[Any]:
        """Elements that send, receive, store or process *datum*."""
        from .dataflow import Dataflow

        uids = set()
        for flow in self._flows:
            if datum in flow.data:
                uids |= {_uuid(flow.source), _uuid(flow.sink)}
        for element in self._elements:
            if isinstance(element, Dataflow):
                continue
            own = getattr(element, "data", None)
            if own and not isinstance(own, str) and datum in own:
                uids.add(_uuid(element))
        for model_datum in self._data:
            if model_datum == datum:
                uids |= {_uuid(e) for e in getattr(model_datum, "processedBy", [])}
        return [
            self._show(e)
            for e in self._elements
            if _uuid(e) in uids and not isinstance(e, Dataflow)
        ]

    def data_findings(self, datum: Any) -> list[Any]:
        """Findings against the dataflows carrying *datum*, in finding order."""
        uids = {_uuid(f) for f in self._flows if datum in f.data}
        return [f for f in self._findings if _uuid(getattr(f, "element", None)) in uids]

    # -- boundaries ---------------------------------------------------------

    def members(self, boundary: Any) -> list[Any]:
        """Elements and boundaries directly inside *boundary*."""
        from .dataflow import Dataflow

        uid = _uuid(boundary)
        return [
            self._show(e)
            for e in self._elements
            if not isinstance(e, Dataflow)
            and _uuid(getattr(e, "inBoundary", None)) == uid
        ]

    # -- findings and threats ---------------------------------------------

    def findings(self, element: Any) -> list[Any]:
        """Findings against *element*."""
        uid = _uuid(element)
        return [f for f in self._findings if _uuid(getattr(f, "element", None)) == uid]

    def threats(self, element: Any) -> list[Any]:
        """Distinct threats that fired against *element*, in library order."""
        ids = {f.threat_id for f in self.findings(element)}
        return [t for t in self._threats if t.id in ids]

    def fired_threats(self) -> list[Any]:
        """Distinct threats with at least one finding, in library order."""
        ids = {f.threat_id for f in self._findings}
        return [t for t in self._threats if t.id in ids]

    def findings_for(self, threat: Any) -> list[Any]:
        """Findings produced by *threat* (a threat, or a threat id)."""
        threat_id = getattr(threat, "id", threat)
        return [f for f in self._findings if f.threat_id == threat_id]


def current() -> Relations:
    """The relations of the report being rendered, or of the whole model."""
    from .tm import TM

    active = TM._get_state().report_relations
    return active if active is not None else Relations()
