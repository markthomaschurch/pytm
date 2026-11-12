"""Utilities used by report templates."""

from __future__ import annotations

from typing import Any, List


class ReportUtils:
    """Helper methods exposed to Jinja-style templates via :class:`SuperFormatter`."""

    @staticmethod
    def getParentName(element: Any) -> str:
        """Return the parent boundary name for *element* or an empty string."""
        from pytm import Boundary  # Local import to avoid circular dependency

        if not isinstance(element, Boundary):
            return (
                f"ERROR: getParentName method is not valid for {type(element).__name__}"
            )

        parent = element.inBoundary
        return parent.name if parent is not None else ""

    @staticmethod
    def getNamesOfParents(element: Any) -> List[str] | str:
        """Return a list of parent boundary names for *element*."""
        from pytm import Boundary

        if not isinstance(element, Boundary):
            return f"ERROR: getNamesOfParents method is not valid for {type(element).__name__}"

        return [parent.name for parent in element.parents()]

    @staticmethod
    def getInScopeFindings(element: Any) -> list:
        """Return only findings that belong to an in-scope element and target an in-scope element."""
        from pytm import Element

        if not isinstance(element, Element):
            return []

        if not element.inScope:
            return []

        in_scope_findings = []
        for finding in element.findings:
            target = getattr(finding, "element", None)
            if target is not None and getattr(target, "inScope", False):
                in_scope_findings.append(finding)

        return in_scope_findings

    @staticmethod
    def getFindingCount(element: Any) -> str:
        """Return the count of findings for *element* as a string."""
        from pytm import Element

        if not isinstance(element, Element):
            return f"ERROR: getFindingCount method is not valid for {type(element).__name__}"

        return str(len(list(element.findings)))

    @staticmethod
    def getElementType(element: Any) -> str:
        """Return the class name for *element*."""
        from pytm import Element

        if not isinstance(element, Element):
            return f"ERROR: getElementType method is not valid for {type(element).__name__}"

        return element.__class__.__name__

    @staticmethod
    def getThreatId(obj: Any) -> str:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.threat_id
        return ""

    @staticmethod
    def getFindingDescription(obj: Any) -> str:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.description
        return ""

    @staticmethod
    def getFindingTarget(obj: Any) -> Any:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.target
        return ""

    @staticmethod
    def getFindingSeverity(obj: Any) -> str:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.severity
        return ""

    @staticmethod
    def getFindingMitigations(obj: Any) -> str:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.mitigations
        return ""

    @staticmethod
    def getFindingReferences(obj: Any) -> str:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.references
        return ""

    @staticmethod
    def getFindingExample(obj: Any) -> str:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.example
        return ""

    @staticmethod
    def getAnchor(obj: Any) -> str:
        """Return the link anchor for an element, data, threat or finding.

        Use it for heading IDs and links, e.g. ``#{{item:call:getAnchor}}``.
        """
        from pytm.anchors import anchor

        try:
            return anchor(obj)
        except TypeError:
            return f"ERROR: getAnchor method is not valid for {type(obj).__name__}"

    @staticmethod
    def getThreatAnchor(obj: Any) -> str:
        """Return the anchor of the threat behind a finding (or of a threat)."""
        from pytm import Finding, Threat
        from pytm.anchors import anchor_for_threat_id

        if isinstance(obj, Finding):
            return anchor_for_threat_id(obj.threat_id)
        if isinstance(obj, Threat):
            return anchor_for_threat_id(obj.id)
        return f"ERROR: getThreatAnchor method is not valid for {type(obj).__name__}"

    @staticmethod
    def getThumbnail(obj: Any) -> str:
        """Return the link to *obj*'s thumbnail, or "" if none was rendered.

        Thumbnails are registered by :func:`pytm.thumbnails.render_thumbnails`
        (``--thumbnails DIR`` on the command line).
        """
        from pytm import TM
        from pytm.anchors import anchor

        try:
            return TM._thumbnails.get(anchor(obj), "")
        except TypeError:
            return ""

    @staticmethod
    def getThumbnailMarkdown(obj: Any) -> str:
        """Return a Markdown image of *obj*'s thumbnail, or "" if none."""
        link = ReportUtils.getThumbnail(obj)
        if not link:
            return ""
        from pytm.anchors import label

        name = label(obj)
        for char in "\\[]":  # backslash first, or its escapes get doubled
            name = name.replace(char, f"\\{char}")
        if any(char.isspace() for char in link):
            link = f"<{link}>"
        return f"![{name}]({link})"

    # -- cross-references (see pytm.relations) ------------------------------

    @staticmethod
    def getFlows(obj: Any) -> list:
        """Dataflows attached to an element (as source or sink)."""
        from pytm.relations import current

        return current().flows(obj)

    @staticmethod
    def getInboundFlows(obj: Any) -> list:
        """Dataflows into an element."""
        from pytm.relations import current

        return current().flows(obj, "in")

    @staticmethod
    def getOutboundFlows(obj: Any) -> list:
        """Dataflows out of an element."""
        from pytm.relations import current

        return current().flows(obj, "out")

    @staticmethod
    def getData(obj: Any) -> list:
        """Data an element produces or consumes, or a dataflow carries."""
        from pytm.relations import current

        return current().data(obj)

    @staticmethod
    def getDataHandlers(obj: Any) -> list:
        """Elements that send, receive, store or process a piece of data."""
        from pytm.relations import current

        return current().handlers(obj)

    @staticmethod
    def getDataCarriers(obj: Any) -> list:
        """Dataflows that carry a piece of data."""
        from pytm.relations import current

        return current().carriers(obj)

    @staticmethod
    def getDataFindings(obj: Any) -> list:
        """Findings against the dataflows carrying data."""
        from pytm.relations import current

        return current().data_findings(obj)

    @staticmethod
    def getBoundaryMembers(obj: Any) -> list:
        """Elements and boundaries directly inside a boundary."""
        from pytm.relations import current

        return current().members(obj)

    @staticmethod
    def getElementFindings(obj: Any) -> list:
        """Findings against an element."""
        from pytm.relations import current

        return current().findings(obj)

    @staticmethod
    def getElementThreats(obj: Any) -> list:
        """Distinct threats that fired against an element."""
        from pytm.relations import current

        return current().threats(obj)

    @staticmethod
    def getFiredThreats(obj: Any = None) -> list:
        """Distinct threats with at least one finding (argument ignored).

        Use it as ``{tm:call:getFiredThreats:...}`` for a threat library.
        """
        from pytm.relations import current

        return current().fired_threats()

    @staticmethod
    def getThreatFindings(obj: Any) -> list:
        """Findings produced by a threat."""
        from pytm.relations import current

        return current().findings_for(obj)

    @staticmethod
    def getFindingRemedies(obj: Any) -> list:
        """How to resolve a finding: alternative sets of value changes.

        Each item is a list of changes (``attribute``, ``required``,
        ``current``, ``subject`` and a Markdown ``instruction``); making all
        the changes in any one item makes the threat stop applying.
        """
        from pytm import Finding
        from pytm.relations import current

        if not isinstance(obj, Finding):
            return []
        return current().remedies(obj)
