"""TM (Threat Model) - the main container for all threat model elements."""

from __future__ import annotations

import copy
import json
import logging
import os
import random
import re
import sys
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime
from itertools import combinations
from textwrap import indent
from typing import Any, ClassVar, Dict, Iterable, List, TYPE_CHECKING
from html import escape as html_escape

from pydantic import BaseModel, Field, ConfigDict, field_validator

from .enums import Action
from .base import Assumption
from .template_engine import SuperFormatter

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .element import Element
    from .asset import Asset
    from .actor import Actor
    from .dataflow import Dataflow
    from .boundary import Boundary
    from .data import Data
    from .threat import Threat
    from .finding import Finding


class UIError(Exception):
    """Exception for UI-related errors."""

    def __init__(self, e, context):
        self.error = e
        self.context = context


def _resolve_model_path(path: str) -> str:
    """*path*, looked up next to the model script if it is relative.

    A relative path is resolved against the directory of the script being
    run (the model), so a model finds its files whether it is run from its
    own directory or from elsewhere; if there is no such file there, the
    path is used as given (relative to the current directory).
    """
    if os.path.isabs(path):
        return path
    script = getattr(sys.modules.get("__main__"), "__file__", None)
    if script:
        candidate = os.path.join(os.path.dirname(os.path.abspath(script)), path)
        if os.path.exists(candidate):
            return candidate
    return path


@dataclass
class TMState:
    """Mutable registry for TM-owned collections."""

    flows: List["Dataflow"] = field(default_factory=list)
    elements: List["Element"] = field(default_factory=list)
    actors: List["Actor"] = field(default_factory=list)
    assets: List["Asset"] = field(default_factory=list)
    threats: List["Threat"] = field(default_factory=list)
    boundaries: List["Boundary"] = field(default_factory=list)
    data: List["Data"] = field(default_factory=list)
    threats_excluded: List[str] = field(default_factory=list)
    # link anchors already given to elements and data (see pytm.anchors)
    anchors: set[str] = field(default_factory=set)
    # dataflows hidden by check() as duplicates (onDuplicates=Action.IGNORE)
    ignored_duplicates: List["Dataflow"] = field(default_factory=list)
    # anchor -> link to the element's thumbnail, filled by render_thumbnails()
    thumbnails: dict[str, str] = field(default_factory=dict)
    # legend item key -> link to its image, filled by render_legend_images()
    legend_images: dict[str, str] = field(default_factory=dict)
    # relations of the report being rendered (see pytm.relations.current())
    report_relations: Any = None


class _StateAttribute:
    """Descriptor that proxies attribute access to the shared TM state."""

    def __init__(self, field_name: str):
        self.field_name = field_name
        self.owner: type["TM"] | None = None

    def __set_name__(self, owner, name):
        self.owner = owner
        register = getattr(owner, "_register_state_attribute", None)
        if callable(register):
            register(name, self)

    def __get__(self, instance, owner=None):
        owner = owner or self.owner
        if owner is None:
            raise AttributeError("State attribute descriptor is unbound")
        return getattr(owner._state, self.field_name)

    def __set__(self, instance, value):
        owner = self.owner if instance is None else type(instance)
        if owner is None:
            raise AttributeError("State attribute descriptor is unbound")
        setattr(owner._state, self.field_name, value)


class TMModelMetaclass(type(BaseModel)):
    """Metaclass that keeps TM state descriptors intact on class assignment."""

    def __setattr__(cls, name, value):
        state_attrs = getattr(cls, "_state_attributes", None)
        if state_attrs and name in state_attrs:
            descriptor = state_attrs[name]
            descriptor.__set__(None, value)
            return
        super().__setattr__(name, value)


def plantuml_escape(text: str) -> str:
    """Escape *text* for PlantUML sequence diagram names, messages and notes.

    PlantUML turns ``\\n`` and ``\\t`` in text into a newline and a tab, and
    reads a trailing ``\\`` as a line continuation (which swallows the next
    line, e.g. ``@enduml``). Backslash escaping is not applied consistently,
    so backslashes and double quotes are written as PlantUML Unicode escapes.
    """
    return text.replace("\\", "<U+005C>").replace('"', "<U+0022>")


class TM(BaseModel, metaclass=TMModelMetaclass):
    """Describes the threat model administratively, and holds all details during a run."""

    model_config = ConfigDict(
        extra="allow", validate_assignment=True, arbitrary_types_allowed=True
    )

    _state: ClassVar[TMState] = TMState()
    _state_attributes: ClassVar[Dict[str, _StateAttribute]] = {}
    _duplicate_ignored_attrs: ClassVar[tuple[str, ...]] = ()

    @classmethod
    def _register_state_attribute(cls, name: str, descriptor: _StateAttribute) -> None:
        cls._state_attributes[name] = descriptor

    _flows: ClassVar[_StateAttribute] = _StateAttribute("flows")
    _elements: ClassVar[_StateAttribute] = _StateAttribute("elements")
    _actors: ClassVar[_StateAttribute] = _StateAttribute("actors")
    _assets: ClassVar[_StateAttribute] = _StateAttribute("assets")
    _threats: ClassVar[_StateAttribute] = _StateAttribute("threats")
    _boundaries: ClassVar[_StateAttribute] = _StateAttribute("boundaries")
    _data: ClassVar[_StateAttribute] = _StateAttribute("data")
    _threatsExcluded: ClassVar[_StateAttribute] = _StateAttribute("threats_excluded")
    _thumbnails: ClassVar[_StateAttribute] = _StateAttribute("thumbnails")
    _legend_images: ClassVar[_StateAttribute] = _StateAttribute("legend_images")

    @classmethod
    def _get_state(cls) -> TMState:
        """Return the mutable shared state for this TM class."""
        return cls._state

    name: str = Field(description="Model name")
    description: str = Field(description="Model description")
    threatsFile: str = Field(
        default_factory=lambda: os.path.dirname(__file__) + "/threatlib/threats.json",
        description="JSON file with custom threats",
    )
    extraThreatsFiles: List[str] = Field(
        default_factory=list,
        description="More JSON threat files, loaded after threatsFile; a relative path is looked up next to the model script, then in the current directory",
    )
    isOrdered: bool = Field(
        default=False, description="Automatically order all Dataflows"
    )
    mergeResponses: bool = Field(
        default=False, description="Merge response edges in DFDs"
    )
    ignoreUnused: bool = Field(
        default=False, description="Ignore elements not used in any Dataflow"
    )
    findings: List["Finding"] = Field(
        default_factory=list, description="Threats found for elements of this model"
    )
    excluded_findings: List["Finding"] = Field(
        default_factory=list,
        description="Threats found for elements of this model, that were excluded on a per-element basis, using the Assumptions class",
    )
    onDuplicates: Action = Field(
        default=Action.NO_ACTION,
        description="How to handle duplicate Dataflow with same properties, except name and notes",
    )
    assumptions: List[Assumption] = Field(
        default_factory=list, description="A list of assumptions about the design/model"
    )
    colormap: bool = Field(default=False, exclude=True)

    @field_validator("extraThreatsFiles", mode="before")
    @classmethod
    def _normalize_extra_threats_files(cls, value):
        """Allow a single path as well as a list of paths."""
        if value is None:
            return []
        if isinstance(value, (str, os.PathLike)):
            return [os.fspath(value)]
        return [os.fspath(item) for item in value]

    @field_validator("assumptions", mode="before")
    @classmethod
    def _normalize_assumptions(cls, value):
        """Allow string assumptions to be converted into Assumption models."""
        if value is None or value == []:
            return []

        def convert(item):
            if isinstance(item, Assumption):
                return item
            if isinstance(item, dict):
                return item
            if isinstance(item, str):
                return {"name": item}
            raise TypeError(
                "assumptions must be strings, dicts, or Assumption instances"
            )

        if isinstance(value, (str, dict, Assumption)):
            return [convert(value)]

        if isinstance(value, Iterable) and not isinstance(value, (bytes, str)):
            return [convert(item) for item in value]

        raise TypeError(
            "assumptions must be provided as an iterable of supported types"
        )

    def __init__(self, name: str, description: str = "", **data):
        """Initialize the threat model."""
        data.update({"name": name, "description": description})

        object.__setattr__(self, "_initializing_tm", True)
        super().__init__(**data)
        object.__setattr__(self, "_initializing_tm", False)

        self._sf = SuperFormatter()
        random.seed(0)

        try:
            self._init_threats()
        except UIError as e:
            raise e
        finally:
            if hasattr(self, "_initializing_tm"):
                object.__delattr__(self, "_initializing_tm")

    def __setattr__(self, name, value):
        # Changing the threat files reloads the threats (and restores the
        # previous files if the new ones can't be loaded).
        if name in ("threatsFile", "extraThreatsFiles") and not getattr(
            self, "_initializing_tm", False
        ):
            current_value = getattr(self, name, None)
            if current_value == value:
                return super().__setattr__(name, value)

            super().__setattr__(name, value)
            try:
                self._init_threats()
            except UIError as e:
                object.__setattr__(self, "_initializing_tm", True)
                try:
                    super().__setattr__(name, current_value)
                finally:
                    object.__setattr__(self, "_initializing_tm", False)

                if current_value is not None:
                    try:
                        self._init_threats()
                    except UIError:
                        TM._get_state().threats.clear()
                raise e
            return

        super().__setattr__(name, value)

    @classmethod
    def reset(cls):
        """Reset all class variables."""
        cls._state = TMState()

    def _init_threats(self):
        """Initialize threats from file."""
        TM._get_state().threats.clear()
        self._add_threats()

    def _add_threats(self):
        """Add threats from threatsFile, then from each of extraThreatsFiles.

        A threat id defined in more than one file is an error.
        """
        from .threat import Threat

        defined_in: dict[str, str] = {}
        paths = [self.threatsFile] + [
            _resolve_model_path(path) for path in self.extraThreatsFiles
        ]
        for path in paths:
            try:
                with open(path, "r", encoding="utf8") as threat_file:
                    threats_json = json.load(threat_file)
            except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
                raise UIError(e, f"while trying to open the threat file ({path}).")

            for entry in threats_json:
                if "DEPRECATED" in entry:
                    continue
                sid = entry.get("SID")
                if sid in defined_in:
                    raise UIError(
                        ValueError(f"threat {sid} is defined more than once"),
                        f"while loading threats: {sid} is in both "
                        f"{defined_in[sid]} and {path}.",
                    )
                defined_in[sid] = path
                TM._threats.append(Threat(**entry))

    def check(self):
        """Check the threat model for consistency and completeness."""
        if self.description is None:
            raise ValueError(
                """Every threat model should have at least
a brief description of the system being modeled."""
            )

        from . import pytm as pytm_module

        state = TM._get_state()
        state.flows = pytm_module._match_responses(
            pytm_module._sort(state.flows, getattr(self, "isOrdered", False))
        )

        self._check_duplicates(state.flows)

        pytm_module._apply_defaults(state.flows, state.data)

        for element in state.elements:
            top = Counter(
                getattr(f, "threat_id", None) for f in getattr(element, "overrides", [])
            ).most_common(1)
            if not top:
                continue
            threat_id, count = top[0]
            if count != 1:
                raise ValueError(
                    f"Finding {threat_id} have more than one override in {element}"
                )

        if getattr(self, "ignoreUnused", False):
            elements, boundaries = pytm_module._get_elements_and_boundaries(state.flows)
            state.elements = elements
            state.boundaries = boundaries

        result = True
        for element in state.elements:
            if not element.check():
                result = False

        if getattr(self, "ignoreUnused", False):
            state.elements = pytm_module._sort_elem(state.elements)

        return result

    def resolve(self):
        """Resolve threats and generate findings."""
        from .finding import Finding
        from collections import defaultdict

        finding_count = 0
        excluded_finding_count = 0
        findings = []
        excluded_findings = []

        # Get global assumptions with exclusions
        global_assumptions = [a for a in self.assumptions if len(a.exclude) > 0]
        elements = defaultdict(list)

        for e in TM._elements:
            if not getattr(e, "inScope", True):
                e.findings = []
                continue

            override_ids = set(f.threat_id for f in getattr(e, "overrides", []))

            # Filter out overrides from source and sink for dataflows
            try:
                source_overrides = set(
                    f.threat_id for f in getattr(e.source, "overrides", [])
                )
                sink_overrides = set(
                    f.threat_id for f in getattr(e.sink, "overrides", [])
                )
                override_ids -= source_overrides | sink_overrides
            except AttributeError:
                pass

            for t in TM._threats:
                if not t.apply(e) and t.id not in override_ids:
                    continue

                if t.id in TM._threatsExcluded:
                    continue

                _continue = False
                element_assumptions = getattr(e, "assumptions", [])
                for assumption in element_assumptions + global_assumptions:
                    if hasattr(assumption, "exclude") and t.id in assumption.exclude:
                        excluded_finding_count += 1
                        f = Finding(
                            e,
                            id=str(excluded_finding_count),
                            threat=t,
                            assumption=assumption,
                        )
                        excluded_findings.append(f)
                        _continue = True
                        break
                if _continue:
                    continue

                finding_count += 1
                f = Finding(e, id=str(finding_count), threat=t)
                findings.append(f)
                elements[e].append(f)

                # Set severity on element
                if hasattr(e, "_set_severity"):
                    e._set_severity(getattr(f, "severity", 0))

        self.findings = findings
        self.excluded_findings = excluded_findings

        for e, findings in elements.items():
            e.findings = findings

    def process(self):
        """Entry point mirroring the legacy CLI workflow."""
        try:
            self._process()
        except UIError as e:  # pragma: no cover - mirrors historical behaviour
            message = "Failed to execute\n" f"    {e.context}\n" f"    {e.error}\n"
            sys.stderr.write(message)
            raise SystemExit(127) from e

    def _process(self):
        """Execute the CLI workflow (check, resolve, render outputs)."""
        from . import pytm as pytm_module

        self.check()

        result = pytm_module.get_args()

        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
        if getattr(result, "debug", False):
            logger.setLevel(logging.DEBUG)

        exclude_raw = getattr(result, "exclude", None)
        if exclude_raw:
            if isinstance(exclude_raw, str):
                tokens = [exclude_raw]
            elif isinstance(exclude_raw, list):
                tokens = [str(item) for item in exclude_raw]
            else:
                tokens = [str(exclude_raw)]

            exclusions: list[str] = []
            for token in tokens:
                exclusions.extend(
                    sid.strip() for sid in token.split(",") if sid and sid.strip()
                )
            TM._threatsExcluded = exclusions

        if getattr(result, "seq", False):
            print(self.seq())

        colormap = getattr(result, "colormap", False)
        if getattr(result, "dfd", False):
            if colormap:
                self.resolve()
            levels = set(getattr(result, "levels", []) or [])
            print(self.dfd(colormap=colormap, levels=levels))
        if getattr(result, "legend", False):
            print(self.legend(colormap=colormap))

        needs_resolution = any(
            getattr(result, attr, None)
            for attr in ("report", "json", "stale_days", "thumbnails")
        )

        if needs_resolution:
            self.resolve()

        if getattr(result, "thumbnails", None):
            from .thumbnails import ThumbnailError, render_thumbnails

            try:
                render_thumbnails(
                    self,
                    result.thumbnails,
                    fmt=getattr(result, "thumbnail_format", "png"),
                    link_prefix=getattr(result, "thumbnail_prefix", None),
                    colormap=getattr(result, "colormap", False),
                    levels=set(getattr(result, "levels", []) or []),
                )
            except (ThumbnailError, OSError) as exc:
                raise UIError(exc, f"while writing thumbnails to {result.thumbnails}")

        if getattr(result, "json", None):
            try:
                with open(result.json, "w", encoding="utf8") as f:
                    json.dump(self, f, default=pytm_module.to_serializable)
            except (FileExistsError, PermissionError, IsADirectoryError) as exc:
                raise UIError(
                    exc, f"while trying to write to the result file ({result.json})"
                )

        if getattr(result, "report", None):
            variables = {}
            for item in getattr(result, "report_var", None) or []:
                key, sep, value = item.partition("=")
                if not sep or not key.strip():
                    raise UIError(
                        ValueError(f"expected KEY=VALUE, got {item!r}"),
                        "while reading --report-var",
                    )
                variables[key.strip()] = value
            print(self.report(result.report, variables))

        describe_targets = getattr(result, "describe", None)
        if describe_targets:
            names = describe_targets.split()
            pytm_module._describe_classes(names)

        if getattr(result, "list_elements", False):
            pytm_module._list_elements()

        if getattr(result, "list_templates", False):
            from .report_templates import packaged_templates

            for name in packaged_templates():
                print(name)

        if getattr(result, "list", False):
            for threat in TM._threats:
                print(
                    f"{getattr(threat, 'id', '')} - {getattr(threat, 'description', '')}"
                )

        if getattr(result, "stale_days", None) is not None:
            print(self._stale(result.stale_days))

    def _stale(self, days: int) -> str:
        """Report source files whose age diverges from the model script."""
        base_path = os.path.dirname(sys.argv[0])
        try:
            tm_path = sys.argv[0]
            tm_mtime = datetime.fromtimestamp(os.stat(tm_path).st_mtime)
        except OSError as err:
            sys.stderr.write(f"{sys.argv[0]} - {err}\n")
            sys.stderr.flush()
            return "[ERROR]"

        print(f"Checking for code {days} days older than this model.")

        for element in TM._elements:
            source_files = getattr(element, "sourceFiles", [])
            for src in source_files:
                try:
                    src_path = os.path.join(base_path, src)
                    src_mtime = datetime.fromtimestamp(os.stat(src_path).st_mtime)
                except OSError as err:
                    sys.stderr.write(f"{sys.argv[0]} - {err}\n")
                    sys.stderr.flush()
                    continue

                # compare unrounded: timedelta.days floors negative deltas
                age = (src_mtime - tm_mtime).total_seconds() / 86400
                if age >= days:
                    print(f"This model is {int(age)} days older than {src_path}.")
                elif age <= -days:
                    print(
                        f"Model script {sys.argv[0]} is only {int(-age)} days newer than source code file {src_path}"
                    )

        return ""

    def _dfd_template(self):
        """Template for DFD generation."""
        return (
            "digraph tm {{\n"
            "    graph [\n"
            "        fontname = Arial;\n"
            "        fontsize = 14;\n"
            "    ]\n"
            "    node [\n"
            "        fontname = Arial;\n"
            "        fontsize = 14;\n"
            "        rankdir = lr;\n"
            "    ]\n"
            "    edge [\n"
            "        shape = none;\n"
            "        arrowtail = onormal;\n"
            "        fontname = Arial;\n"
            "        fontsize = 12;\n"
            "    ]\n"
            '    labelloc = "t";\n'
            "    fontsize = 20;\n"
            "    nodesep = 1;\n"
            "\n"
            "{edges}\n"
            "\n"
            "}}"
        )

    def dfd(self, **kwargs):
        """Generate Data Flow Diagram.

        Drawing has no side effects on the model, so ``dfd()`` can be called
        any number of times (for example with different ``levels`` or
        ``colormap``) and always draws the whole model.
        """
        from .boundary import Boundary

        if "levels" in kwargs:
            levels = kwargs["levels"]
            if not hasattr(levels, "__iter__") or isinstance(levels, str):
                kwargs["levels"] = [levels]
            kwargs["levels"] = set(kwargs["levels"])

        merge = bool(getattr(self, "mergeResponses", False))
        kwargs["mergeResponses"] = merge
        kwargs["skip"] = self._hidden_flows(merge)

        # Draw the boundary tree from its roots: each boundary draws its own
        # members, nested boundaries included, so everything is drawn once.
        # Roots are ordered by the depth of their nesting (deepest first),
        # then by name.
        roots = [b for b in TM._boundaries if b.inBoundary is None]
        roots.sort(key=lambda b: b.name)
        roots.sort(key=self._boundary_height, reverse=True)
        edges = [b.dfd(**kwargs) for b in roots]

        # Then everything outside any boundary.
        for e in TM._elements:
            if (
                not isinstance(e, Boundary)
                and getattr(e, "inBoundary", None) is None
                and id(e) not in kwargs["skip"]
            ):
                edges.append(e.dfd(**kwargs))

        return self._dfd_template().format(
            edges=indent("\n".join(filter(len, edges)), "    ").rstrip("\n")
        )

    def legend(self, colormap: bool = False) -> str:
        """DOT for a standalone legend of the model's DFD (see pytm.legend)."""
        from .legend import legend_dot

        return legend_dot(colormap=colormap)

    @staticmethod
    def _boundary_height(boundary) -> int:
        """Number of boundary levels nested inside *boundary* (0 if none)."""
        children = [b for b in TM._boundaries if b.inBoundary is boundary]
        return max((1 + TM._boundary_height(b) for b in children), default=0)

    def _hidden_flows(self, merge_responses: bool) -> set[int]:
        """ids of the dataflows not drawn as edges of their own.

        Duplicates ignored by check() (``onDuplicates=Action.IGNORE``), and,
        with *merge_responses*, responses drawn on their request's edge.
        """
        hidden = {id(flow) for flow in TM._get_state().ignored_duplicates}
        if merge_responses:
            hidden |= {
                id(flow.response)
                for flow in TM._flows
                if getattr(flow, "response", None) is not None
            }
        return hidden

    def _seq_template(self):
        """Template for sequence diagram generation."""
        return """@startuml
{participants}

{messages}
@enduml"""

    def seq(self):
        """Generate sequence diagram."""
        from .actor import Actor
        from .datastore import Datastore
        from .boundary import Boundary
        from .dataflow import Dataflow

        participants = []
        for e in TM._elements:
            if isinstance(e, Actor):
                participants.append(
                    'actor {0} as "{1}"'.format(
                        e._uniq_name(),
                        plantuml_escape(getattr(e, "display_name", lambda: e.name)()),
                    )
                )
            elif isinstance(e, Datastore):
                participants.append(
                    'database {0} as "{1}"'.format(
                        e._uniq_name(),
                        plantuml_escape(getattr(e, "display_name", lambda: e.name)()),
                    )
                )
            elif not isinstance(e, (Dataflow, Boundary)):
                participants.append(
                    'entity {0} as "{1}"'.format(
                        e._uniq_name(),
                        plantuml_escape(getattr(e, "display_name", lambda: e.name)()),
                    )
                )

        messages = []
        for e in TM._flows:
            message = "{0} -> {1}: {2}".format(
                e.source._uniq_name(),
                e.sink._uniq_name(),
                plantuml_escape(getattr(e, "display_name", lambda: e.name)()),
            )
            note = ""
            if getattr(e, "note", "") != "":
                note = "\nnote left\n{}\nend note".format(plantuml_escape(e.note))
            messages.append("{}{}".format(message, note))

        return self._seq_template().format(
            participants="\n".join(participants), messages="\n".join(messages)
        )

    def report(self, template_path, variables=None):
        """Generate report from template.

        Templates ending in ``.j2`` or ``.jinja`` (e.g. ``report.md.j2``) are
        rendered with Jinja2 (``pip install pytm[jinja]``); all others use
        pytm's built-in format-string templates. Both receive the same data,
        plus any extra *variables* (e.g. ``{"dfd_image": "dfd.png"}``).

        *template_path* is looked up as a file first (relative to the current
        directory), then among the templates shipped with pytm, so
        ``basic_template.md`` or ``report.md.j2`` work from anywhere;
        ``pytm:<name>`` always uses the shipped one (see
        :mod:`pytm.report_templates`).
        """
        from .jinja_report import is_jinja_template, render_jinja
        from .relations import Relations
        from .report_templates import TemplateNotFound, resolve_template

        try:
            template_file = resolve_template(template_path)
        except TemplateNotFound as exc:
            raise UIError(
                exc, f"while looking for the report template ({template_path})."
            )

        from .report_templates import stylesheet_uri

        context = self._report_context()
        # Templates link the stylesheet as {stylesheet}; found like a template
        # (current directory first, then pytm's), overridable as a variable.
        context["stylesheet"] = stylesheet_uri()
        context.update(variables or {})
        state = TM._get_state()
        state.report_relations = Relations(context)
        try:
            if is_jinja_template(template_file):
                return render_jinja(template_file, context)
            return self._report_superformatter(template_file, context)
        finally:
            state.report_relations = None

    def _report_superformatter(self, template_path, context):
        """Render a built-in format-string template."""
        try:
            with open(template_path, encoding="utf-8") as file:
                template = file.read()
        except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
            from .pytm import UIError

            raise UIError(
                e, f"while trying to open the report template file ({template_path})."
            )

        if not hasattr(self, "_sf") or self._sf is None:
            self._sf = SuperFormatter()

        return self._sf.format(template, **context)

    def _report_context(self):
        """Return the data passed to report templates (by both engines)."""

        def _clone(obj):
            copy_method = getattr(obj, "model_copy", None)
            if callable(copy_method):
                return copy_method(deep=True)
            return copy.deepcopy(obj)

        def encode_threat_data(obj):
            """Encode threat data for HTML output."""
            encoded_threat_data = []
            attrs = [
                "description",
                "details",
                "severity",
                "mitigations",
                "example",
                "id",
                "threat_id",
                "references",
                "condition",
                "cvss",
                "response",
                "likelihood",
            ]

            items = obj if isinstance(obj, list) else [obj]

            def _escape_markdown(text: str) -> str:
                return re.sub(r"(?<!\\)\$", r"\\$", text)

            for entry in items:
                if entry is None:
                    continue

                clone = _clone(entry)

                for attr in attrs:
                    value = getattr(entry, attr, None)
                    if isinstance(value, str):
                        sanitized = _escape_markdown(value)
                        setattr(clone, attr, html_escape(sanitized))

                encoded_threat_data.append(clone)
            return encoded_threat_data

        def encode_element_threat_data(elements):
            """Encode element threat data for HTML output."""
            from .base import DataSet

            encoded_elements = []
            for element in elements:
                if element is None:
                    continue

                element_copy = _clone(element)

                attribute_sources = {}

                if hasattr(element, "__dict__"):
                    attribute_sources.update(
                        {
                            k: v
                            for k, v in element.__dict__.items()
                            if not k.startswith("_")
                        }
                    )

                model_fields = getattr(element.__class__, "model_fields", {})
                for attr_name in model_fields:
                    attribute_sources.setdefault(
                        attr_name, getattr(element, attr_name, None)
                    )

                fields_set = getattr(element_copy, "__pydantic_fields_set__", None)

                for attr_name, original_value in attribute_sources.items():
                    if attr_name == "findings":
                        findings_value = encode_threat_data(
                            getattr(element, "findings", [])
                        )
                        object.__setattr__(element_copy, "findings", findings_value)
                        if isinstance(fields_set, set):
                            fields_set.add("findings")
                        continue

                    value = getattr(element, attr_name, None)

                    if isinstance(value, DataSet):
                        if len(value) == 0:
                            value = "[]"
                    elif isinstance(value, set):
                        value = list(value)

                    if isinstance(value, list) and len(value) == 0:
                        value = "[]"

                    object.__setattr__(element_copy, attr_name, value)
                    if isinstance(fields_set, set):
                        fields_set.add(attr_name)

                encoded_elements.append(element_copy)
            return encoded_elements

        threats = encode_threat_data(TM._threats)
        findings = encode_threat_data(getattr(self, "findings", []))
        excluded_findings = encode_threat_data(getattr(self, "excluded_findings", []))

        elements = encode_element_threat_data(TM._elements)
        assets = encode_element_threat_data(TM._assets)
        actors = encode_element_threat_data(TM._actors)
        boundaries = encode_element_threat_data(TM._boundaries)
        flows = encode_element_threat_data(TM._flows)

        data = {
            "tm": self,
            "dataflows": flows,
            "threats": threats,
            "findings": findings,
            "excluded_findings": excluded_findings,
            "elements": elements,
            "assets": assets,
            "actors": actors,
            "boundaries": boundaries,
            "data": TM._data,
        }

        return data

    def _check_duplicates(self, flows):
        """Ensure duplicate dataflows are handled according to configuration."""
        ignored = TM._get_state().ignored_duplicates
        ignored.clear()
        if getattr(self, "onDuplicates", Action.NO_ACTION) == Action.NO_ACTION:
            return

        index = defaultdict(list)
        for flow in flows:
            key = (flow.source, flow.sink)
            index[key].append(flow)

        for grouped_flows in index.values():
            for left, right in combinations(grouped_flows, 2):
                left_attrs = left._attr_values()
                right_attrs = right._attr_values()
                for attr in self._duplicate_ignored_attrs:
                    left_attrs.pop(attr, None)
                    right_attrs.pop(attr, None)
                if left_attrs != right_attrs:
                    continue
                left_controls = getattr(left, "controls", None)
                right_controls = getattr(right, "controls", None)
                if left_controls is not None and right_controls is not None:
                    if left_controls._attr_values() != right_controls._attr_values():
                        continue
                if self.onDuplicates == Action.IGNORE:
                    if all(flow is not right for flow in ignored):
                        ignored.append(right)
                    continue
                raise ValueError(
                    "Duplicate Dataflow found between {} and {}: {} is same as {}".format(
                        left.source,
                        left.sink,
                        left,
                        right,
                    )
                )


# Initialize class variables
TM.reset()
TM._sf = None
TM._duplicate_ignored_attrs = (
    "name",
    "note",
    "order",
    "response",
    "responseTo",
    "controls",
    "uuid",
)
