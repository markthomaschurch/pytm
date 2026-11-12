"""Dataflow model - represents data flows between elements."""

from typing import Annotated, Optional
from pydantic import Field, field_validator, model_validator

from .roles import Role
from .element import Element, sev_to_color
from .condition_methods import condition_method
from .enums import Classification, TLSVersion
from .base import DataSet


class Dataflow(Element):
    """A data flow from a source to a sink."""

    source: Annotated[Element, Role.DESCRIPTIVE] = Field(
        description="Source element of the data flow"
    )
    sink: Annotated[Element, Role.DESCRIPTIVE] = Field(
        description="Sink element of the data flow"
    )
    isResponse: Annotated[bool, Role.DESCRIPTIVE] = Field(
        default=False, description="Is a response to another data flow"
    )
    response: Annotated[Optional["Dataflow"], Role.DESCRIPTIVE] = Field(
        default=None, description="Another data flow that is a response to this one"
    )
    responseTo: Annotated[Optional["Dataflow"], Role.DESCRIPTIVE] = Field(
        default=None, description="Is a response to this data flow"
    )
    srcPort: Annotated[int, Role.DESCRIPTIVE] = Field(
        default=-1, description="Source TCP port"
    )
    dstPort: Annotated[int, Role.DESCRIPTIVE] = Field(
        default=-1, description="Destination TCP port"
    )
    tlsVersion: Annotated[TLSVersion, Role.SAFEGUARD] = Field(
        default=TLSVersion.NONE, description="TLS version used"
    )
    protocol: Annotated[str, Role.SAFEGUARD] = Field(
        default="", description="Protocol used in this data flow"
    )
    data: Annotated[DataSet, Role.DESCRIPTIVE] = Field(
        default_factory=DataSet,
        description="pytm.Data object(s) in incoming data flows",
    )
    order: Annotated[int, Role.BOOKKEEPING] = Field(
        default=-1, description="Number of this data flow in the threat model"
    )
    implementsCommunicationProtocol: Annotated[bool, Role.DESCRIPTIVE] = Field(
        default=False, description="Does this flow implement a communication protocol"
    )
    note: Annotated[str, Role.BOOKKEEPING] = Field(
        default="", description="Note about this data flow"
    )
    usesVPN: Annotated[bool, Role.SAFEGUARD] = Field(
        default=False, description="Does this flow use VPN"
    )
    usesSessionTokens: Annotated[bool, Role.DESCRIPTIVE] = Field(
        default=False, description="Does this flow use session tokens"
    )

    @field_validator("data", mode="before")
    @classmethod
    def validate_data(cls, v):
        """Convert single Data object to DataSet, handle compatibility."""
        from .data import Data

        if isinstance(v, str):
            # Handle legacy string assignment
            return DataSet(
                [
                    Data(
                        name="undefined",
                        description=v,
                        classification=Classification.UNKNOWN,
                    )
                ]
            )

        if isinstance(v, Data):
            # Single Data object
            return DataSet([v])

        if hasattr(v, "__iter__") and not isinstance(v, (str, bytes)):
            # Iterable of Data objects
            return DataSet(v)

        if isinstance(v, DataSet):
            return v

        return DataSet([v])

    def __setattr__(self, name, value):
        """Handle bidirectional response relationships during assignment."""
        # Set the attribute first
        super().__setattr__(name, value)

        # Skip relationship setup if we're already in the process of linking
        if getattr(self, "_updating_relationships", False):
            return

        # Set up bidirectional relationships for response/responseTo
        if name == "responseTo" and value is not None:
            self._link_response_to(value)
        elif name == "response" and value is not None:
            self._link_response_from(value)

    def _link_response_to(self, target: "Dataflow") -> None:
        """Link this dataflow as a response to the target dataflow."""
        object.__setattr__(self, "_updating_relationships", True)
        try:
            # Mark this as a response
            if not self.isResponse:
                object.__setattr__(self, "isResponse", True)
            # Set reverse link on target
            if target.response is None:
                object.__setattr__(target, "response", self)
        finally:
            object.__setattr__(self, "_updating_relationships", False)

    def _link_response_from(self, source: "Dataflow") -> None:
        """Link the source dataflow as a response to this dataflow."""
        object.__setattr__(self, "_updating_relationships", True)
        try:
            # Mark source as a response
            if not source.isResponse:
                object.__setattr__(source, "isResponse", True)
            # Set reverse link on source
            if source.responseTo is None:
                object.__setattr__(source, "responseTo", self)
        finally:
            object.__setattr__(self, "_updating_relationships", False)

    @model_validator(mode="after")
    def setup_response_relationships(self) -> "Dataflow":
        """Set up bidirectional response relationships after validation."""
        # Set up bidirectional response relationship if responseTo is set
        if self.responseTo is not None:
            if not self.isResponse:
                object.__setattr__(self, "isResponse", True)
            if self.responseTo.response is None:
                object.__setattr__(self.responseTo, "response", self)

        # Handle reverse relationship
        if self.response is not None:
            if not self.response.isResponse:
                object.__setattr__(self.response, "isResponse", True)
            if self.response.responseTo is None:
                object.__setattr__(self.response, "responseTo", self)

        return self

    def __init__(self, source: Element, sink: Element, name: str, **data):
        """Create a Dataflow between two elements.

        Args:
            source: Source element of the data flow.
            sink: Sink element of the data flow.
            name: Name of this data flow.
            **data: Additional field values (e.g. protocol, tlsVersion, srcPort).
        """
        # Handle positional arguments
        data["source"] = source
        data["sink"] = sink
        data["name"] = name
        super().__init__(**data)
        # Register with TM flows
        self._register_with_tm_flows()

    def _register_with_tm_flows(self):
        """Register this dataflow with the TM class."""
        try:
            from .tm import TM

            TM._flows.append(self)
        except ImportError:
            pass

    def _anchor_base(self) -> str:
        """Unnamed dataflows are named after their ends: ``<source>-to-<sink>``."""
        from .anchors import slugify, type_prefix

        name = slugify(self.name, fallback="") or slugify(
            f"{self.source.name} to {self.sink.name}"
        )
        return f"{type_prefix(self)}-{name}"

    def display_label(self) -> str:
        """Name to show in reports; unnamed dataflows show ``<source> to <sink>``."""
        name = str(self.name or "").strip()
        if name:
            return name
        return f"{self.source.display_label()} to {self.sink.display_label()}"

    def display_name(self) -> str:
        """Get display name for this dataflow."""
        if self.order == -1:
            return self.name
        return f"({self.order}) {self.name}"

    def _dfd_template(self) -> str:
        """Template for DFD representation."""
        return """{source} -> {sink} [
{id}    color = {color};
    fontcolor = {color};
    dir = {direction};
    label = "{label}";
]
"""

    def dfd(self, mergeResponses: bool = False, **kwargs) -> str:
        """Generate DFD representation of this dataflow."""

        levels = kwargs.get("levels", None)
        if (
            levels
            and not levels & self.levels
            and not (levels & self.source.levels and levels & self.sink.levels)
        ):
            return ""

        color = self._color()

        if kwargs.get("colormap", False):
            color = sev_to_color(self.severity, bool(self.findings))

        direction = "forward"
        label = self._label()
        if mergeResponses and self.response is not None:
            direction = "both"
            label += "\n" + self.response._label()

        return self._dfd_template().format(
            source=self.source._uniq_name(),
            sink=self.sink._uniq_name(),
            id=self._dfd_id(**kwargs),
            direction=direction,
            label=label,
            color=color,
        )

    @condition_method(
        "any(d.classification > self.source.maxClassification"
        " or d.classification > self.sink.maxClassification"
        " or d.classification > self.maxClassification for d in self.data)"
    )
    def hasDataLeaks(self) -> bool:
        """Check if this dataflow has data leaks."""
