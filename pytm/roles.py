"""What each model attribute means for threat analysis.

Every field of a model class that describes the system (elements, data and
controls) declares its role next to its type::

    usesVPN: Annotated[bool, Role.SAFEGUARD] = Field(default=False, ...)

A model class can instead give all of its fields one role with a
``pytm_default_role`` class variable (``Controls`` does: every control is a
safeguard).

Analyses read roles with :func:`field_role` rather than keeping their own
lists of attribute names. For example, when pytm suggests how to resolve a
finding, changing a safeguard is a mitigation, while changing a descriptive
attribute only describes the system differently. ``tests/test_roles.py``
fails if a field has no role, so a new attribute cannot be added without
deciding what it means.
"""

from __future__ import annotations

import enum
from typing import Any


class Role(enum.Enum):
    """The role of a model attribute."""

    SAFEGUARD = "safeguard"
    """A security measure: turning it on or tightening it mitigates threats
    (controls, encryption, TLS versions, VPNs, protocols, ...)."""

    DESCRIPTIVE = "descriptive"
    """A fact about the system that threat conditions test (``isResponse``,
    ``inScope``, a data item's ``classification``, ...). Changing it makes
    threats apply differently without making anything safer, so it is only
    right when the model is inaccurate."""

    BOOKKEEPING = "bookkeeping"
    """Model plumbing and documentation (``name``, ``uuid``, ``findings``,
    ``levels``, ...): never part of a remedy."""


def field_role(model: Any, name: str) -> Role | None:
    """Role of attribute *name* on *model* (a model class or instance).

    Attributes a model accepts beyond its declared fields (``extra="allow"``,
    e.g. a custom control) get the class's ``pytm_default_role``. Returns
    None for unknown attributes and fields without a role.
    """
    cls = model if isinstance(model, type) else type(model)
    fields = getattr(cls, "model_fields", {})
    info = fields.get(name)
    if info is None:
        allows_extra = getattr(cls, "model_config", {}).get("extra") == "allow"
        if allows_extra and not isinstance(model, type) and hasattr(model, name):
            return getattr(cls, "pytm_default_role", None)
        return None
    for item in info.metadata:
        if isinstance(item, Role):
            return item
    return getattr(cls, "pytm_default_role", None)
