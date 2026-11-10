import inspect

import pytest
from pydantic import BaseModel

import pytm
from pytm import TM, Actor, Data, Dataflow, Server
from pytm.base import Controls
from pytm.data import Data as DataModel
from pytm.element import Element
from pytm.relations import Change, remedies
from pytm.roles import Role, field_role


def _model_classes():
    """Every model class whose attributes describe a system."""
    classes = {
        obj
        for obj in vars(pytm).values()
        if inspect.isclass(obj)
        and issubclass(obj, BaseModel)
        and (issubclass(obj, Element) or obj in (DataModel, Controls))
    }
    return sorted(classes, key=lambda c: c.__name__)


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    yield
    TM.reset()


@pytest.mark.parametrize("cls", _model_classes(), ids=lambda c: c.__name__)
def test_every_field_declares_a_role(cls):
    # When this fails, add Annotated[<type>, Role.<ROLE>] to the field's
    # declaration: SAFEGUARD for a security measure, DESCRIPTIVE for a fact
    # about the system, BOOKKEEPING for model plumbing (see pytm/roles.py).
    missing = [name for name in cls.model_fields if field_role(cls, name) is None]

    assert missing == [], f"{cls.__name__} fields without a role: {missing}"


@pytest.mark.parametrize(
    "cls, name, role",
    [
        (Server, "usesVPN", Role.SAFEGUARD),
        (Dataflow, "tlsVersion", Role.SAFEGUARD),
        (DataModel, "isSourceEncryptedAtRest", Role.SAFEGUARD),
        (Controls, "sanitizesInput", Role.SAFEGUARD),
        (Dataflow, "isResponse", Role.DESCRIPTIVE),
        (Server, "inScope", Role.DESCRIPTIVE),
        (DataModel, "classification", Role.DESCRIPTIVE),
        (Server, "name", Role.BOOKKEEPING),
        (Dataflow, "order", Role.BOOKKEEPING),
    ],
)
def test_roles(cls, name, role):
    assert field_role(cls, name) is role
    assert role.value in ("safeguard", "descriptive", "bookkeeping")


def test_unknown_and_extra_attributes():
    server = Server("Web")
    server.controls.checksCustomThing = True  # Controls allow extra attributes

    assert field_role(server, "notAnAttribute") is None
    assert field_role(server.controls, "checksCustomThing") is Role.SAFEGUARD
    assert field_role(Controls, "checksCustomThing") is None


def test_remedies_take_roles_from_the_declaring_class():
    tm = TM("roles tm", description="test")
    flow = Dataflow(Actor("User"), Server("Web"), "Login", data=Data("Token"))
    tm.check()
    threat = pytm.Threat(
        SID="X1",
        target="Dataflow",
        description="x",
        condition="target.controls.isEncrypted is False and not target.isResponse"
        " and target.source.inScope",
    )

    options = remedies(threat, flow)

    assert [[(c.attribute, c.role) for c in option] for option in options] == [
        [("controls.isEncrypted", Role.SAFEGUARD)],
        [("isResponse", Role.DESCRIPTIVE)],
        [("source.inScope", Role.DESCRIPTIVE)],
    ]
    # Safeguard-only alternatives are listed first.
    assert [o[0].is_mitigation for o in options] == [True, False, False]


def test_change_without_role_is_not_a_mitigation():
    assert Change("hasDataLeaks()", "False", "True").is_mitigation is False
