"""TM.dfd() draws the boundary tree from its roots, without changing the model."""

import random
import re

import pytest

from pytm import TM, Action, Actor, Boundary, Dataflow, Server


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _order(output, names):
    """The names, in the order their nodes or clusters appear in *output*."""
    return sorted(names, key=lambda name: output.index(name))


def _state(element):
    """The element's own field values (references compared by identity)."""
    return {
        name: id(value) if hasattr(value, "uuid") else repr(value)
        for name, value in vars(element).items()
    }


def test_drawing_does_not_change_the_model():
    tm = TM("pure tm", description="d", mergeResponses=True)
    outer = Boundary("Outer")
    web = Server("Web", inBoundary=Boundary("Inner", inBoundary=outer))
    request = Dataflow(Actor("User"), web, "Request")
    Dataflow(web, request.source, "Response", responseTo=request)
    tm.check()
    before = [_state(e) for e in TM._elements]

    tm.dfd()
    tm.dfd(colormap=True, levels=[0])

    assert [_state(e) for e in TM._elements] == before


def test_every_element_is_drawn_once():
    tm = TM("once tm", description="d")
    outer = Boundary("Outer")
    middle = Boundary("Middle", inBoundary=outer)
    inner = Boundary("Inner", inBoundary=middle)
    web = Server("Web", inBoundary=inner)
    db = Server("DB", inBoundary=middle)
    Dataflow(web, db, "Query")
    tm.check()

    output = tm.dfd()

    for element in (outer, middle, inner, web, db):
        name = re.escape(element._uniq_name())
        definitions = re.findall(
            rf"^\s*({name} \[|subgraph cluster_{name} )", output, re.M
        )
        assert len(definitions) == 1, element.name
    # Nesting follows inBoundary.
    assert (
        output.index(f"cluster_{outer._uniq_name()}")
        < output.index(f"cluster_{middle._uniq_name()}")
        < output.index(f"cluster_{inner._uniq_name()}")
        < output.index(web._uniq_name())
    )


def test_root_boundaries_deepest_first_then_by_name():
    tm = TM("order tm", description="d")
    flat_b = Boundary("B flat")
    flat_a = Boundary("A flat")
    deep = Boundary("Z deep")
    Boundary("Child", inBoundary=deep)
    tm.check()

    output = tm.dfd()

    clusters = [f"cluster_{b._uniq_name()}" for b in (flat_a, flat_b, deep)]
    assert _order(output, clusters) == [clusters[2], clusters[0], clusters[1]]


def test_ignored_duplicates_follow_the_last_check():
    tm = TM("dup tm", description="d", onDuplicates=Action.IGNORE)
    user = Actor("User")
    web = Server("Web")
    Dataflow(user, web, "First")
    Dataflow(user, web, "Second")
    tm.check()
    assert tm.dfd().count(" -> ") == 1

    tm.onDuplicates = Action.NO_ACTION
    tm.check()

    assert tm.dfd().count(" -> ") == 2


def test_merged_response_inside_a_boundary_is_hidden():
    # Before: responses were only hidden outside boundaries.
    tm = TM("merge tm", description="d", mergeResponses=True)
    zone = Boundary("Zone")
    user = Actor("User", inBoundary=zone)
    web = Server("Web", inBoundary=zone)
    request = Dataflow(user, web, "Request", inBoundary=zone)
    Dataflow(web, user, "Response", responseTo=request, inBoundary=zone)
    tm.check()

    output = tm.dfd()

    assert output.count(" -> ") == 1
    assert "dir = both;" in output
