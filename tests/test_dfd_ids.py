import json
import random
import re
import shutil
import subprocess

import pytest

from pytm import TM, Actor, Boundary, Dataflow, Datastore, Lambda, Server
from pytm.anchors import anchor


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _model(**tm_kwargs):
    tm = TM("ids tm", description="test", **tm_kwargs)
    internet = Boundary("Internet")
    user = Actor("User", inBoundary=internet)
    web = Server("Web Server")
    db = Datastore("SQL Database")
    fn = Lambda("Auth Function")
    login = Dataflow(user, web, "Login")
    token = Dataflow(web, user, "Token", responseTo=login)
    query = Dataflow(web, db, "Query")
    invoke = Dataflow(web, fn, "Invoke")
    tm.check()
    return tm, dict(
        internet=internet,
        user=user,
        web=web,
        db=db,
        fn=fn,
        login=login,
        token=token,
        query=query,
        invoke=invoke,
    )


def test_ids_are_off_by_default():
    tm, _ = _model()

    assert " id = " not in tm.dfd()


def test_every_drawn_object_gets_its_anchor_as_id():
    tm, e = _model()

    output = tm.dfd(ids=True)

    ids = re.findall(r'^\s*id = "([^"]+)";$', output, re.M)
    assert sorted(ids) == sorted(anchor(obj) for obj in e.values())


def test_id_is_first_attribute_of_each_node_edge_and_cluster():
    tm, e = _model()

    output = tm.dfd(ids=True)

    assert f'{e["web"]._uniq_name()} [\n        id = "server-web-server";' in output
    assert f'{e["fn"]._uniq_name()} [\n        id = "lambda-auth-function";' in output
    assert (
        f'{e["web"]._uniq_name()} -> {e["db"]._uniq_name()} [\n'
        '        id = "dataflow-query";'
    ) in output
    assert 'graph [\n            id = "boundary-internet";' in output


def test_merged_response_shares_the_request_edge():
    tm, e = _model(mergeResponses=True)

    output = tm.dfd(ids=True)

    assert 'id = "dataflow-login";' in output
    assert 'id = "dataflow-token";' not in output


def test_ids_combine_with_colormap_and_levels():
    tm, e = _model()
    e["db"].levels = {1}

    output = tm.dfd(ids=True, colormap=True, levels=[0])

    assert 'id = "server-web-server";' in output
    assert 'id = "datastore-sql-database";' not in output


def test_duplicate_names_get_distinct_ids():
    tm = TM("dup tm", description="test")
    Server("Web Server")
    Server("Web Server")
    tm.check()

    ids = re.findall(r'id = "([^"]+)";', tm.dfd(ids=True))

    assert ids == ["server-web-server", "server-web-server-2"]


@pytest.mark.skipif(shutil.which("dot") is None, reason="Graphviz dot not installed")
def test_graphviz_svg_and_json_carry_the_ids():
    tm, e = _model()
    dot = tm.dfd(ids=True)

    def render(fmt):
        return subprocess.run(
            ["dot", f"-T{fmt}"], input=dot, capture_output=True, text=True, check=True
        ).stdout

    svg = render("svg").replace("&#45;", "-")
    for key, kind in [
        ("internet", "cluster"),
        ("user", "node"),
        ("db", "node"),
        ("login", "edge"),
    ]:
        assert f'<g id="{anchor(e[key])}" class="{kind}"' in svg

    layout = json.loads(render("json"))
    object_ids = {o.get("id") for o in layout["objects"]}
    edge_ids = {edge.get("id") for edge in layout["edges"]}
    assert {"boundary-internet", "actor-user", "server-web-server"} <= object_ids
    assert {"dataflow-login", "dataflow-query", "dataflow-invoke"} <= edge_ids
