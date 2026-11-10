import random
import re

import pytest

from pytm import (
    LLM,
    TM,
    Actor,
    Boundary,
    Data,
    Dataflow,
    ExternalEntity,
    Finding,
    Server,
    Threat,
)
from pytm.anchors import anchor, anchor_for_threat_id, label, slugify
from pytm.report_util import ReportUtils

VALID_ID = re.compile(r"^[a-z][a-z0-9-]*$")


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


class TestSlugify:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("Web Server", "web-server"),
            ("Web Server (v2)", "web-server-v2"),
            ("  --Leading & trailing--  ", "leading-trailing"),
            ("Café Ünïcode", "cafe-unicode"),
            ("C:\\Server\\", "c-server"),
            ('The "admin" user', "the-admin-user"),
            ("INP01", "inp01"),
            (42, "42"),
        ],
    )
    def test_slugify(self, text, expected):
        assert slugify(text) == expected

    @pytest.mark.parametrize("text", ["", "!!!", "データベース"])
    def test_fallback_when_nothing_is_left(self, text):
        assert slugify(text) == "item"
        assert slugify(text, fallback="x") == "x"


class TestElementAnchors:
    def test_type_prefix_and_name(self):
        user = Actor("User")
        web = Server("Web Server")
        flow = Dataflow(user, web, "Login")
        internet = Boundary("Internet")

        assert anchor(user) == "actor-user"
        assert anchor(web) == "server-web-server"
        assert anchor(flow) == "dataflow-login"
        assert anchor(internet) == "boundary-internet"

    def test_unnamed_dataflow_uses_source_and_sink(self):
        user = Actor("User")
        web = Server("Web Server")
        first = Dataflow(user, web, "")
        second = Dataflow(user, web, "")

        assert anchor(first) == "dataflow-user-to-web-server"
        assert anchor(second) == "dataflow-user-to-web-server-2"

    def test_camel_case_and_acronym_class_names(self):
        assert anchor(ExternalEntity("Partner API")) == "external-entity-partner-api"
        assert anchor(LLM("Chat Model")) == "llm-chat-model"

    def test_duplicates_are_numbered_in_creation_order(self):
        first = Server("Web Server")
        second = Server("Web Server")
        # A name that slugifies to the same text as a numbered duplicate.
        third = Server("Web Server 2")

        assert anchor(first) == "server-web-server"
        assert anchor(second) == "server-web-server-2"
        assert anchor(third) == "server-web-server-2-2"

    def test_same_name_different_type_does_not_collide(self):
        assert anchor(Actor("Admin")) == "actor-admin"
        assert anchor(Server("Admin")) == "server-admin"

    def test_copy_has_same_anchor_as_original(self):
        Server("Web Server")
        second = Server("Web Server")

        assert anchor(second.model_copy(deep=True)) == "server-web-server-2"

    def test_unregistered_element_falls_back_to_name(self):
        web = Server("Web Server")
        TM.reset()

        assert anchor(web) == "server-web-server"

    def test_anchor_follows_new_elements(self):
        web = Server("Web Server")
        assert anchor(web) == "server-web-server"

        late = Server("Web Server")
        assert anchor(late) == "server-web-server-2"

    def test_anchors_are_valid_identifiers(self):
        for name in ["Web Server", "!!!", "データベース", "2 Fast", 'Say "hi"']:
            assert VALID_ID.match(anchor(Server(name))), name


class TestDataAnchors:
    def test_data_anchor(self):
        assert anchor(Data("Auth Token")) == "data-auth-token"

    def test_equal_data_get_their_own_anchors(self):
        # Each Data object is listed (and linked) separately in a report.
        first = Data("Token", description="a")
        second = Data("Token", description="a")

        assert (anchor(first), anchor(second)) == ("data-token", "data-token-2")

    def test_different_data_with_same_name_are_numbered(self):
        Data("Token", description="a")
        other = Data("Token", description="b")

        assert anchor(other) == "data-token-2"

    def test_data_anchor_is_kept_after_a_rename(self):
        # Anchors are reserved at creation, so links don't move.
        token = Data("Token")

        token.name = "Session Token"

        assert anchor(token) == "data-token"

    def test_data_does_not_collide_with_elements(self):
        # Element and data anchors share one namespace in a report.
        Server("Token")
        token = Data("Token")

        assert anchor(token) == "data-token"


class TestThreatAndFindingAnchors:
    def test_threat_anchor_uses_sid(self):
        threat = Threat(SID="INP01", target="Server", description="x")

        assert anchor(threat) == "threat-inp01"
        assert anchor_for_threat_id("INP01") == "threat-inp01"

    def test_finding_anchor_and_its_threat(self):
        web = Server("Web Server")
        threat = Threat(SID="INP01", target="Server", description="x")
        finding = Finding(web, id="7", threat=threat)

        assert anchor(finding) == "finding-7"
        assert ReportUtils.getThreatAnchor(finding) == "threat-inp01"
        assert ReportUtils.getThreatAnchor(threat) == "threat-inp01"

    def test_unsupported_type(self):
        with pytest.raises(TypeError):
            anchor("not a model object")
        assert ReportUtils.getAnchor("x").startswith("ERROR: getAnchor")
        assert ReportUtils.getThreatAnchor("x").startswith("ERROR: getThreatAnchor")


def test_report_template_gets_anchors_for_copied_elements(tmp_path):
    # TM.report() passes deep copies of elements to templates.
    tm = TM("anchor tm", description="test")
    user = Actor("User")
    Server("Web Server")
    duplicate = Server("Web Server")
    Dataflow(user, duplicate, "Login", data=Data("Token"))
    template = tmp_path / "template.md"
    template.write_text(
        "{assets:repeat:{{item:call:getAnchor}} }\n"
        "{dataflows:repeat:{{item:call:getAnchor}} }\n"
        "{data:repeat:{{item:call:getAnchor}} }\n",
        encoding="utf-8",
    )
    tm.check()
    tm.resolve()

    report = tm.report(str(template))

    assert report.splitlines() == [
        "server-web-server server-web-server-2 ",
        "dataflow-login ",
        "data-token ",
    ]


def test_label_falls_back_for_unnamed_objects():
    user = Actor("User")
    web = Server("Web Server")

    assert label(web) == "Web Server"
    assert label(Dataflow(user, web, "")) == "User to Web Server"
    assert label(Dataflow(user, web, "  ")) == "User to Web Server"
    assert label(Data("")) == "(unnamed Data)"
    assert label(Server("")) == "(unnamed Server)"


def test_reset_starts_a_new_set_of_anchors():
    Server("Web Server")
    TM.reset()

    assert anchor(Server("Web Server")) == "server-web-server"


def test_subclasses_can_name_their_own_anchors():
    class Gateway(Server):
        def _anchor_base(self) -> str:
            return "gw-" + super()._anchor_base()

    assert anchor(Gateway("Edge")) == "gw-gateway-edge"
    assert anchor(Gateway("Edge")) == "gw-gateway-edge-2"


def test_anchor_is_an_attribute_of_model_objects():
    web = Server("Web Server")
    threat = Threat(SID="INP01", target="Server", description="x")

    assert web.anchor == anchor(web) == "server-web-server"
    assert threat.anchor == "threat-inp01"
    assert Finding(web, id="3", threat=threat).anchor == "finding-3"
