import random

import pytest

from pytm import TM, Actor, Boundary, Data, Dataflow, Datastore, Server, Threat
from pytm.relations import Relations, current
from pytm.report_util import ReportUtils


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _model():
    tm = TM("relations tm", description="test")
    token = Data("Token")
    profile = Data("Profile")
    user = Actor("User", data=[profile])
    web = Server("Web Server")
    db = Datastore("DB")
    cache = Server("Cache")
    login = Dataflow(user, web, "Login", data=token)
    store = Dataflow(web, db, "Store", data=[token, profile])
    fetch = Dataflow(db, web, "Fetch")
    tm.check()
    # check() rebuilds processedBy from the flows; add an extra processor.
    token.processedBy = [*token.processedBy, cache]
    return tm, locals()


def _names(objects):
    return [o.name for o in objects]


class TestElements:
    def test_flows_all_in_and_out(self):
        _, m = _model()
        rel = Relations()

        assert _names(rel.flows(m["web"])) == ["Login", "Store", "Fetch"]
        assert _names(rel.flows(m["web"], "in")) == ["Login", "Fetch"]
        assert _names(rel.flows(m["web"], "out")) == ["Store"]
        assert rel.flows(m["cache"]) == []
        with pytest.raises(ValueError):
            rel.flows(m["web"], "sideways")

    def test_data_of_element_includes_flows_and_own_data(self):
        _, m = _model()
        rel = Relations()

        assert _names(rel.data(m["user"])) == ["Token", "Profile"]
        assert _names(rel.data(m["db"])) == ["Token", "Profile"]
        assert rel.data(m["cache"]) == []

    def test_data_of_dataflow(self):
        _, m = _model()

        assert _names(Relations().data(m["store"])) == ["Token", "Profile"]
        assert Relations().data(m["fetch"]) == []

    def test_copies_are_matched_by_uuid(self):
        _, m = _model()

        copy = m["web"].model_copy(deep=True)

        assert _names(Relations().flows(copy)) == ["Login", "Store", "Fetch"]


class TestData:
    def test_handlers_include_flow_ends_own_data_and_processed_by(self):
        _, m = _model()
        rel = Relations()

        assert _names(rel.handlers(m["token"])) == ["User", "Web Server", "DB", "Cache"]
        assert _names(rel.handlers(m["profile"])) == ["User", "Web Server", "DB"]

    def test_carriers(self):
        _, m = _model()

        assert _names(Relations().carriers(m["token"])) == ["Login", "Store"]
        # Login also carries Profile: flows inherit their source's own data.
        assert _names(Relations().carriers(m["profile"])) == ["Login", "Store"]


class TestFindingsAndThreats:
    def _resolved(self):
        tm, m = _model()
        TM._threats[:] = [
            Threat(
                SID="T1", target="Server", description="<b>one</b>", condition="True"
            ),
            Threat(SID="T2", target="Datastore", description="two", condition="True"),
            Threat(SID="T3", target="Actor", description="never", condition="False"),
        ]
        tm.resolve()
        return tm, m

    def test_findings_and_threats_per_element(self):
        _, m = self._resolved()
        rel = Relations()

        assert [f.threat_id for f in rel.findings(m["web"])] == ["T1"]
        assert [t.id for t in rel.threats(m["db"])] == ["T2"]
        assert rel.findings(m["user"]) == []

    def test_fired_threats_and_findings_for(self):
        _, m = self._resolved()
        rel = Relations()

        assert [t.id for t in rel.fired_threats()] == ["T1", "T2"]
        assert _names([f.element for f in rel.findings_for("T1")]) == [
            "Web Server",
            "Cache",
        ]
        assert rel.findings_for(TM._threats[2]) == []

    def test_report_returns_escaped_copies(self, tmp_path):
        tm, _ = self._resolved()
        template = tmp_path / "t.md"
        template.write_text(
            "{tm:call:getFiredThreats:{{item.id}}={{item.description}};}",
            encoding="utf-8",
        )

        assert tm.report(str(template)) == "T1=&lt;b&gt;one&lt;/b&gt;;T2=two;"


class TestBoundariesAndDataThreats:
    def test_members_are_direct_children(self):
        TM("members tm", description="test")
        outer = Boundary("Outer")
        inner = Boundary("Inner", inBoundary=outer)
        web = Server("Web", inBoundary=outer)
        Server("Deep", inBoundary=inner)
        Dataflow(web, Actor("User"), "Reply")

        assert _names(Relations().members(outer)) == ["Inner", "Web"]
        assert _names(ReportUtils.getBoundaryMembers(inner)) == ["Deep"]

    def test_data_findings_come_from_the_flows_that_carry_it(self):
        tm, m = _model()
        TM._threats[:] = [
            Threat(SID="F1", target="Dataflow", description="flow", condition="True"),
            Threat(SID="S1", target="Server", description="server", condition="True"),
        ]
        tm.resolve()

        found = Relations().data_findings(m["token"])
        assert [f.threat_id for f in found] == ["F1"] * len(found) and found
        assert {f.element.name for f in found} == {
            f.name for f in TM._flows if m["token"] in f.data
        }
        assert ReportUtils.getDataFindings(Data("Unused")) == []


class TestReportIntegration:
    def test_both_engines_and_report_state(self, tmp_path):
        pytest.importorskip("jinja2")
        tm, _ = _model()
        classic = tmp_path / "t.md"
        classic.write_text(
            "{assets:repeat:{{item.name}}:{{item:call:getFlows:{{{{item.name}}}},}};}",
            encoding="utf-8",
        )
        jinja = tmp_path / "t.md.j2"
        jinja.write_text(
            "{% for a in assets %}{{ a.name }}:"
            "{% for f in flows_of(a) %}{{ f.name }},{% endfor %};{% endfor %}",
            encoding="utf-8",
        )

        expected = "Web Server:Login,Store,Fetch,;DB:Store,Fetch,;Cache:;"
        assert tm.report(str(classic)) == expected
        assert tm.report(str(jinja)) == expected
        assert TM._get_state().report_relations is None

    def test_report_state_is_cleared_after_errors(self, tmp_path):
        tm, _ = _model()

        with pytest.raises(Exception):
            tm.report(str(tmp_path / "missing.md"))

        assert TM._get_state().report_relations is None

    def test_current_outside_a_report_uses_the_model(self):
        _, m = _model()

        assert _names(current().flows(m["db"])) == ["Store", "Fetch"]
        assert _names(ReportUtils.getDataCarriers(m["profile"])) == ["Login", "Store"]
