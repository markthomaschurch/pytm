import random

import pytest

from pytm import (
    TM,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    Server,
    Threat,
)
from pytm.relations import Change, Relations, current, format_condition, remedies
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
        assert ReportUtils.getFindingRemedies("not a finding") == []


class TestRemedies:
    def _threat(self, condition, target="Server"):
        return Threat(SID="X1", target=target, description="x", condition=condition)

    def _fixes(self, condition, element):
        return [
            [(c.subject, c.attribute, c.required, c.current) for c in option]
            for option in remedies(self._threat(condition), element)
        ]

    def test_flag_is_false(self):
        web = Server("Web")

        assert self._fixes("target.controls.sanitizesInput is False", web) == [
            [("target", "controls.sanitizesInput", "True", "False")]
        ]

    def test_and_gives_alternatives_or_needs_all(self):
        web = Server("Web")

        assert self._fixes(
            "target.controls.sanitizesInput is False and "
            "target.controls.validatesInput is False",
            web,
        ) == [
            [("target", "controls.sanitizesInput", "True", "False")],
            [("target", "controls.validatesInput", "True", "False")],
        ]
        assert self._fixes(
            "target.controls.sanitizesInput is False or "
            "target.controls.validatesInput is False",
            web,
        ) == [
            [
                ("target", "controls.sanitizesInput", "True", "False"),
                ("target", "controls.validatesInput", "True", "False"),
            ]
        ]

    def test_only_true_parts_of_an_or_need_fixing(self):
        web = Server("Web")
        web.controls.validatesInput = True

        assert self._fixes(
            "target.controls.sanitizesInput is False or "
            "target.controls.validatesInput is False",
            web,
        ) == [[("target", "controls.sanitizesInput", "True", "False")]]

    def test_not_and_truthiness(self):
        web = Server("Web", usesVPN=True)

        assert self._fixes("not target.controls.isEncrypted", web) == [
            [("target", "controls.isEncrypted", "True", "False")]
        ]
        assert self._fixes("target.usesVPN", web) == [
            [("target", "usesVPN", "False", "True")]
        ]

    @pytest.mark.parametrize(
        "condition, required",
        [
            ("target.protocol == 'HTTP'", "not 'HTTP'"),
            ("'HTTP' == target.protocol", "not 'HTTP'"),
            ("target.protocol != 'HTTPS'", "'HTTPS'"),
            ("target.protocol in ('HTTP', 'FTP')", "not one of ['HTTP', 'FTP']"),
            ("target.minTLSVersion < TLSVersion.TLSv12", ">= TLSVersion.TLSv12"),
            ("TLSVersion.TLSv12 > target.minTLSVersion", ">= TLSVersion.TLSv12"),
        ],
    )
    def test_comparisons(self, condition, required):
        flow = Dataflow(Actor("User"), Server("Web"), "Login", protocol="HTTP")

        [[(_, attribute, found, _)]] = [
            [(c.subject, c.attribute, c.required, c.current) for c in o]
            for o in remedies(self._threat(condition, "Dataflow"), flow)
        ]

        assert found == required
        assert attribute in ("protocol", "minTLSVersion")

    def test_any_over_data_names_each_item(self):
        tm = TM("remedy tm", description="test")
        secret = Data("Secret", isPII=True)
        other = Data("Other", isPII=True)
        flow = Dataflow(Actor("User"), Server("Web"), "Login", data=[secret, other])
        tm.check()

        [option] = remedies(
            self._threat("any(d.isPII for d in target.data)", "Dataflow"), flow
        )

        assert [
            (c.subject, c.attribute, c.required, c.subject_anchor) for c in option
        ] == [
            ('data "Other"', "isPII", "False", "data-other"),
            ('data "Secret"', "isPII", "False", "data-secret"),
        ]

    def test_has_data_leaks_names_classifications(self):
        tm = TM("leak tm", description="test")
        token = Data("Token", classification=Classification.SECRET)
        user = Actor("User", maxClassification=Classification.SECRET)
        web = Server("Web", maxClassification=Classification.RESTRICTED)
        flow = Dataflow(
            user, web, "Login", data=token, maxClassification=Classification.SECRET
        )
        tm.check()

        options = self._fixes("target.hasDataLeaks()", flow)

        assert options == [
            [
                (
                    'data "Token"',
                    "classification",
                    "<= Classification.RESTRICTED",
                    "Classification.SECRET",
                )
            ],
            [
                (
                    "target",
                    "sink.maxClassification",
                    ">= Classification.SECRET",
                    "Classification.RESTRICTED",
                )
            ],
        ]

    def test_constant_condition_has_no_remedy(self):
        assert remedies(self._threat("True"), Server("Web")) == []
        assert remedies(self._threat(""), Server("Web")) == []

    @pytest.mark.parametrize(
        "attribute, required, expected",
        [
            ("controls.isHardened", "True", "set `controls.isHardened` to `True`"),
            (
                "protocol",
                "not 'HTTP'",
                "set `protocol` to something other than `'HTTP'`",
            ),
            (
                "minTLSVersion",
                ">= TLSVersion.TLSv12",
                "set `minTLSVersion` to `TLSVersion.TLSv12` or higher",
            ),
            (
                "classification",
                "<= Classification.PUBLIC",
                "set `classification` to `Classification.PUBLIC` or lower",
            ),
            ("port", "one of (80, 443)", "set `port` to one of `(80, 443)`"),
            (
                "port",
                "not one of (80, 443)",
                "set `port` to a value other than `(80, 443)`",
            ),
            (
                "description",
                "a false or empty value",
                "set `description` to a false or empty value",
            ),
            ("hasDataLeaks()", "False", "make `hasDataLeaks()` return `False`"),
        ],
    )
    def test_instruction(self, attribute, required, expected):
        assert Change(attribute, required, "x").instruction == expected


def test_every_remedy_resolves_its_finding():
    """Apply each suggested change and check the threat no longer applies."""
    import ast

    import pytm

    tm = TM("verify tm", description="test")
    internet = Boundary("Internet")
    user = Actor("User", inBoundary=internet)
    web = Server("Web", OS="Linux", usesSessionTokens=True)
    db = Datastore("DB", isSQL=True)
    token = Data("Token", classification=Classification.SECRET, isCredentials=True)
    comment = Data("Comment", isPII=True, format="JSON")
    login = Dataflow(user, web, "Login", data=[token, comment], protocol="HTTP")
    Dataflow(web, db, "Store", data=comment)
    Dataflow(web, user, "Reply", responseTo=login)
    tm.check()
    tm.resolve()
    threats = {t.id: t for t in TM._threats}
    checked = 0

    def value(required):
        if required.startswith(("not ", "< ", "> ", "a ", "one of")):
            return None
        text = required[3:] if required[:3] in ("<= ", ">= ") else required
        try:
            return ast.literal_eval(text)
        except (ValueError, SyntaxError):
            return eval(text, vars(pytm))  # noqa: S307 - enum names only

    for finding in tm.findings:
        for option in Relations().remedies(finding):
            values = [value(c.required) for c in option]
            if None in values or any(c.attribute.endswith(")") for c in option):
                continue
            target, saved = finding.element, []
            try:
                for change, new in zip(option, values):
                    owners = [target]
                    if change.subject != "target":
                        name = change.subject.split('"')[1]
                        owners = [d for d in target.data if d.name == name]
                    *path, attr = change.attribute.split(".")
                    for owner in owners:
                        for part in path:
                            owner = getattr(owner, part)
                        saved.append((owner, attr, getattr(owner, attr)))
                        object.__setattr__(owner, attr, new)
                assert not threats[finding.threat_id].apply(target), (
                    finding.threat_id,
                    option,
                )
                checked += 1
            finally:
                for owner, attr, old in reversed(saved):
                    object.__setattr__(owner, attr, old)

    assert checked > 50


class TestFormatCondition:
    def test_boolean_operators_start_lines_and_groups_are_indented(self):
        condition = (
            "target.controls.isEncrypted is False or (target.source.inScope and "
            "not target.isResponse and (not target.controls.authenticatesDestination"
            " or not target.controls.checksDestinationRevocation))"
        )

        assert format_condition(condition) == (
            "target.controls.isEncrypted is False\n"
            "or (\n"
            "    target.source.inScope\n"
            "    and not target.isResponse\n"
            "    and (\n"
            "        not target.controls.authenticatesDestination\n"
            "        or not target.controls.checksDestinationRevocation\n"
            "    )\n"
            ")"
        )

    def test_not_of_a_group_and_short_generators(self):
        assert format_condition("not (target.a or target.b)") == (
            "not (\n    target.a\n    or target.b\n)"
        )
        assert format_condition("any(d.isPII for d in target.data)") == (
            "any(d.isPII for d in target.data)"
        )

    def test_long_calls_and_sequences_break_inside_brackets(self):
        condition = (
            "any(d.credentialsLife in (Lifetime.UNKNOWN, Lifetime.LONG, "
            "Lifetime.MANUAL, Lifetime.HARDCODED) for d in target.data)"
        )

        assert format_condition(condition) == (
            "any(\n"
            "    d.credentialsLife in (\n"
            "        Lifetime.UNKNOWN,\n"
            "        Lifetime.LONG,\n"
            "        Lifetime.MANUAL,\n"
            "        Lifetime.HARDCODED,\n"
            "    )\n"
            "    for d in target.data\n"
            ")"
        )

    def test_invalid_text_is_returned_unchanged(self):
        assert format_condition("not a (valid expression") == (
            "not a (valid expression"
        )

    def test_library_conditions_keep_their_meaning_and_fit(self):
        import ast
        import json
        from pathlib import Path

        import pytm

        library = Path(pytm.__file__).parent / "threatlib" / "threats.json"
        conditions = [
            t["condition"]
            for t in json.loads(library.read_text(encoding="utf-8"))
            if t.get("condition")
        ]
        assert len(conditions) > 100
        for condition in conditions:
            formatted = format_condition(condition)
            # Wrapped in parentheses the layout is valid Python again.
            again = ast.parse("(\n" + formatted + "\n)", mode="eval")
            assert ast.dump(again) == ast.dump(ast.parse(condition, mode="eval"))
            assert max(map(len, formatted.splitlines())) <= 60, condition
