import ast
import itertools
import random

import pytest

import pytm
from pytm import (
    TM,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    Lambda,
    Process,
    Server,
    Threat,
    TLSVersion,
)
from pytm.condition_methods import (
    condition_method,
    condition_method_names,
    method_expression,
)
from pytm.relations import Relations, remedies


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _threat(condition, target="Dataflow"):
    return Threat(SID="X1", target=target, description="x", condition=condition)


class TestMarkedMethods:
    def test_methods_conditions_may_call(self):
        assert {
            "checkTLSVersion",
            "hasDataLeaks",
            "oneOf",
            "crosses",
            "enters",
            "exits",
            "inside",
        } <= condition_method_names()

    def test_expression_and_opaque_methods(self):
        flow = Dataflow(Actor("User"), Server("Web"), "Login")

        assert method_expression(flow, "hasDataLeaks")[1] == ()
        assert method_expression(Server, "checkTLSVersion")[1] == ("flows",)
        assert method_expression(flow, "oneOf") is None  # opaque
        assert method_expression(flow, "display_name") is None  # not marked

    @pytest.mark.parametrize("seed", range(30))
    def test_generated_methods_match_their_meaning(self, seed):
        rng = random.Random(seed)
        levels = list(Classification)
        source = Actor("User", maxClassification=rng.choice(levels))
        sink = Server(
            "Web",
            maxClassification=rng.choice(levels),
            minTLSVersion=rng.choice(list(TLSVersion)),
        )
        data = [Data(f"d{i}", classification=rng.choice(levels)) for i in range(3)]
        flow = Dataflow(
            source,
            sink,
            "Login",
            data=data,
            maxClassification=rng.choice(levels),
            tlsVersion=rng.choice(list(TLSVersion)),
        )

        assert flow.hasDataLeaks() == any(
            d.classification > source.maxClassification
            or d.classification > sink.maxClassification
            or d.classification > flow.maxClassification
            for d in data
        )
        assert sink.checkTLSVersion([flow]) == (flow.tlsVersion < sink.minTLSVersion)

    def test_expressions_are_validated_like_conditions(self):
        class Bad(Server):
            @condition_method("__import__('os').system('true')")
            def bad(self) -> bool:
                """Not allowed."""

        with pytest.raises(ValueError):
            Bad("x").bad()


class TestValidator:
    def test_unmarked_methods_cannot_be_called(self):
        with pytest.raises(ValueError, match="not permitted"):
            _threat("target.display_name() == 'x'")

    def test_marked_methods_can_be_called(self):
        assert _threat("target.hasDataLeaks()").condition

    def test_user_subclasses_can_add_condition_methods(self):
        class Gateway(Server):
            @condition_method("self.port == 443")
            def usesHTTPSPort(self) -> bool:
                """Does the gateway listen on 443?"""

        threat = _threat("target.usesHTTPSPort()", target="Server")

        assert threat.apply(Gateway("Edge", port=443))
        assert not threat.apply(Gateway("Other", port=80))


class TestRemedies:
    def test_arguments_are_substituted(self):
        tm = TM("tls tm", description="d")
        web = Server("Web", minTLSVersion=TLSVersion.TLSv12)
        Dataflow(Actor("User"), web, "Login", tlsVersion=TLSVersion.TLSv10)
        tm.check()

        options = remedies(
            _threat("target.checkTLSVersion(target.inputs)", "Server"), web
        )

        found = [[(c.subject, c.attribute, c.required) for c in o] for o in options]
        # Raise the flow's TLS version, or lower the server's minimum.
        assert [('dataflow "Login"', "tlsVersion", ">= TLSVersion.TLSv12")] in found
        assert [("target", "minTLSVersion", "<= TLSVersion.TLSv10")] in found

    def test_loop_variables_are_not_captured(self):
        # The method's own "d" must not be confused with the condition's "d".
        class Store(Datastore):
            @condition_method("any(d.isPII for d in self.data)")
            def holdsPII(self) -> bool:
                """Does the store hold personal data?"""

        tm = TM("capture tm", description="d")
        store = Store("DB", data=[Data("Token", isPII=True)])
        flow = Dataflow(Actor("User"), store, "Save", data=Data("Other"))
        tm.check()
        threat = _threat(
            "any(d.isStored is False and target.sink.holdsPII() for d in target.data)"
        )

        options = remedies(threat, flow)

        attributes = {(c.subject, c.attribute) for o in options for c in o}
        assert ('data "Token"', "isPII") in attributes
        assert ('data "Other"', "isStored") in attributes

    def test_opaque_methods_are_reported_as_computed(self):
        tm = TM("opaque tm", description="d")
        zone = Boundary("Zone")
        flow = Dataflow(Actor("User"), Server("Web", inBoundary=zone), "Login")
        tm.check()

        [[change]] = remedies(_threat("target.crosses(Boundary)"), flow)

        assert change.attribute == "crosses(Boundary)"
        assert change.is_computed and not change.is_mitigation


# ---------------------------------------------------------------------------
# Every remedy, on generated models, makes its threat stop applying.
# ---------------------------------------------------------------------------

_BOOLEAN_FIELDS = {
    cls: [
        name
        for name, info in cls.model_fields.items()
        if info.annotation is bool and name not in ("is_drawn",)
    ]
    for cls in (Actor, Server, Process, Datastore, Lambda, Dataflow, Data)
}
_CONTROLS = [
    n for n, i in pytm.base.Controls.model_fields.items() if i.annotation is bool
]


def _randomize(obj, rng):
    for name in _BOOLEAN_FIELDS.get(type(obj), []):
        object.__setattr__(obj, name, rng.random() < 0.5)
    controls = getattr(obj, "controls", None)
    if controls is not None:
        for name in _CONTROLS:
            object.__setattr__(controls, name, rng.random() < 0.3)


def _model(seed):
    rng = random.Random(seed)
    TM.reset()
    tm = TM(f"generated {seed}", description="d")
    inside = Boundary("Inside")
    levels = list(Classification)
    elements = [
        Actor("User", maxClassification=rng.choice(levels)),
        Server(
            "Web", inBoundary=inside, OS="Linux", maxClassification=rng.choice(levels)
        ),
        Process(
            "Worker", inBoundary=inside, environment=rng.choice(["Production", ""])
        ),
        Datastore("DB", inBoundary=inside, maxClassification=rng.choice(levels)),
        Lambda("Fn", environment=rng.choice(["Production", ""])),
    ]
    data = [
        Data(
            name,
            classification=rng.choice(levels),
            format=rng.choice(["JSON", "XML", ""]),
            credentialsLife=rng.choice(list(pytm.Lifetime)),
        )
        for name in ("Token", "Comment", "Key")
    ]
    for d in data:
        _randomize(d, rng)
    for source, sink in itertools.permutations(elements, 2):
        if rng.random() < 0.4:
            Dataflow(
                source,
                sink,
                f"{source.name} to {sink.name}",
                data=rng.sample(data, rng.randint(0, 2)),
                protocol=rng.choice(["HTTP", "HTTPS", ""]),
                tlsVersion=rng.choice(list(TLSVersion)),
            )
    for element in TM._elements:
        _randomize(element, rng)
    tm.check()
    tm.resolve()
    return tm


def _value(required):
    if required.startswith(("not ", "< ", "> ", "a ", "one of")):
        return None
    text = required[3:] if required[:3] in ("<= ", ">= ") else required
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return eval(text, vars(pytm))  # noqa: S307 - enum names only


def test_remedies_resolve_their_findings_on_generated_models():
    threats_seen, checked = set(), 0
    for seed in range(12):
        tm = _model(seed)
        library = {t.id: t for t in TM._threats}
        for finding in tm.findings:
            threats_seen.add(finding.threat_id)
            for option in Relations().remedies(finding):
                values = [_value(c.required) for c in option]
                if None in values or any(c.is_computed for c in option):
                    continue
                target, saved = finding.element, []
                try:
                    for change, new in zip(option, values):
                        owners = [target]
                        if change.subject != "target":
                            name = change.subject.split('"')[1]
                            items = list(getattr(target, "data", [])) + list(
                                getattr(target, "inputs", []) or []
                            )
                            owners = [i for i in items if i.name == name]
                        *path, attr = change.attribute.split(".")
                        for owner in owners:
                            for part in path:
                                owner = getattr(owner, part)
                            saved.append((owner, attr, getattr(owner, attr)))
                            object.__setattr__(owner, attr, new)
                    assert not library[finding.threat_id].apply(target), (
                        seed,
                        finding.threat_id,
                        finding.target,
                        option,
                    )
                    checked += 1
                finally:
                    for owner, attr, old in reversed(saved):
                        object.__setattr__(owner, attr, old)

    conditional = {t.id for t in TM._threats if t.condition and t.condition != "True"}
    # The generated models exercise most of the threat library.
    assert len(threats_seen & conditional) >= 0.6 * len(conditional)
    assert checked > 500
