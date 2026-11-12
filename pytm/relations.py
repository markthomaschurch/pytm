"""Cross-references between model objects, for report templates.

Answers the questions a report needs to link its sections together: which
dataflows touch an element, which data it produces or consumes, which
elements handle a piece of data, which threats fired against an element (and
in the model as a whole), which values to change to resolve a finding, and
which assumptions were made and what they suppressed.

During :meth:`pytm.TM.report` the helpers return the same (copied and
HTML-escaped) objects the template iterates over, so names, links and threat
text are rendered consistently. Outside a report they return the model's own
objects. Relationships are always computed from the model itself and matched
by ``uuid``, so a helper accepts either an original object or its copy.
"""

from __future__ import annotations

import ast
import copy
import enum
from dataclasses import dataclass, field, replace
from typing import Any

from .condition_methods import method_expression
from .roles import Role, field_role

_MAX_VALUE_LENGTH = 80


def _uuid(obj: Any) -> str | None:
    value = getattr(obj, "uuid", None)
    return None if value is None else str(value)


def _describe(value: Any) -> str:
    """Short, human-readable rendering of an attribute value."""
    if isinstance(value, enum.Enum):
        text = f"{type(value).__name__}.{value.name}"
    elif hasattr(value, "uuid") and hasattr(value, "name"):
        text = str(value.name)
    elif isinstance(value, (list, tuple, set, frozenset)):
        text = "[" + ", ".join(_describe(item) for item in value) + "]"
    else:
        text = repr(value)
    if len(text) > _MAX_VALUE_LENGTH:
        text = text[: _MAX_VALUE_LENGTH - 3] + "..."
    return text


@dataclass(frozen=True)
class Change:
    """One value that has to change for a threat to stop applying.

    Attributes:
        attribute: What to change, relative to *subject*, e.g.
            ``controls.sanitizesInput`` or ``protocol``.
        required: The value it needs, e.g. ``True``, ``not 'HTTP'``,
            ``>= TLSVersion.TLSv12``, or ``False`` for a method's result.
        current: Its current value.
        subject: Whose attribute it is: ``"target"`` (the element the finding
            is about), or a name such as ``data "Token"`` for items of a
            collection checked with ``any(...)``.
        subject_anchor: Link anchor of that item (``data-token``), if any.
        role: The attribute's :class:`pytm.roles.Role` (None if unknown, e.g.
            the result of a method).
    """

    attribute: str
    required: str
    current: str
    subject: str = "target"
    subject_anchor: str = ""
    role: Role | None = None
    # ("<=", value) etc. for ordered requirements, so several bounds on one
    # attribute can be reconciled; not part of equality.
    bound: tuple | None = field(default=None, compare=False, repr=False)
    # The object the attribute belongs to (the target, or an item of one of
    # its collections), used to check the change; not part of equality.
    owner: Any = field(default=None, compare=False, repr=False)

    @property
    def is_computed(self) -> bool:
        """True for the result of a method that has no expression form
        (``@opaque_condition_method``): what to change is whatever it uses."""
        return self.attribute.endswith(")")

    @property
    def is_mitigation(self) -> bool:
        """True if the attribute is a safeguard (``Role.SAFEGUARD``).

        False for a change to how the model *describes* the system, such as
        ``isResponse``, ``inScope`` or a data item's ``classification``: it
        makes the threat stop applying without making anything safer, so it
        is only right if the model is currently inaccurate.
        """
        return self.role is Role.SAFEGUARD

    @property
    def instruction(self) -> str:
        """Markdown, e.g. ``set `controls.sanitizesInput` to `True```."""
        required = self.required
        what = f"`{self.attribute}`"
        if self.attribute.endswith(")"):
            return f"make {what} return `{required}`"
        for prefix, phrase in (
            ("<= ", "to `{}` or lower"),
            (">= ", "to `{}` or higher"),
            ("< ", "below `{}`"),
            ("> ", "above `{}`"),
            ("not one of ", "to a value other than `{}`"),
            ("one of ", "to one of `{}`"),
            ("not ", "to something other than `{}`"),
        ):
            if required.startswith(prefix):
                return f"set {what} " + phrase.format(required[len(prefix) :])
        if required.startswith("a "):
            return f"set {what} to {required}"
        return f"set {what} to `{required}`"


# How to turn a comparison around: required relation for the value on the
# left when the comparison must become false.
_NEGATED = {
    ast.Eq: "not",
    ast.NotEq: "",
    ast.Lt: ">=",
    ast.LtE: ">",
    ast.Gt: "<=",
    ast.GtE: "<",
    ast.In: "not one of",
    ast.NotIn: "one of",
}
_SAME = {
    ast.Eq: "",
    ast.NotEq: "not",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
    ast.In: "one of",
    ast.NotIn: "not one of",
}
_MIRRORED = {
    ast.Lt: ast.Gt,
    ast.LtE: ast.GtE,
    ast.Gt: ast.Lt,
    ast.GtE: ast.LtE,
}
_MAX_REMEDIES = 8


class _Remedies:
    """Find minimal sets of value changes that make a condition false."""

    def __init__(self, threat: Any, target: Any):
        self.condition = threat.condition
        self.globals = dict(threat._build_eval_globals())
        self.threat_id = threat.id
        self.target = target

    def evaluate(self, node: ast.AST, names: dict[str, Any]) -> Any:
        code = compile(ast.Expression(node), f"<Threat {self.threat_id}>", "eval")
        return eval(code, self.globals, {"target": self.target, **names})  # noqa: S307

    @staticmethod
    def text(node: ast.AST) -> str:
        return ast.unparse(node)

    @staticmethod
    def _settable(node: ast.AST, names: dict[str, Any]) -> str | None:
        """Root name of an attribute chain (``target.a.b``), else None."""
        while isinstance(node, ast.Attribute):
            node = node.value
        if isinstance(node, ast.Name) and (node.id == "target" or node.id in names):
            return node.id
        return None

    def _change(self, node, required, names, current) -> Change:
        root = self._settable(node, names) or "target"
        text = self.text(node)
        attribute = text[len(root) + 1 :] if text.startswith(root + ".") else text
        subject = names.get("_labels", {}).get(root, "target")
        subject_anchor = names.get("_anchors", {}).get(root, "")
        return Change(
            attribute,
            required,
            _describe(current),
            subject,
            subject_anchor,
            self._role(node, names),
            owner=names.get(root, self.target) if root != "target" else self.target,
        )

    def _role(self, node: ast.AST, names: dict) -> Role | None:
        """Role of the attribute *node* sets, from the class that declares it."""
        if not isinstance(node, ast.Attribute):
            return None
        try:
            owner = self.evaluate(node.value, names)
        except Exception:
            return None
        return field_role(owner, node.attr)

    def options(self, node: ast.AST, want: bool, names: dict) -> list[frozenset]:
        """Alternative sets of changes that make *node* evaluate to *want*."""
        try:
            if bool(self.evaluate(node, names)) == want:
                return [frozenset()]
        except Exception:
            pass

        if isinstance(node, ast.BoolOp):
            parts = node.values
            any_part = isinstance(node.op, ast.Or) == want
            if any_part:  # one part changed is enough
                return _minimal(
                    [o for part in parts for o in self.options(part, want, names)]
                )
            return _product(
                [
                    self.options(part, want, names)
                    for part in parts
                    if self._truth(part, names) != want
                ]
            )

        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.options(node.operand, not want, names)

        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            found = self._compare(node, want, names)
            if found is not None:
                return found

        expanded = self._expand_method(node, names)
        if expanded is not None:
            return self.options(expanded, want, names)

        if self._is_any_over_items(node):
            found = self._any(node, want, names)
            if found is not None:
                return found

        if self._settable(node, names):
            current = self._value(node, names)
            required = (
                repr(want)
                if isinstance(current, bool)
                else ("a true value" if want else "a false or empty value")
            )
            return [frozenset({self._change(node, required, names, current)})]

        if not self._references_model(node, names):
            return []  # e.g. a constant: no change to the model affects it

        # Anything else (e.g. an unknown target method): it must give `want`.
        return [
            frozenset({self._change(node, repr(want), names, self._value(node, names))})
        ]

    @staticmethod
    def _references_model(node: ast.AST, names: dict) -> bool:
        return any(
            isinstance(n, ast.Name) and (n.id == "target" or n.id in names)
            for n in ast.walk(node)
        )

    def _expand_method(self, node: ast.AST, names: dict) -> ast.AST | None:
        """``target.hasDataLeaks()`` -> the expression the method computes.

        Uses the expression the method is defined by (see
        :mod:`pytm.condition_methods`), with ``self`` replaced by the object
        the method is called on and each parameter by its argument.
        """
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and self._settable(node.func.value, names)
            and not node.keywords
        ):
            return None
        try:
            receiver = self.evaluate(node.func.value, names)
        except Exception:
            return None
        found = method_expression(receiver, node.func.attr)
        if found is None:
            return None
        expression, parameters = found
        if len(node.args) != len(parameters):
            return None
        tree = ast.parse(expression, mode="eval").body
        replacements = {"self": node.func.value, **dict(zip(parameters, node.args))}
        return _Substitute(replacements).visit(tree)

    def _truth(self, node, names) -> bool | None:
        try:
            return bool(self.evaluate(node, names))
        except Exception:
            return None

    def _value(self, node, names) -> Any:
        try:
            return self.evaluate(node, names)
        except Exception as exc:
            return f"<{type(exc).__name__}>"

    def _compare(self, node, want, names):
        op = type(node.ops[0])
        left, right = node.left, node.comparators[0]
        if not self._settable(left, names) and self._settable(right, names):
            if op not in _MIRRORED and op not in (ast.Eq, ast.NotEq):
                return None
            left, right = right, left
            op = _MIRRORED.get(op, op)
        if not self._settable(left, names):
            return None
        if self._settable(right, names) and op in _MIRRORED:
            # Two model values compared: changing either one resolves it.
            return _minimal(
                self._compare_to_value(left, op, right, want, names)
                + self._compare_to_value(right, _MIRRORED[op], left, want, names)
            )
        if self._settable(right, names):
            return None
        return self._compare_to_value(left, op, right, want, names) or None

    def _compare_to_value(self, left, op, right, want, names):
        """Change *left* so that ``left <op> right`` evaluates to *want*."""
        current = self._value(left, names)
        other = self._value(right, names)
        if op in (ast.Is, ast.IsNot):
            equal = op is ast.Is
            if isinstance(other, bool):
                required = repr(other if equal == want else not other)
            elif other is None:
                required = "None" if equal == want else "a value"
            else:
                return []
        elif op in _NEGATED:
            if op in (ast.Eq, ast.NotEq) and isinstance(other, bool):
                equal = op is ast.Eq
                required = repr(other if equal == want else not other)
            else:
                relation = (_SAME if want else _NEGATED)[op]
                required = f"{relation} {_describe(other)}".strip()
                if relation in ("<", "<=", ">", ">="):
                    change = self._change(left, required, names, current)
                    return [frozenset({replace(change, bound=(relation, other))})]
        else:
            return []
        return [frozenset({self._change(left, required, names, current)})]

    @staticmethod
    def _is_any_over_items(node) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("any", "all")
            and len(node.args) == 1
            and isinstance(node.args[0], ast.GeneratorExp)
            and len(node.args[0].generators) == 1
            and isinstance(node.args[0].generators[0].target, ast.Name)
            and not node.args[0].generators[0].ifs
        )

    def _any(self, node, want, names):
        """``any(pred for x in items)``: fix the items that decide the result."""
        generator = node.args[0]
        loop = generator.generators[0]
        variable = loop.target.id
        try:
            items = list(self.evaluate(loop.iter, names))
        except Exception:
            return None
        is_any = node.func.id == "any"
        # any() is false only if every item is false; all() is true only if
        # every item is true. Otherwise one item is enough.
        every_item = is_any != want
        per_item = []
        for item in items:
            label = _item_label(loop.iter, item, self)
            scope = {
                **names,
                variable: item,
                "_labels": {**names.get("_labels", {}), variable: label},
                "_anchors": {**names.get("_anchors", {}), variable: _item_anchor(item)},
            }
            per_item.append(self.options(generator.elt, want, scope))
        if every_item:
            return _product(per_item)
        return _minimal([o for options in per_item for o in options]) or None


class _Substitute(ast.NodeTransformer):
    """Replace names with expressions, and give comprehension variables
    fresh names so they can't capture names from the calling condition."""

    _counter = 0

    def __init__(self, replacements: dict[str, ast.AST]):
        self.replacements = dict(replacements)

    def visit_comprehension(self, node: ast.comprehension) -> ast.AST:
        node.iter = self.visit(node.iter)
        if isinstance(node.target, ast.Name):
            _Substitute._counter += 1
            fresh = f"{node.target.id}_{_Substitute._counter}"
            self.replacements[node.target.id] = ast.Name(fresh, ast.Load())
            node.target = ast.Name(fresh, ast.Store())
        node.ifs = [self.visit(condition) for condition in node.ifs]
        return node

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> ast.AST:
        # Bind the loop variables before visiting the element expression.
        node.generators = [self.visit(g) for g in node.generators]
        node.elt = self.visit(node.elt)
        return node

    visit_ListComp = visit_GeneratorExp

    def visit_Name(self, node: ast.Name) -> ast.AST:
        replacement = self.replacements.get(node.id)
        if replacement is None:
            return node
        return ast.fix_missing_locations(copy.deepcopy(replacement))


def _item_label(iterable: ast.AST, item: Any, remedies: _Remedies) -> str:
    """``data "Token"`` for an item of ``target.data``, else its name."""
    collection = remedies.text(iterable).rsplit(".", 1)[-1]
    kind = {"data": "data", "inputs": "dataflow", "outputs": "dataflow"}.get(
        collection, collection
    )
    from .anchors import label

    name = label(item) if hasattr(item, "name") else item
    return f'{kind} "{name}"'


def _item_anchor(item: Any) -> str:
    from .anchors import anchor

    try:
        return anchor(item)
    except TypeError:
        return ""


def _minimal(
    options: list[frozenset], limit: int | None = _MAX_REMEDIES
) -> list[frozenset]:
    """Drop duplicates and options that contain another option."""
    unique = sorted(set(options), key=lambda o: (len(o), sorted(map(repr, o))))
    kept: list[frozenset] = []
    for option in unique:
        if not any(other <= option for other in kept):
            kept.append(option)
    return kept[:limit]


def _product(groups: list[list[frozenset]]) -> list[frozenset]:
    """Every combination of one option from each group."""
    combined = [frozenset()]
    for group in groups:
        if not group:
            return []
        merged = (_reconcile(a | b) for a in combined for b in group)
        combined = _minimal([option for option in merged if option is not None])
    return combined


def _reconcile(option: frozenset) -> frozenset | None:
    """Merge requirements on the same attribute; None if they contradict.

    Combining "``classification`` <= RESTRICTED" with "<= UNKNOWN" keeps the
    stricter one; "<= PUBLIC" with ">= SECRET", or "True" with "False",
    can't both hold, so the option is dropped.
    """
    groups: dict[tuple[str, str], list[Change]] = {}
    for change in option:
        groups.setdefault((change.subject, change.attribute), []).append(change)
    kept: list[Change] = []
    for changes in groups.values():
        if len(changes) == 1:
            kept.extend(changes)
            continue
        bounded = [c for c in changes if c.bound is not None]
        other = [c for c in changes if c.bound is None]
        if len({c.required for c in other}) > 1:
            return None  # e.g. "True" and "False"
        kept.extend(other[:1])
        try:
            upper = min(
                (c for c in bounded if c.bound[0] in ("<", "<=")),
                key=lambda c: (c.bound[1], c.bound[0] == "<="),
                default=None,
            )
            lower = max(
                (c for c in bounded if c.bound[0] in (">", ">=")),
                key=lambda c: (c.bound[1], c.bound[0] == ">"),
                default=None,
            )
        except TypeError:  # values that can't be ordered: keep them all
            kept.extend(bounded)
            continue
        if upper is not None and lower is not None:
            low, high = lower.bound[1], upper.bound[1]
            strict = lower.bound[0] == ">" or upper.bound[0] == "<"
            if low > high or (low == high and strict):
                return None
        kept.extend(c for c in (upper, lower) if c is not None)
    return frozenset(kept)


def remedies(threat: Any, target: Any) -> list[list[Change]]:
    """Alternative sets of changes that would make *threat* not apply.

    Each item is one way to resolve the finding: change every value in it.
    Alternatives made only of safeguards (``Change.is_mitigation``) come
    first, then those that also change how the system is described; within
    each group, fewer changes come first. An empty list means no
    change to the model's values would help (for example a threat with no
    condition, which applies to every element of its type).
    """
    if not getattr(threat, "condition", ""):
        return []
    finder = _Remedies(threat, target)
    tree = ast.parse(threat.condition, mode="eval")
    options = [o for o in finder.options(tree.body, False, {}) if o]
    # Each clause is analysed on its own, so a change that falsifies one
    # clause can make another one true; drop options shown not to work.
    options = [o for o in options if _resolves(threat, target, o) is not False]
    ordered = sorted(
        _minimal(options, limit=None),
        key=lambda o: (not all(c.is_mitigation for c in o), len(o)),
    )[:_MAX_REMEDIES]
    return [sorted(o, key=lambda c: (c.subject, c.attribute)) for o in ordered]


_NO_VALUE = object()


def _concrete(change: Change) -> Any:
    """A value that satisfies *change*, or _NO_VALUE if there's no single one."""
    if change.bound is not None:
        relation, value = change.bound
        return value if relation in ("<=", ">=") else _NO_VALUE
    try:
        return ast.literal_eval(change.required)
    except (ValueError, SyntaxError):
        return _NO_VALUE


def _resolves(threat: Any, target: Any, option: frozenset) -> bool | None:
    """Does making every change in *option* stop *threat* applying to *target*?

    The changes are applied to the model, the threat's condition is
    evaluated, and the old values are put back. None when a change has no
    single value to try (e.g. "something other than 'HTTP'") or can't be
    applied.
    """
    saved = []
    try:
        for change in option:
            value = _concrete(change)
            if value is _NO_VALUE or change.owner is None or change.is_computed:
                return None
            *path, attr = change.attribute.split(".")
            owner = change.owner
            for part in path:
                owner = getattr(owner, part)
            saved.append((owner, attr, getattr(owner, attr)))
            object.__setattr__(owner, attr, value)
        return not threat.apply(target)
    except Exception:
        return None
    finally:
        for owner, attr, value in reversed(saved):
            object.__setattr__(owner, attr, value)


_INDENT = "    "
_FORMAT_WIDTH = 60


def format_condition(condition: str, width: int = _FORMAT_WIDTH) -> str:
    """Lay out a threat condition over several short lines.

    Each boolean operator starts a new line, and the contents of
    parenthesized groups (and long calls such as ``any(...)``) are indented,
    so conditions fit narrow pages instead of running off them::

        target.controls.isEncrypted is False
        or (
            target.source.inScope
            and not target.isResponse
        )

    The result means exactly the same as *condition*; text that is not a
    valid expression is returned unchanged.
    """
    try:
        tree = ast.parse(condition.strip(), mode="eval")
    except SyntaxError:
        return condition
    return "\n".join(_condition_lines(tree.body, width))


def _indented(lines: list[str]) -> list[str]:
    return [_INDENT + line for line in lines]


def _operand_lines(node: ast.AST, width: int) -> list[str]:
    if isinstance(node, ast.BoolOp):
        return ["(", *_indented(_condition_lines(node, width)), ")"]
    return _condition_lines(node, width)


def _condition_lines(node: ast.AST, width: int) -> list[str]:
    if isinstance(node, ast.BoolOp):
        operator = "and" if isinstance(node.op, ast.And) else "or"
        lines: list[str] = []
        for index, value in enumerate(node.values):
            part = _operand_lines(value, width)
            lines.append(part[0] if index == 0 else f"{operator} {part[0]}")
            lines.extend(part[1:])
        return lines

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        if isinstance(node.operand, ast.BoolOp):
            inner = _condition_lines(node.operand, width)
            return ["not (", *_indented(inner), ")"]
        inner = _condition_lines(node.operand, width)
        return [f"not {inner[0]}", *inner[1:]]

    has_boolean = any(isinstance(n, ast.BoolOp) for n in ast.walk(node))

    if (
        isinstance(node, ast.Call)
        and not node.keywords
        and len(node.args) == 1
        and isinstance(node.args[0], ast.GeneratorExp)
    ):
        # any(x for x in y): written without the doubled parentheses
        # ast.unparse() produces, and broken up when long or boolean.
        function = ast.unparse(node.func)
        body = _generator_lines(node.args[0], width)
        if not has_boolean and len(function) + 2 + len(" ".join(body)) <= width:
            return [f"{function}({' '.join(body)})"]
        return [f"{function}(", *_indented(body), ")"]

    text = ast.unparse(node)
    if len(text) <= width and not has_boolean:
        return [text]

    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.comparators[0], (ast.Tuple, ast.List, ast.Set))
    ):
        # x in (A, B, C, ...): one item per line.
        sequence = node.comparators[0]
        opening, closing = {ast.Tuple: "()", ast.List: "[]", ast.Set: "{}"}[
            type(sequence)
        ]
        operator = ast.unparse(
            ast.Compare(left=ast.Name("x"), ops=node.ops, comparators=[ast.Name("y")])
        )[2:-2]
        items = [f"{ast.unparse(e)}," for e in sequence.elts]
        return [
            f"{ast.unparse(node.left)} {operator} {opening}",
            *_indented(items),
            closing,
        ]

    if isinstance(node, ast.Call) and not node.keywords:
        body = []
        for index, arg in enumerate(node.args):
            part = _condition_lines(arg, width)
            if index < len(node.args) - 1:
                part[-1] += ","
            body.extend(part)
        return [f"{ast.unparse(node.func)}(", *_indented(body), ")"]

    if isinstance(node, ast.GeneratorExp):
        return ["(", *_indented(_generator_lines(node, width)), ")"]

    return [text]


def _generator_lines(node: ast.GeneratorExp, width: int) -> list[str]:
    lines = _condition_lines(node.elt, width)
    for generator in node.generators:
        clause = f"for {ast.unparse(generator.target)} in {ast.unparse(generator.iter)}"
        lines.append(("async " if generator.is_async else "") + clause)
        lines.extend(f"if {ast.unparse(condition)}" for condition in generator.ifs)
    return lines


# Weight of each threat severity, for ordering findings and assumptions.
SEVERITY_RANK = {
    "very high": 5,
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "very low": 1,
    "info": 0,
}
SEVERITY_ORDER = ("Very High", "High", "Medium", "Low", "Very Low", "Info")


def severity_rank(severity: Any) -> int:
    """Weight of a severity name: 5 for "Very High" down to 0 for "Info"."""
    return SEVERITY_RANK.get(str(severity or "").strip().lower(), 0)


@dataclass(frozen=True)
class AssumptionEntry:
    """An assumption, what it was made about, and what it suppressed."""

    assumption: Any
    owner: Any  # the element it was made about, or None for the whole model
    anchor: str
    suppressed: tuple[Any, ...]  # the findings it suppressed
    # Threat ids in its ``exclude`` that suppressed no finding, and those
    # that are not in the threat library at all (usually a typo).
    unused: tuple[str, ...]
    unknown: tuple[str, ...]
    # Findings it would suppress once verified (only when the model
    # requires verified assumptions).
    pending: tuple[Any, ...] = ()

    @property
    def name(self) -> str:
        return self.assumption.name

    @property
    def description(self) -> str:
        return self.assumption.description

    @property
    def exclude(self) -> list[str]:
        return sorted(self.assumption.exclude)

    @property
    def verified(self) -> bool:
        return self.assumption.verified

    @property
    def verifier(self) -> str:
        return self.assumption.verifier

    @property
    def verifiedOn(self) -> Any:
        return self.assumption.verifiedOn

    @property
    def risk(self) -> int:
        """Combined severity of the findings it would suppress once verified."""
        return sum(severity_rank(f.severity) for f in self.pending)

    def risk_key(self) -> tuple:
        """Sort key: highest combined, then highest single severity, first."""
        ranks = [severity_rank(f.severity) for f in self.pending]
        return (-sum(ranks), -max(ranks, default=0), -len(ranks), self.name)

    def risk_counts(self) -> list[tuple[str, int]]:
        """(severity, number of pending findings), highest severity first."""
        ranks = [severity_rank(f.severity) for f in self.pending]
        return [
            (name, ranks.count(severity_rank(name)))
            for name in SEVERITY_ORDER
            if severity_rank(name) in ranks
        ]

    def display_label(self) -> str:
        return self.assumption.name or "(unnamed assumption)"


class Relations:
    """Index of the model's relationships, optionally for one report."""

    def __init__(self, context: dict[str, Any] | None = None):
        from .tm import TM

        context = context or {}
        self._originals = {_uuid(e): e for e in TM._elements}
        self._flows = list(TM._flows)
        self._elements = list(TM._elements)
        self._data = list(TM._data)
        self._display: dict[str | None, Any] = {}
        for key in ("elements", "assets", "actors", "boundaries", "dataflows"):
            for obj in context.get(key) or []:
                self._display.setdefault(_uuid(obj), obj)
        self._threat_library = list(TM._threats)
        self._threats = list(context.get("threats") or TM._threats)
        if "findings" in context:
            self._findings = list(context["findings"])
        else:
            self._findings = [f for e in self._elements for f in e.findings]
        tm = context.get("tm")
        self._model_assumptions = list(getattr(tm, "assumptions", None) or [])
        self._require_verified = bool(getattr(tm, "requireVerifiedAssumptions", False))
        self._suppressed = list(
            context.get("excluded_findings")
            or getattr(tm, "excluded_findings", None)
            or []
        )
        self._assumption_entries: list[AssumptionEntry] | None = None

    # -- helpers ----------------------------------------------------------

    def _original(self, obj: Any) -> Any:
        return self._originals.get(_uuid(obj), obj)

    def _show(self, obj: Any) -> Any:
        return self._display.get(_uuid(obj), obj)

    def _data_in(self, collection: Any) -> list[Any]:
        """Model data contained in *collection*, in model order."""
        if not collection or isinstance(collection, str):
            return []
        items = list(collection)
        return [d for d in self._data if any(d == item for item in items)]

    # -- elements and dataflows -------------------------------------------

    def flows(self, element: Any, direction: str | None = None) -> list[Any]:
        """Dataflows attached to *element*: all, ``"in"`` (sink) or ``"out"``."""
        if direction not in (None, "in", "out"):
            raise ValueError(f"direction must be None, 'in' or 'out': {direction!r}")
        uid = _uuid(element)
        result = []
        for flow in self._flows:
            is_source = _uuid(flow.source) == uid
            is_sink = _uuid(flow.sink) == uid
            if (direction in (None, "out") and is_source) or (
                direction in (None, "in") and is_sink
            ):
                result.append(self._show(flow))
        return result

    def data(self, element: Any) -> list[Any]:
        """Data produced or consumed by *element* (or carried by a dataflow)."""
        from .dataflow import Dataflow

        original = self._original(element)
        if isinstance(original, Dataflow):
            return self._data_in(original.data)
        own = getattr(original, "data", None)
        collected = [] if not own or isinstance(own, str) else list(own)
        uid = _uuid(original)
        for flow in self._flows:
            if uid in (_uuid(flow.source), _uuid(flow.sink)):
                collected.extend(flow.data)
        return self._data_in(collected)

    # -- data -------------------------------------------------------------

    def carriers(self, datum: Any) -> list[Any]:
        """Dataflows that carry *datum*."""
        return [self._show(f) for f in self._flows if datum in f.data]

    def handlers(self, datum: Any) -> list[Any]:
        """Elements that send, receive, store or process *datum*."""
        from .dataflow import Dataflow

        uids = set()
        for flow in self._flows:
            if datum in flow.data:
                uids |= {_uuid(flow.source), _uuid(flow.sink)}
        for element in self._elements:
            if isinstance(element, Dataflow):
                continue
            own = getattr(element, "data", None)
            if own and not isinstance(own, str) and datum in own:
                uids.add(_uuid(element))
        for model_datum in self._data:
            if model_datum == datum:
                uids |= {_uuid(e) for e in getattr(model_datum, "processedBy", [])}
        return [
            self._show(e)
            for e in self._elements
            if _uuid(e) in uids and not isinstance(e, Dataflow)
        ]

    def data_findings(self, datum: Any) -> list[Any]:
        """Findings against the dataflows carrying *datum*, in finding order."""
        uids = {_uuid(f) for f in self._flows if datum in f.data}
        return [f for f in self._findings if _uuid(getattr(f, "element", None)) in uids]

    # -- boundaries ---------------------------------------------------------

    def members(self, boundary: Any) -> list[Any]:
        """Elements and boundaries directly inside *boundary*."""
        from .dataflow import Dataflow

        uid = _uuid(boundary)
        return [
            self._show(e)
            for e in self._elements
            if not isinstance(e, Dataflow)
            and _uuid(getattr(e, "inBoundary", None)) == uid
        ]

    # -- findings and threats ---------------------------------------------

    def findings(self, element: Any) -> list[Any]:
        """Findings against *element*."""
        uid = _uuid(element)
        return [f for f in self._findings if _uuid(getattr(f, "element", None)) == uid]

    def threats(self, element: Any) -> list[Any]:
        """Distinct threats that fired against *element*, in library order."""
        ids = {f.threat_id for f in self.findings(element)}
        return [t for t in self._threats if t.id in ids]

    def fired_threats(self) -> list[Any]:
        """Distinct threats with at least one finding, in library order."""
        ids = {f.threat_id for f in self._findings}
        return [t for t in self._threats if t.id in ids]

    def findings_for(self, threat: Any) -> list[Any]:
        """Findings produced by *threat* (a threat, or a threat id)."""
        threat_id = getattr(threat, "id", threat)
        return [f for f in self._findings if f.threat_id == threat_id]

    # -- assumptions and what they suppress --------------------------------

    def _owner_of(self, finding: Any) -> Any:
        """The element whose assumption suppressed *finding* (None: model)."""
        element = self._original(getattr(finding, "element", None))
        own = getattr(element, "assumptions", None) or []
        return element if any(a == finding.assumption for a in own) else None

    def _entries(self) -> list[AssumptionEntry]:
        """Every assumption: the model's, then each element's, in order."""
        if self._assumption_entries is not None:
            return self._assumption_entries
        from .anchors import anchor, slugify

        known = {t.id for t in self._threat_library}
        owners = [(None, a) for a in self._model_assumptions]
        owners += [
            (e, a)
            for e in self._elements
            for a in getattr(e, "assumptions", None) or []
        ]
        used: set[str] = set()
        entries = []
        for owner, assumption in owners:
            base = "assumption-" + slugify(assumption.name, fallback="unnamed")
            if owner is not None:
                base = f"{anchor(owner)}-{base}"
            candidate, number = base, 2
            while candidate in used:
                candidate, number = f"{base}-{number}", number + 1
            used.add(candidate)
            suppressed = tuple(
                f
                for f in self._suppressed
                if f.assumption == assumption
                and _uuid(self._owner_of(f)) == _uuid(owner)
            )
            pending: tuple[Any, ...] = ()
            if self._require_verified and not assumption.verified:
                pending = tuple(
                    f
                    for f in self._findings
                    if f.threat_id in assumption.exclude
                    and (
                        owner is None
                        or _uuid(getattr(f, "element", None)) == _uuid(owner)
                    )
                )
            hit = {f.threat_id for f in suppressed + pending}
            entries.append(
                AssumptionEntry(
                    assumption,
                    self._show(owner) if owner is not None else None,
                    candidate,
                    suppressed,
                    tuple(
                        t
                        for t in sorted(assumption.exclude)
                        if t in known and t not in hit
                    ),
                    tuple(t for t in sorted(assumption.exclude) if t not in known),
                    pending,
                )
            )
        self._assumption_entries = entries
        return entries

    def assumptions(self, owner: Any = None) -> list[AssumptionEntry]:
        """Assumptions about *owner* (an element), or about the whole model."""
        uid = _uuid(owner)
        return [
            e
            for e in self._entries()
            if (e.owner is None if owner is None else _uuid(e.owner) == uid)
        ]

    def assumption_of(self, finding: Any) -> AssumptionEntry | None:
        """The assumption that suppressed *finding*."""
        # By identity: comparing findings compares their elements, whose
        # references lead back to the findings.
        return next(
            (e for e in self._entries() if any(f is finding for f in e.suppressed)),
            None,
        )

    def all_assumptions(self) -> list[AssumptionEntry]:
        """Every assumption: the model's, then each element's, in order."""
        return list(self._entries())

    def pending_assumptions_of(self, finding: Any) -> list[AssumptionEntry]:
        """Unverified assumptions that would suppress *finding* once verified."""
        return [e for e in self._entries() if any(f is finding for f in e.pending)]

    def requires_verified_assumptions(self) -> bool:
        """Does the model only let verified assumptions suppress threats?"""
        return self._require_verified

    def suppressed(self, element: Any = None) -> list[Any]:
        """Findings suppressed by an assumption: all, or those on *element*."""
        if element is None:
            return list(self._suppressed)
        uid = _uuid(element)
        return [
            f for f in self._suppressed if _uuid(getattr(f, "element", None)) == uid
        ]

    def data_suppressed(self, datum: Any) -> list[Any]:
        """Suppressed findings on the dataflows carrying *datum*."""
        uids = {_uuid(f) for f in self._flows if datum in f.data}
        return [
            f for f in self._suppressed if _uuid(getattr(f, "element", None)) in uids
        ]

    def suppressed_for(self, threat: Any) -> list[Any]:
        """Suppressed findings of *threat* (a threat, or a threat id)."""
        threat_id = getattr(threat, "id", threat)
        return [f for f in self._suppressed if f.threat_id == threat_id]

    def reported_threats(self) -> list[Any]:
        """Threats with a finding, or a finding an assumption suppressed."""
        ids = {f.threat_id for f in self._findings + self._suppressed}
        return [t for t in self._threats if t.id in ids]

    def excluded_threats(self) -> list[tuple[str, Any]]:
        """Threats left out with ``--exclude``: (id, threat, or None if unknown)."""
        from .tm import TM

        library = {t.id: t for t in self._threats}
        return [(sid, library.get(sid)) for sid in TM._threatsExcluded]

    def remedies(self, finding: Any) -> list[list[Change]]:
        """Alternative sets of changes that would resolve *finding*."""
        threat = next(
            (t for t in self._threat_library if t.id == finding.threat_id), None
        )
        target = self._original(getattr(finding, "element", None))
        if threat is None or target is None:
            return []
        return remedies(threat, target)


def current() -> Relations:
    """The relations of the report being rendered, or of the whole model."""
    from .tm import TM

    active = TM._get_state().report_relations
    return active if active is not None else Relations()
