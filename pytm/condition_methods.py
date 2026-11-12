"""Model methods that threat conditions may call.

A threat condition such as ``target.hasDataLeaks()`` may only call methods
marked with one of these decorators; the condition validator rejects any
other call. The marker also tells the remedy analysis
(:func:`pytm.relations.remedies`) what the method computes:

``@condition_method("<expression>")``
    The method *is* the expression: the decorator generates its body from
    it, and remedies inline the same expression, so the two can't drift
    apart. ``self`` and the method's parameters can be used in it::

        @condition_method("any(f.tlsVersion < self.minTLSVersion for f in flows)")
        def checkTLSVersion(self, flows) -> bool:
            \"\"\"Does any of *flows* use a TLS version below the minimum?\"\"\"

``@opaque_condition_method``
    For methods that can't be written as one expression (for example ones
    that test classes). Conditions may call them, and remedies can only say
    that the result has to change.
"""

from __future__ import annotations

import ast
import functools
import inspect
from collections.abc import Callable
from typing import Any

_EXPRESSION = "__condition_expression__"
_OPAQUE = "__condition_opaque__"

# Names of all methods marked with either decorator, including methods of
# user-defined subclasses (registered when their class is defined).
_NAMES: set[str] = set()


def condition_method(expression: str) -> Callable[[Callable], Callable]:
    """Make the decorated method compute *expression* (see the module docs)."""

    def decorate(func: Callable) -> Callable:
        signature = inspect.signature(func)
        parameters = tuple(signature.parameters)[1:]  # without "self"
        compiled: list[Any] = []

        @functools.wraps(func)
        def method(self, *args, **kwargs):
            if not compiled:
                compiled.append(_compile(expression, parameters, func.__qualname__))
            bound = signature.bind(self, *args, **kwargs)
            bound.apply_defaults()
            # Arguments go in the globals: a generator expression in the
            # expression has its own scope and can't see eval() locals.
            names = {**_globals(), **bound.arguments}
            return eval(compiled[0], names)  # noqa: S307

        setattr(method, _EXPRESSION, expression)
        method.__condition_parameters__ = parameters
        _NAMES.add(func.__name__)
        return method

    return decorate


def opaque_condition_method(func: Callable) -> Callable:
    """Allow conditions to call *func*, which has no expression form."""
    setattr(func, _OPAQUE, True)
    _NAMES.add(func.__name__)
    return func


def method_expression(owner: Any, name: str) -> tuple[str, tuple[str, ...]] | None:
    """``(expression, parameters)`` of method *name* of *owner*, if it has one."""
    method = getattr(type(owner) if not isinstance(owner, type) else owner, name, None)
    expression = getattr(method, _EXPRESSION, None)
    if expression is None:
        return None
    return expression, method.__condition_parameters__


def condition_method_names() -> set[str]:
    """Names of the methods conditions may call (marked with a decorator)."""
    return set(_NAMES)


def _globals() -> dict[str, Any]:
    from .threat import Threat

    return Threat._build_eval_globals()


def _compile(expression: str, parameters: tuple[str, ...], where: str):
    """Validate *expression* like a threat condition, then compile it."""
    from .threat import Threat, _ConditionValidator

    tree = ast.parse(expression, mode="eval")
    allowed = Threat._allowed_global_names() | {"self", *parameters}
    _ConditionValidator(allowed).visit(tree)
    return compile(tree, f"<condition method {where}>", "eval")
