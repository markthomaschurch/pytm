import pytest

from pytm import TM, Server


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    yield
    TM.reset()


@pytest.mark.parametrize(
    "first, second, expected",
    [
        (5, 2, 5),
        (2, 5, 5),
        ("Very High", "Low", 5),
        ("Low", "Very High", 5),
        ("Very High", 2, 5),
        (4, "Low", 4),
        (3, 0, 3),
    ],
)
def test_severity_keeps_the_highest(first, second, expected):
    web = Server("Web")

    web._set_severity(first)
    web._set_severity(second)

    assert web.severity == expected


def test_negative_and_unknown_values_are_ignored():
    web = Server("Web")

    web._set_severity(-3)
    web._set_severity("not a severity")

    assert web.severity == 0
