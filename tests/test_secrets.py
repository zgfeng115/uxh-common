import pytest

from uxh_common.secrets import MASK, is_masked, mask, merge_secret, redact


def test_mask():
    assert MASK == "***"
    assert mask("abc") == "***"
    assert mask("") == ""
    assert mask(None) == ""


def test_is_masked():
    assert is_masked("***") is True
    assert is_masked("") is False
    assert is_masked(None) is False
    assert is_masked("****") is False


@pytest.mark.parametrize("incoming,expected", [(None, "old"), ("", "old"), ("***", "old"), ("new", "new")])
def test_merge_secret(incoming, expected):
    assert merge_secret(incoming, "old") == expected


def test_redact_multiple():
    assert redact("u=AAA p=BBB", ["AAA", "BBB"]) == "u=*** p=***"


def test_redact_nested():
    assert redact("tok=abcdef", ["abc", "abcdef"]) == "tok=***"


def test_redact_empty_and_none():
    assert redact("x", []) == "x"
    assert redact("x", [None, ""]) == "x"
    assert redact("", ["a"]) == ""
