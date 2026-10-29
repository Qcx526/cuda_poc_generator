# -*- coding: utf-8 -*-
"""The generator writes its own helpers; nothing stops it from disagreeing with itself."""

import ast

from src.quality_lints import lint_unpack_arity_mismatch

RETURNS_FOUR = """
import subprocess

def run_capture(cmd, timeout=120):
    try:
        proc = subprocess.run(cmd, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr, False
    except Exception:
        return None, b"", b"", True

def main():
    rc, out, err = run_capture(["ls"])
"""

RETURNS_THREE = RETURNS_FOUR.replace(", False", "").replace(", True", "")


def _lint(code: str):
    return lint_unpack_arity_mismatch(ast.parse(code))


def test_unpacking_three_from_a_four_tuple_is_reported():
    findings = _lint(RETURNS_FOUR)
    assert len(findings) == 1
    assert "unpacks 3" in findings[0] and "returns 4" in findings[0]


def test_matching_arity_is_silent():
    assert _lint(RETURNS_THREE) == []


def test_too_many_positional_arguments_is_reported():
    code = """
def helper(a, b):
    return a

helper(1, 2, 3)
"""
    findings = _lint(code)
    assert any("takes 2" in f for f in findings)


def test_skips_functions_with_varargs():
    """*args makes the expected count unknowable; guessing there would be noise."""
    code = """
def helper(*args):
    return 1, 2

a, b, c = helper(1, 2, 3, 4)
"""
    assert _lint(code) == []


def test_skips_when_a_return_value_is_not_a_fixed_tuple():
    code = """
def helper(flag):
    if flag:
        return 1, 2, 3
    return compute()

a, b = helper(True)
"""
    assert _lint(code) == []


def test_skips_decorated_functions():
    """A decorator can change the signature; do not reason about it."""
    code = """
@wraps
def helper(a):
    return 1, 2, 3

x, y = helper(1)
"""
    assert _lint(code) == []
