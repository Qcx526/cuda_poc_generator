# -*- coding: utf-8 -*-
"""Domain lints for generated PoCs.

Each lint encodes a failure that a real generated PoC committed and that
syntax/import checks let through. They run after the generic checks so the
correction loop can hand the model a specific, actionable complaint:

- ``version-classifier-unknown-major``: a version classifier that answers
  NOT-AFFECTED for an unmapped major silently declares patched builds
  vulnerable or vice versa (CVE-2024-0090: major 551 missing from the branch
  table produced a false PATCHED).
- ``driver-probe-without-context``: probes against nvcuda/nvml/nvapi need
  initialization first; without cuInit/cuCtxCreate every call returns
  CUDA_ERROR_NOT_INITIALIZED and the whole matrix measures nothing
  (CVE-2024-0091: 35 probes, all vacuous).
- ``legacy-token-search-on-modern-profile``: D3DSIO_* opcodes are SM2/SM3;
  a ps_5_0/SM4 byte stream does not contain them, so searching for such
  tokens patches arbitrary operand bytes (CVE-2024-0107).
"""

import ast
import re
from typing import List, Tuple

# Lint B -----------------------------------------------------------------

_PROBE_CALLS = {
    "cuModuleLoadData", "cuModuleLoadDataEx", "cuModuleLoad",
    "nvmlDeviceGetHandleByIndex_v2", "nvmlDeviceGetMemoryInfo",
    "nvapi_QueryInterface",
}
_INIT_CALLS = {"cuInit", "cuCtxCreate_v2", "cuCtxCreate", "D3D11CreateDevice"}


def _called_names(func: ast.FunctionDef) -> set:
    """Names called directly inside one function definition."""
    names = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Name):
                names.add(target.id)
            elif isinstance(target, ast.Attribute):
                names.add(target.attr)
    return names


def _reachable_calls(func: ast.FunctionDef, table: dict) -> set:
    """Union of calls made by ``func`` and every function it can reach."""
    seen, stack, calls = set(), [func.name], set()
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        body = table.get(name)
        if body is None:
            continue
        calls |= _called_names(body)
        for callee in _called_names(body):
            if callee in table and callee not in seen:
                stack.append(callee)
    return calls


def lint_driver_probe_without_context(tree: ast.Module) -> List[str]:
    """Flag probe entry points whose reachable calls never initialize."""
    functions = {node.name: node for node in ast.walk(tree)
                 if isinstance(node, ast.FunctionDef)}
    findings = []
    for name, func in functions.items():
        direct = _called_names(func)
        if not (direct & _PROBE_CALLS):
            continue
        if "probe" not in name.lower() and "single" not in name.lower():
            continue
        reachable = _reachable_calls(func, functions)
        if not (reachable & _INIT_CALLS):
            findings.append(
                "driver-probe-without-context: function %r calls a driver API "
                "probe but its reachable code never calls cuInit/cuCtxCreate/"
                "D3D11CreateDevice; every probe will return "
                "CUDA_ERROR_NOT_INITIALIZED before touching the vulnerable path"
                % name)
    return findings


# Lint A -----------------------------------------------------------------


def lint_version_classifier_unknown_major(tree: ast.Module) -> List[str]:
    """Flag classifiers that answer NOT-AFFECTED when a version is unmapped.

    ``x not in y`` parses as ``Compare(x, [NotIn], y)`` while
    ``not (x in y)`` parses as ``UnaryOp(Not, Compare(x, [In], y))``; both
    spellings must be recognised.
    """
    findings = []

    def membership_negated(test: ast.expr) -> bool:
        if isinstance(test, ast.Compare):
            return any(isinstance(op, ast.NotIn) for op in test.ops)
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            operand = test.operand
            if isinstance(operand, ast.Compare):
                return any(isinstance(op, ast.In) for op in operand.ops)
        return False

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(func):
            if not isinstance(node, ast.If):
                continue
            if not membership_negated(node.test):
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Return):
                    continue
                value = child.value
                if isinstance(value, ast.Constant) and value.value is False:
                    findings.append(
                        "version-classifier-unknown-major: %r returns False for "
                        "unmapped versions; an unknown branch must map to "
                        "UNKNOWN, never to NOT-AFFECTED" % func.name)
                    break
                if isinstance(value, ast.Tuple) and value.elts:
                    first = value.elts[0]
                    if isinstance(first, ast.Constant) and first.value is False:
                        findings.append(
                            "version-classifier-unknown-major: %r returns "
                            "(False, ...) for unmapped versions; an unknown "
                            "branch must map to UNKNOWN, never to NOT-AFFECTED"
                            % func.name)
                        break
            else:
                continue
            break
    return findings


# Lint C -----------------------------------------------------------------

_MODERN_PROFILE = re.compile(r"['\"](?:ps|vs|cs|gs|hs|ds)_5_\d['\"]")
_LEGACY_TOKEN = re.compile(r"D3DSIO_[A-Z0-9_]+")


def lint_legacy_token_search_on_modern_profile(code: str) -> List[str]:
    """Flag SM2/SM3 token searches against an SM4/SM5 shader profile."""
    if _MODERN_PROFILE.search(code) and _LEGACY_TOKEN.search(code):
        return ["legacy-token-search-on-modern-profile: the PoC compiles an "
                "SM4/SM5 profile but searches for D3DSIO_* tokens; those "
                "opcodes only exist in SM2/SM3 streams, so any hit is operand "
                "data being patched as an instruction"]
    return []


# Entry point ------------------------------------------------------------


def run_lints(code: str) -> List[Tuple[str, str]]:
    """Run every lint; returns (lint_id, message) pairs, empty when clean."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    findings: List[Tuple[str, str]] = []
    for message in lint_version_classifier_unknown_major(tree):
        findings.append(("version-classifier-unknown-major", message))
    for message in lint_driver_probe_without_context(tree):
        findings.append(("driver-probe-without-context", message))
    for message in lint_legacy_token_search_on_modern_profile(code):
        findings.append(("legacy-token-search-on-modern-profile", message))
    return findings
