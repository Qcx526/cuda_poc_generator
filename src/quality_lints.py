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

# Only APIs that consume attacker-controlled state need initialisation.
# nvapi_QueryInterface is deliberately absent: it merely resolves a function
# pointer, so a resolver named "probe_*" is not a probe and must not be flagged.
_PROBE_CALLS = {
    "cuModuleLoadData", "cuModuleLoadDataEx", "cuModuleLoad",
    "nvmlDeviceGetHandleByIndex_v2", "nvmlDeviceGetMemoryInfo",
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
    """Flag probe entry points whose reachable calls never initialize.

    Limitation: only direct calls are visible. A probe that invokes a callable
    pulled from a builder (``for name, fn in targets: fn(value)``) escapes this
    lint; the dynamic layer covers that case when the call returns
    CUDA_ERROR_NOT_INITIALIZED and the loop diagnoses PRECONDITION_VIOLATED.
    """
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


# Only adding a section needs the string-table bookkeeping, so only that case
# is refused. Patching an existing field in place is a supported mutation on its
# own and must stay allowed - forcing the helper there cost a working target its
# success rate.
_ELF_SECTION_CREATION = ("shstrtab", "add_section", "append_section", "new section")
_KIT_IMPORT = re.compile(r"^\s*(?:from\s+cpgkit\s+import|import\s+cpgkit)", re.M)


def lint_elf_layout_built_by_hand(code: str) -> List[str]:
    """Flag ELF layout arithmetic written from scratch.

    The mistakes are always the same shape - a section sized to its header, a
    name never added to the string table, an offset taken before alignment - and
    the result is a file that looks fine but that the tool reports as having no
    such section. cpgkit keeps that bookkeeping; hand-rolling it is avoidable
    work with a known failure mode.
    """
    lowered = code.lower()
    if not any(token in lowered for token in _ELF_SECTION_CREATION):
        return []
    if _KIT_IMPORT.search(code):
        return []
    return ["a new ELF section is created by hand (shstrtab bookkeeping) "
            "without importing cpgkit"]


_PROJECT_IMPORT = re.compile(r"^\s*(?:from|import)\s+(?:src|tools|specs|tests)\b", re.M)


def lint_project_import(code: str) -> List[str]:
    """Flag imports of this repository's own packages.

    The candidate runs inside a container that mounts only its own directory, so
    ``from src.tools.env import ...`` raises ModuleNotFoundError before the first
    step. It looks like a plausible import because the generator has seen this
    repository, which is exactly why it needs a rule rather than vigilance.
    """
    hits = sorted({m.group(0).strip() for m in _PROJECT_IMPORT.finditer(code)})
    if not hits:
        return []
    return ["the candidate imports this project's own packages (%s); it must be "
            "self-contained" % ", ".join(hits[:3])]


_BUILTIN_GENERICS = {"list", "dict", "set", "tuple", "frozenset", "type"}


def lint_builtin_generics_on_py38(code: str, tree: ast.Module) -> List[str]:
    """Flag syntax that only works on 3.9+ when the container runs 3.8.

    ``def f(x: list[str])`` is valid syntax and a runtime TypeError on 3.8, so
    the failure lands at import time and looks like a broken script rather than
    a version mismatch. ``from __future__ import annotations`` defers the
    evaluation, so that case is left alone.
    """
    source = code
    if re.search(r"^\s*from\s+__future__\s+import\s+annotations", source, re.M):
        return []
    hits = []
    # Only annotation positions matter: a plain `flags | mask` expression is
    # ordinary bitwise OR and must never be rejected.
    annotations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            annotations.append(node.annotation)
        elif isinstance(node, ast.AnnAssign) and node.annotation is not None:
            annotations.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            annotations.append(node.returns)
    for ann in annotations:
        for node in ast.walk(ann):
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) \
                    and node.value.id in _BUILTIN_GENERICS:
                hits.append("%s[...]" % node.value.id)
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
                hits.append("X | Y")
    if not hits:
        return []
    return ["Python 3.8 runtime: %s is not supported at runtime; use typing.List/"
            "Optional or add 'from __future__ import annotations'" % ", ".join(sorted(set(hits))[:3])]


_OWN_VERDICT_TAGS = ("[CPG_VERDICT]", "[CPG_INFO]")


def lint_missing_run_lines(code: str) -> List[str]:
    """Flag scripts that report results in their own format.

    The grader reads `[CPG_RUN] <file> exit=<code>`; a script that prints
    `[CPG_VERDICT] ...` instead is unreadable no matter how correct its own
    conclusion was, and the run is recorded as "no observations" - the most
    misleading failure there is, because the work was done.
    """
    if "[CPG_RUN]" in code:
        return []
    hits = [tag for tag in _OWN_VERDICT_TAGS if tag in code]
    if hits:
        return ["the script reports results as %s instead of the required "
                "'[CPG_RUN] <file> exit=<code>' line" % ", ".join(hits)]
    return []


def lint_missing_artifact_manifest(code: str) -> List[str]:
    """Flag a script that produces artifacts without declaring their roles.

    The grader labels roles from `artifacts.json`. Without it, roles fall back to
    filename prefixes and every undeclared file gets executed - both of which
    have already produced a wrong verdict and a twenty-four minute run.
    """
    if "artifacts.json" in code:
        return []
    if ".cubin" not in code and ".elf" not in code and ".fatbin" not in code:
        return []
    return ["the script produces ELF artifacts but never writes artifacts.json, "
            "so their roles are undeclared"]


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
    for message in lint_elf_layout_built_by_hand(code):
        findings.append(("elf-layout-built-by-hand", message))
    for message in lint_project_import(code):
        findings.append(("project-import-in-poc", message))
    for message in lint_builtin_generics_on_py38(code, tree):
        findings.append(("py38-incompatible-syntax", message))
    for message in lint_missing_run_lines(code):
        findings.append(("missing-run-lines", message))
    for message in lint_missing_artifact_manifest(code):
        findings.append(("missing-artifact-manifest", message))
    return findings
