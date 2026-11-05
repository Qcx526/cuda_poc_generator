# -*- coding: utf-8 -*-
"""Native/Python parity.

If the two implementations diverge, no metric from either one means anything.
"""

import os

import pytest

from mock_native import binding as nb

pytestmark = pytest.mark.skipif(not nb.DLL.is_file(), reason="mock_gpu.dll 未构建")


def test_authz_bypass_matches_between_native_and_python():
    steps = [nb.Step("open", ()), nb.Step("device", ()), nb.Step("context", ()),
             nb.Step("device2", ()), nb.Step("escape_cross", ())]
    os.environ["MOCK_GPU_JUDGE"] = "1"
    native_status, native_triggers = nb.run_script(nb.load(), steps)
    python_status, python_triggers = nb.python_triggers(steps)
    assert native_status == python_status
    assert native_triggers == python_triggers == [nb.TRIGGER_AUTHZ]


def test_oob_matches_between_native_and_python():
    steps = [nb.Step("open", ()), nb.Step("device", ()), nb.Step("context", ()),
             nb.Step("escape_oob", ())]
    os.environ["MOCK_GPU_JUDGE"] = "1"
    native_status, native_triggers = nb.run_script(nb.load(), steps)
    python_status, python_triggers = nb.python_triggers(steps)
    assert native_status == python_status
    assert native_triggers == python_triggers == [nb.TRIGGER_OOB]


def test_normal_input_triggers_nothing_in_either_implementation():
    steps = [nb.Step("open", ()), nb.Step("device", ()), nb.Step("context", ()),
             nb.Step("escape_normal", ())]
    os.environ["MOCK_GPU_JUDGE"] = "1"
    native_status, native_triggers = nb.run_script(nb.load(), steps)
    python_status, python_triggers = nb.python_triggers(steps)
    assert native_status == python_status
    assert native_triggers == python_triggers == []
