"""Offline SYNTHETIC admission failures. No native executable is started."""

from contextlib import ExitStack
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.execution_preflight import preflight_fixed_memcheck
from src.models.execution import snapshot_sha256
from src.models.lifecycle import canonical_sha256
from src.models.memcheck import MemcheckDescription, MemcheckRequest, MemcheckAuthorization, MemcheckPolicy
from src.models.tool_result import ToolIdentity
from src.memcheck_registry import fixed_source
from src import memcheck_sandbox
from tests.test_host_diagnostics_probe import tool_result
from tests.test_platform_probe import packet


def context():
    snapshot = packet()["snapshot"]
    label = snapshot["metadata"]["environment_label"]
    tools = {role:ToolIdentity(requested_executable="/synthetic/"+role,resolved_path="/synthetic/"+role,
        status="OBSERVED",file_sha256="1"*64,source="SYNTHETIC_OFFLINE") for role in (
        "compiler","valgrind","valgrind_launcher","memcheck","bwrap","guard_python")}
    collector = hashlib.sha256(Path(memcheck_sandbox.__file__).read_bytes()).hexdigest()
    description = MemcheckDescription(description_id="d"*32,status="DESCRIBED",target_environment=label,
        snapshot=snapshot,native_task_root="/synthetic-root",tools=tools,helper_images={},collector_sha256=collector,
        versions={role:tool_result([tools[role].resolved_path,"--version"],tool=tools[role].model_dump(mode="json"))
                  for role in ("compiler","valgrind","bwrap")},target_boot_id="synthetic-boot",observed_monotonic_ns=100000000000,
        diagnostics=[])
    request = MemcheckRequest(request_id="a"*32,run_id="b"*32,task_id="p3c-normal-v1",
        source_sha256=hashlib.sha256(fixed_source("p3c-normal-v1")).hexdigest(),description_sha256=canonical_sha256(description),
        collector_sha256=collector,platform_environment_id=description.snapshot.environment_id,
        platform_probe_id=description.snapshot.metadata["probe_id"],snapshot_sha256=snapshot_sha256(description.snapshot),
        target_environment=label,target_boot_id=description.target_boot_id,observed_monotonic_ns=description.observed_monotonic_ns,
        tools=tools,helper_images={},resource_limits={},authorization_reference="synthetic-user-approval")
    auth=MemcheckAuthorization(request_id=request.request_id,run_id=request.run_id,task_id=request.task_id,
        request_sha256=canonical_sha256(request),operator_id="synthetic-operator",authorization_reference=request.authorization_reference,
        issuer_kind="operator",target_boot_id=request.target_boot_id,not_before_monotonic_ns=description.observed_monotonic_ns,
        expires_monotonic_ns=description.observed_monotonic_ns+300000000000)
    policy=MemcheckPolicy(request_sha256=canonical_sha256(request),description_sha256=request.description_sha256,
        allowed_operator_ids=[auth.operator_id],allowed_authorization_references=[auth.authorization_reference],
        allowed_images={x.resolved_path:x.file_sha256 for x in tools.values()},native_task_root=description.native_task_root,
        resource_limits=request.resource_limits)
    return request,auth,policy,description


def check(request,auth,policy,description,*,tool_status="OBSERVED",tool_hash="1"*64,clock=101000000000,hard=-1,target=None):
    mocked_resource=SimpleNamespace(RLIMIT_CPU=0,RLIMIT_AS=1,RLIMIT_FSIZE=2,RLIMIT_NOFILE=3,RLIM_INFINITY=-1,
                                    getrlimit=lambda kind:(hard,hard))
    with ExitStack() as stack:
        stack.enter_context(patch("src.execution_preflight.current_platform_type",return_value="wsl"))
        stack.enter_context(patch("src.tools.process.canonical_target_environment",return_value=target or request.target_environment))
        stack.enter_context(patch("src.execution_preflight.target_boot_id",return_value=request.target_boot_id))
        stack.enter_context(patch("src.execution_preflight.time.monotonic_ns",return_value=clock))
        stack.enter_context(patch("src.execution_preflight.fixed_memcheck_task_root",return_value=Path("/synthetic-root")))
        stack.enter_context(patch("src.tools.process.measure_tool_identity",side_effect=lambda path,**kwargs:
            ToolIdentity(requested_executable=path,resolved_path=path,status=tool_status,
                file_sha256=tool_hash if tool_status=="OBSERVED" else None,source="SYNTHETIC")))
        stack.enter_context(patch.dict("sys.modules",{"resource":mocked_resource}))
        stack.enter_context(patch("subprocess.Popen",side_effect=AssertionError("preflight must not start native processes")))
        return preflight_fixed_memcheck(request,auth,policy,description,project_root=Path(__file__).resolve().parents[1])


def test_ready_admits_only_guard_without_claiming_enforced_resources():
    result=check(*context())
    assert result.status=="READY" and result.candidate_execution_status=="NOT_EXECUTED"
    assert result.measured_tool_sha256=="1"*64


@pytest.mark.parametrize("mode,status,code",[
    ("no_auth","REJECTED","AUTHORIZATION_MISSING"),
    ("expired","REJECTED","AUTHORIZATION_EXPIRED"),
    ("stale","REJECTED","PLATFORM_SNAPSHOT_STALE"),
    ("unknown_tool","UNKNOWN","TOOL_IDENTITY_UNKNOWN"),
    ("replaced_tool","REJECTED","TOOL_IDENTITY_MISMATCH"),
    ("wrong_target","REJECTED","ACTUAL_TARGET_MISMATCH"),
    ("low_resource","UNSUPPORTED","RESOURCE_PROFILE_UNSUPPORTED"),
    ("wrong_operator","REJECTED","AUTHORIZATION_UNTRUSTED"),
    ("changed_request","REJECTED","AUTHORIZATION_SCOPE_MISMATCH"),
])
def test_failures_never_dispatch_or_upgrade(mode,status,code):
    req,auth,policy,desc=context()
    options={}
    if mode=="no_auth":auth=None
    if mode=="expired":options["clock"]=500000000000
    if mode=="stale":
        policy=policy.model_copy(update={"max_description_age_seconds":1})
        options["clock"]=102000000000
    if mode=="unknown_tool":options["tool_status"]="UNKNOWN"
    if mode=="replaced_tool":options["tool_hash"]="e"*64
    if mode=="wrong_target":options["target"]="wsl:Foreign"
    if mode=="low_resource":options["hard"]=1
    if mode=="wrong_operator":auth=auth.model_copy(update={"operator_id":"untrusted"})
    if mode=="changed_request":req=req.model_copy(update={"run_id":"f"*32})
    result=check(req,auth,policy,desc,**options)
    assert result.status==status and result.diagnostics[0].code==code
    assert result.verification_status=="NOT_VERIFIED"


@pytest.mark.parametrize("change",[{"task_id":"unknown"},{"authorized_action":"EXECUTE_CANDIDATE"},
    {"argv":["sh","-c","anything"]},{"source_sha256":"0"*64}])
def test_request_cannot_expand_to_other_tasks_or_commands(change):
    raw=context()[0].model_dump(mode="python")
    raw.update(change)
    with pytest.raises(ValueError):MemcheckRequest.model_validate(raw)
