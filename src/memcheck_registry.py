"""Fixed reviewed CPU inputs and immutable plans; never accepts candidate argv."""

from dataclasses import dataclass
import hashlib
from pathlib import Path
from types import MappingProxyType


@dataclass(frozen=True)
class MemcheckTask:
    task_id: str
    source_file: str
    source_sha256: str


MEMCHECK_TASKS = MappingProxyType({
    "p3c-normal-v1": MemcheckTask("p3c-normal-v1", "normal.c", "430cb14334f368538ab36462b8956ab42b9727d7b0a10663c0196f4b8445e107"),
    "p3c-invalid-write-v1": MemcheckTask("p3c-invalid-write-v1", "invalid_write.c", "d69b5329039d1548c977ee3e86e8a895e9b79e10585a1bc09ca08817cd56ef7c"),
})
FIXED_MEMCHECK_ACTION = "FIXED_MEMCHECK_DIAGNOSTIC"
SANDBOX_PROFILE = "P3D_FIXED_CPU_MEMCHECK_V1"


def get_memcheck_task(task_id):
    if type(task_id) is not str or task_id not in MEMCHECK_TASKS:
        raise ValueError("仅支持已审核的 normal 和 invalid-write 固定 CPU fixture")
    return MEMCHECK_TASKS[task_id]


def fixed_source(task_id, project_root=None):
    task = get_memcheck_task(task_id)
    root = Path(project_root or Path(__file__).resolve().parent.parent)
    path = root / "tests" / "fixtures" / "host_diagnostics" / task.source_file
    if path.is_symlink() or not path.is_file():
        raise ValueError("固定源码缺失或使用符号链接")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != task.source_sha256:
        raise ValueError("固定源码 SHA-256 不符合冻结注册表")
    return raw


def inner_argv(step, tools):
    if step == "compile":
        return [tools["compiler"].resolved_path, "-std=c11", "-g", "-O0", "-Wall", "-Wextra",
                "-fno-omit-frame-pointer", "/input/fixture.c", "-o", "/out/fixture.bin"]
    if step == "memcheck":
        return [tools["valgrind_launcher"].resolved_path, "--tool=memcheck", "--xml=yes",
                "--xml-file=/out/memcheck.xml", "/target/fixture.bin"]
    raise ValueError("未注册的固定 Memcheck 步骤")
