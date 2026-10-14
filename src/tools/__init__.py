"""CUDA PoC tool adapters with bounded process evidence and ELF64LE checks.

Generated candidates can import these functions rather than duplicate binary
layouts or process handling. Compilation and structural validation cannot attest
candidate execution or verification of a vulnerability.

Layer 2 tools (this package):
  env.py      — GPU/CUDA environment detection
  compile.py  — nvcc compilation with MSVC setup
  elf_ops.py  — ELF64 section parsing and modification
  inspect.py  — cuobjdump / nvdisasm wrappers

Usage in generated PoC:
    from src.tools.compile import compile_cubin, compile_kernel_source
    from src.tools.elf_ops import find_section, replace_section_content, patch_section_field
    from src.tools.inspect import nvdisasm_run, is_access_violation
    from src.tools.env import get_gpu_compute_capability, setup_msvc_env
"""

# Environment
from .env import (
    find_cuda_tool, find_msvc_vcvarsall, get_cuda_toolkit_version,
    get_cuda_driver_version, get_gpu_compute_capability, setup_msvc_env,
    get_compiler_info,
)

# Compilation
from .compile import (compile_cubin, compile_kernel_source, compile_cubin_result,
                      CompileResult, CompileError, prepare_msvc_environment)

# ELF operations
from .elf_ops import (
    ELF64_SHDR_FMT, ELF64_SHDR_SIZE,
    SHT_REL, SHT_RELA, SHT_PROGBITS, SHT_SYMTAB,
    find_section, find_sections_by_type,
    replace_section_content, append_section, patch_section_field,
    validate_elf_structure, get_section_info,
)

# Toolchain inspection
from .inspect import (
    cuobjdump_elf, nvdisasm_run, nvdisasm_has_relocation_sections,
    get_nvdisasm_version, is_access_violation,
    cuobjdump_result, nvdisasm_result,
)

# Web Search
from .search import search_cve, search_cuda_vuln, search_to_context, is_available as search_available

__all__ = [
    "find_cuda_tool", "find_msvc_vcvarsall", "get_cuda_toolkit_version",
    "get_cuda_driver_version", "get_gpu_compute_capability", "setup_msvc_env",
    "get_compiler_info",
    "compile_cubin", "compile_kernel_source",
    "compile_cubin_result", "CompileResult", "CompileError", "prepare_msvc_environment",
    "ELF64_SHDR_FMT", "ELF64_SHDR_SIZE",
    "SHT_REL", "SHT_RELA", "SHT_PROGBITS", "SHT_SYMTAB",
    "find_section", "find_sections_by_type",
    "replace_section_content", "append_section", "patch_section_field",
    "validate_elf_structure", "get_section_info",
    "cuobjdump_elf", "nvdisasm_run", "nvdisasm_has_relocation_sections",
    "get_nvdisasm_version", "is_access_violation",
    "cuobjdump_result", "nvdisasm_result",
    "search_cve", "search_cuda_vuln", "search_to_context", "search_available",
]


def get_tools_reference_text() -> str:
    """Return a prompt-safe reference block describing available tools.
    Inject this into the LLM code generation prompt so it knows what to import.
    """
    return """\
## IMPORTABLE TOOL LIBRARY

These functions provide process evidence and supported ELF64LE structure checks.
No tool outcome by itself verifies a CVE. To use them, your PoC script must first add the project root to sys.path
(because the script runs from data/outputs/<CVE>/ which is 4 levels deep):

```python
import os, sys
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
```

Then import the tools you need:
# Environment detection
from src.tools.env import (
    find_cuda_tool,             # find nvcc/cuobjdump path
    get_gpu_compute_capability, # observed 'sm_*' or None
    setup_msvc_env,             # validates an already prepared MSVC environment
)

# Compilation
from src.tools.compile import (
    compile_cubin,              # explicit arch required; prepared Windows MSVC env
    compile_kernel_source,      # returns two retained paths; caller cleans task dir
)

# ELF operations (strict ELF64 little endian; unsupported variants are rejected)
from src.tools.elf_ops import (
    ELF64_SHDR_FMT,             # '<IIQQQQIIQQ' (64 bytes)
    find_section,               # find section by name
    find_sections_by_type,      # find all REL/RELA sections
    replace_section_content,    # replace content, update sh_offset/sh_size
    patch_section_field,        # modify sh_link/sh_info/sh_size
    validate_elf_structure,     # structural errors; not execution/CVE verification
)

# Toolchain
from src.tools.inspect import (
    nvdisasm_run,               # run nvdisasm, returns (ok, stdout, stderr, rc)
    is_access_violation,        # exact Windows access violation; not a CVE verdict
    cuobjdump_elf,              # structured cuobjdump output
)

# Web Search (Tavily — optional, needs TAVILY_API_KEY)
from src.tools.search import search_cve, search_cuda_vuln, search_to_context
```

Compilation requires an explicit arch or a validated target snapshot and a
separately prepared MSVC environment on Windows. ToolResult records raw bytes and
process status. Candidate execution remains NOT_EXECUTED / NOT_VERIFIED.
"""
