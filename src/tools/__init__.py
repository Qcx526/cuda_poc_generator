"""CUDA PoC Tool Library — battle-tested, importable tools for PoC code generation.

These tools encapsulate the patterns we've validated against real CUDA 11.2
cubin files on Windows. LLM-generated PoC code should import and use these
functions instead of reimplementing ELF manipulation or MSVC setup from scratch.

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
from .compile import compile_cubin, compile_kernel_source

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
)

# Web Search
from .search import search_cve, search_cuda_vuln, search_to_context, is_available as search_available

__all__ = [
    "find_cuda_tool", "find_msvc_vcvarsall", "get_cuda_toolkit_version",
    "get_cuda_driver_version", "get_gpu_compute_capability", "setup_msvc_env",
    "get_compiler_info",
    "compile_cubin", "compile_kernel_source",
    "ELF64_SHDR_FMT", "ELF64_SHDR_SIZE",
    "SHT_REL", "SHT_RELA", "SHT_PROGBITS", "SHT_SYMTAB",
    "find_section", "find_sections_by_type",
    "replace_section_content", "append_section", "patch_section_field",
    "validate_elf_structure", "get_section_info",
    "cuobjdump_elf", "nvdisasm_run", "nvdisasm_has_relocation_sections",
    "get_nvdisasm_version", "is_access_violation",
    "search_cve", "search_cuda_vuln", "search_to_context", "search_available",
]


def get_tools_reference_text() -> str:
    """Return a prompt-safe reference block describing available tools.
    Inject this into the LLM code generation prompt so it knows what to import.
    """
    return """\
## IMPORTABLE TOOL LIBRARY (use these — do NOT reimplement from scratch)

These are battle-tested, importable functions verified against CUDA 11.2 cubin
files. To use them, your PoC script MUST first add the project root to sys.path
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
    get_gpu_compute_capability, # returns 'sm_75' etc.
    setup_msvc_env,             # returns env dict with MSVC/SDK paths
)

# Compilation
from src.tools.compile import (
    compile_cubin,              # compile .cu -> .cubin with MSVC setup
    compile_kernel_source,      # compile from string, auto-cleanup temp files
)

# ELF operations (use these — verified correct for CUDA 11.2)
from src.tools.elf_ops import (
    ELF64_SHDR_FMT,             # '<IIQQQQIIQQ' (64 bytes)
    find_section,               # find section by name
    find_sections_by_type,      # find all REL/RELA sections
    replace_section_content,    # replace content, update sh_new_size
    patch_section_field,        # modify sh_link/sh_info/sh_size
    validate_elf_structure,     # integrity check before running tool
)

# Toolchain
from src.tools.inspect import (
    nvdisasm_run,               # run nvdisasm, returns (ok, stdout, stderr, rc)
    is_access_violation,        # check if exit code indicates crash
    cuobjdump_elf,              # structured cuobjdump output
)

# Web Search (Tavily — optional, needs TAVILY_API_KEY)
from src.tools.search import search_cve, search_cuda_vuln, search_to_context
```

USE these imports — they handle MSVC setup, correct struct formats, and platform
differences. Do NOT write your own struct.pack/unpack for ELF headers.
"""
