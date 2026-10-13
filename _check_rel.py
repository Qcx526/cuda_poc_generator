from src.tools.compile import compile_kernel_source
from src.tools.elf_ops import get_section_info
import os
cubin, _ = compile_kernel_source(
    'extern "C" __global__ void _k(){}',
    arch="sm_75", extra_flags="-G"
)
info = get_section_info(open(cubin, "rb").read())
rels = [s for s in info if s["type"] == 9]
print("SHT_REL sections:", [s["name"] for s in rels])
print("Total sections:", len(info))
os.unlink(cubin)
os.unlink(cubin.replace(".cubin", ".cu"))
