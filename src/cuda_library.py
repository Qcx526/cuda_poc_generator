# =============================================================================
# CUDA PoC Generator — CUDA 知识辅助库 (Domain Helper Library)
# =============================================================================
# 免责声明: 本工具仅供经过合法授权的安全研究与渗透测试使用。
# =============================================================================

"""
CUDA 领域辅助函数库。

提供 CUDA 漏洞 PoC 开发中常用的辅助函数签名与描述，
供代码生成器在提示中引用，避免 LLM 硬编码 CUDA API 细节。

覆盖:
  - CUDA Driver API (cu*)
  - CUDA Runtime API (cuda*)
  - nvcc / cuobjdump 工具调用
  - CUDA IPC / Stream / Event
  - ELF / cubin 解析
"""

import logging
from typing import Any, Callable, Dict, List

logger = logging.getLogger("cuda_poc_generator.cuda_library")


# =========================================================================
# CUDA Helper Signatures — 完整 CUDA PoC 辅助函数签名库
# =========================================================================

CUDA_HELPER_SIGNATURES: List[str] = [
    # ---------- CUDA Driver API ----------
    "cu_init(flags: int = 0) -> int",
    "  # 初始化 CUDA Driver API，返回 CUresult",
    "cu_device_get_count() -> int",
    "  # 获取可用 GPU 设备数量",
    "cu_device_get(device: int) -> CUdevice",
    "  # 获取指定索引的 CUDA 设备句柄",
    "cu_ctx_create(device: CUdevice, flags: int) -> CUcontext",
    "  # 为指定设备创建 CUDA 上下文",
    "cu_mem_alloc(size: int) -> CUdeviceptr",
    "  # 在 GPU 上分配 size 字节的全局内存",
    "cu_mem_free(dptr: CUdeviceptr) -> None",
    "  # 释放 GPU 全局内存",
    "cu_memcpy_htod(dst: CUdeviceptr, src: bytes, size: int) -> None",
    "  # 将主机内存拷贝到设备内存 (Host to Device)",
    "cu_memcpy_dtoh(dst: bytearray, src: CUdeviceptr, size: int) -> None",
    "  # 将设备内存拷贝到主机内存 (Device to Host)",
    "cu_module_load(data: bytes) -> CUmodule",
    "  # 从 cubin/PTX 二进制数据加载 CUDA 模块",
    "cu_module_get_function(module: CUmodule, name: str) -> CUfunction",
    "  # 从模块中获取指定名称的 kernel 函数",
    "cu_launch_kernel(f: CUfunction, grid: tuple, block: tuple, args: bytes, shared_mem: int, stream: CUstream) -> None",
    "  # 启动 CUDA kernel",
    "cu_ctx_synchronize() -> None",
    "  # 同步当前 CUDA 上下文的所有操作",

    # ---------- CUDA Runtime API ----------
    "cuda_malloc(size: int) -> int",
    "  # 使用 Runtime API 在 GPU 上分配内存",
    "cuda_memcpy(dst: int, src: int, size: int, kind: int) -> None",
    "  # 使用 Runtime API 拷贝内存",
    "cuda_free(ptr: int) -> None",
    "  # 使用 Runtime API 释放内存",
    "cuda_get_device_count() -> int",
    "  # 获取可用 GPU 设备数量",

    # ---------- CUDA Toolchain ----------
    "nvcc_compile(source_path: str, output_path: str, arch: str) -> bool",
    "  # 必须明确架构；使用 src.tools.compile 的受控编译接口，保留 ToolResult 原始证据",
    "cuobjdump_dump_elf(cubin_path: str) -> str",
    "  # 调用 cuobjdump --dump-elf 解析 cubin 的 ELF 结构",
    "nvdisasm_dump(cubin_path: str) -> str",
    "  # 调用 nvdisasm 反汇编 cubin 文件",
    "check_cuda_toolkit_version() -> str",
    "  # 检测已安装的 CUDA Toolkit 版本 (如 '12.8')",

    # ---------- ELF / cubin 二进制操作 ----------
    "parse_elf_header(data: bytes) -> dict",
    "  # 解析 64-bit ELF 头，返回 e_shoff, e_shnum, e_shstrndx 等字段",
    "parse_section_headers(data: bytes, e_shoff: int, e_shnum: int) -> list",
    "  # 解析所有 ELF section headers",
    "locate_shstrtab(data: bytes, shdrs: list, e_shstrndx: int) -> dict",
    "  # 定位 .shstrtab section 并返回其偏移和大小",
    "append_section(data: bytearray, name: str, body: bytes) -> dict",
    "  # 向 ELF 文件追加新 section，更新 .shstrtab、section header table、ELF header",
    "craft_cubin_section(section_type: str, payload: bytes) -> bytes",
    "  # 构造特定类型的 cubin section 数据",
    "modify_elf_field(data: bytearray, offset: int, value: bytes) -> None",
    "  # 修改 ELF 文件中指定偏移处的字段值",

    # ---------- 通用二进制/内存操作 ----------
    "pack_u16(value: int, endian: str = 'little') -> bytes",
    "  # 将整数打包为 16-bit 无符号整数",
    "pack_u32(value: int, endian: str = 'little') -> bytes",
    "  # 将整数打包为 32-bit 无符号整数",
    "pack_u64(value: int, endian: str = 'little') -> bytes",
    "  # 将整数打包为 64-bit 无符号整数",
    "trigger_integer_wrap(value: int, bits: int) -> int",
    "  # 构造特定比特宽度的整数回绕值 (如 0xFFFF + 1 = 0x0000 for 16-bit)",
    "create_heap_spray(size: int, pattern: bytes) -> bytes",
    "  # 生成堆喷数据，用于精确控制内存布局",
    "check_crash_signal(output: str) -> bool",
    "  # 检查程序输出中是否包含 SIGSEGV/SIGABRT 等崩溃信号",
]

# CUDA 错误码映射 — 完整版 (基于 NVIDIA CUDA Toolkit cuda.h)
CUDA_ERROR_CODES: Dict[int, str] = {
    # ---- Success ----
    0: "CUDA_SUCCESS",

    # ---- Core Runtime Errors ----
    1: "CUDA_ERROR_INVALID_VALUE",
    2: "CUDA_ERROR_OUT_OF_MEMORY",
    3: "CUDA_ERROR_NOT_INITIALIZED",
    4: "CUDA_ERROR_DEINITIALIZED",
    5: "CUDA_ERROR_PROFILER_DISABLED",
    6: "CUDA_ERROR_PROFILER_NOT_INITIALIZED",
    7: "CUDA_ERROR_PROFILER_ALREADY_STARTED",
    8: "CUDA_ERROR_PROFILER_ALREADY_STOPPED",
    34: "CUDA_ERROR_STUB_LIBRARY",

    # ---- Device Errors ----
    100: "CUDA_ERROR_NO_DEVICE",
    101: "CUDA_ERROR_INVALID_DEVICE",
    102: "CUDA_ERROR_DEVICE_NOT_LICENSED",

    # ---- Context / Module / Memory Mapping Errors ----
    200: "CUDA_ERROR_INVALID_IMAGE",
    201: "CUDA_ERROR_INVALID_CONTEXT",
    202: "CUDA_ERROR_CONTEXT_ALREADY_CURRENT",
    205: "CUDA_ERROR_MAP_FAILED",
    206: "CUDA_ERROR_UNMAP_FAILED",
    207: "CUDA_ERROR_ARRAY_IS_MAPPED",
    208: "CUDA_ERROR_ALREADY_MAPPED",
    209: "CUDA_ERROR_NO_BINARY_FOR_GPU",
    210: "CUDA_ERROR_ALREADY_ACQUIRED",
    211: "CUDA_ERROR_NOT_MAPPED",
    212: "CUDA_ERROR_NOT_MAPPED_AS_ARRAY",
    213: "CUDA_ERROR_NOT_MAPPED_AS_POINTER",
    214: "CUDA_ERROR_ECC_UNCORRECTABLE",
    215: "CUDA_ERROR_UNSUPPORTED_LIMIT",
    216: "CUDA_ERROR_CONTEXT_ALREADY_IN_USE",
    217: "CUDA_ERROR_PEER_ACCESS_UNSUPPORTED",
    218: "CUDA_ERROR_INVALID_PTX",
    219: "CUDA_ERROR_INVALID_GRAPHICS_CONTEXT",
    220: "CUDA_ERROR_NVLINK_UNCORRECTABLE",
    221: "CUDA_ERROR_JIT_COMPILER_NOT_FOUND",
    222: "CUDA_ERROR_UNSUPPORTED_PTX_VERSION",
    223: "CUDA_ERROR_JIT_COMPILATION_DISABLED",

    # ---- Source Errors ----
    300: "CUDA_ERROR_INVALID_SOURCE",

    # ---- File / Shared Object Errors ----
    400: "CUDA_ERROR_FILE_NOT_FOUND",
    401: "CUDA_ERROR_SHARED_OBJECT_SYMBOL_NOT_FOUND",
    402: "CUDA_ERROR_SHARED_OBJECT_INIT_FAILED",

    # ---- OS Error ----
    500: "CUDA_ERROR_OPERATING_SYSTEM",

    # ---- Handle Error ----
    600: "CUDA_ERROR_INVALID_HANDLE",

    # ---- Kernel / Launch Errors ----
    700: "CUDA_ERROR_ILLEGAL_ADDRESS",
    701: "CUDA_ERROR_LAUNCH_OUT_OF_RESOURCES",
    702: "CUDA_ERROR_LAUNCH_TIMEOUT",
    703: "CUDA_ERROR_LAUNCH_INCOMPATIBLE_TEXTURE",
    704: "CUDA_ERROR_PEER_ACCESS_ALREADY_ENABLED",
    705: "CUDA_ERROR_PEER_ACCESS_NOT_ENABLED",
    708: "CUDA_ERROR_PRIMARY_CONTEXT_ACTIVE",
    709: "CUDA_ERROR_CONTEXT_IS_DESTROYED",
    710: "CUDA_ERROR_ASSERT",
    711: "CUDA_ERROR_TOO_MANY_PEERS",
    712: "CUDA_ERROR_HOST_MEMORY_ALREADY_REGISTERED",
    713: "CUDA_ERROR_HOST_MEMORY_NOT_REGISTERED",
    714: "CUDA_ERROR_HARDWARE_STACK_ERROR",
    715: "CUDA_ERROR_ILLEGAL_INSTRUCTION",
    716: "CUDA_ERROR_MISALIGNED_ADDRESS",
    717: "CUDA_ERROR_INVALID_ADDRESS_SPACE",
    718: "CUDA_ERROR_INVALID_PC",
    719: "CUDA_ERROR_LAUNCH_FAILED",
    720: "CUDA_ERROR_COOPERATIVE_LAUNCH_TOO_LARGE",

    # ---- Not Permitted / Not Supported ----
    800: "CUDA_ERROR_NOT_PERMITTED",
    801: "CUDA_ERROR_NOT_SUPPORTED",
    802: "CUDA_ERROR_SYSTEM_NOT_READY",
    803: "CUDA_ERROR_SYSTEM_DRIVER_MISMATCH",
    804: "CUDA_ERROR_COMPAT_NOT_SUPPORTED_ON_DEVICE",
    805: "CUDA_ERROR_MPS_CONNECTION_FAILED",
    806: "CUDA_ERROR_MPS_RPC_FAILURE",
    807: "CUDA_ERROR_MPS_SERVER_NOT_READY",
    808: "CUDA_ERROR_MPS_MAX_CLIENTS_REACHED",
    809: "CUDA_ERROR_MPS_MAX_CONNECTIONS_REACHED",
    810: "CUDA_ERROR_MPS_CLIENT_TERMINATED",

    # ---- CUDA Graph / Stream Capture Errors ----
    900: "CUDA_ERROR_STREAM_CAPTURE_UNSUPPORTED",
    901: "CUDA_ERROR_STREAM_CAPTURE_INVALIDATED",
    902: "CUDA_ERROR_STREAM_CAPTURE_MERGE",
    903: "CUDA_ERROR_STREAM_CAPTURE_UNMATCHED",
    904: "CUDA_ERROR_STREAM_CAPTURE_UNJOINED",
    905: "CUDA_ERROR_STREAM_CAPTURE_ISOLATION",
    906: "CUDA_ERROR_STREAM_CAPTURE_IMPLICIT",
    907: "CUDA_ERROR_CAPTURED_EVENT",
    908: "CUDA_ERROR_STREAM_CAPTURE_WRONG_THREAD",
    909: "CUDA_ERROR_TIMEOUT",
    910: "CUDA_ERROR_GRAPH_EXEC_UPDATE_FAILURE",

    # ---- External Device ----
    1000: "CUDA_ERROR_EXTERNAL_DEVICE",

    # ---- Unknown ----
    999: "CUDA_ERROR_UNKNOWN",
}

# CUDA 漏洞常见 CWE 分类
CUDA_VULN_CWE_MAP: Dict[str, str] = {
    "CWE-190": "Integer Overflow / Wraparound — CUDA 中最常见的漏洞类型，在计算 buffer 大小、索引偏移时未检查整数溢出",
    "CWE-122": "Heap-based Buffer Overflow — GPU 全局内存 / 主机端堆的越界写入",
    "CWE-416": "Use After Free — CUDA 内存释放后继续使用 (cuMemFree 后访问)",
    "CWE-476": "NULL Pointer Dereference — 未检查 CUDA API 返回值导致空指针解引用",
    "CWE-125": "Out-of-bounds Read — GPU 共享内存 / 全局内存越界读取",
    "CWE-362": "Race Condition — CUDA Stream/Event 竞争条件，多线程并发操作 CUDA 资源",
    "CWE-787": "Out-of-bounds Write — kernel 内数组越界写，破坏 GPU 内存布局",
    "CWE-134": "Format String — CUDA printf 格式化字符串漏洞",
    "CWE-78":  "OS Command Injection — CUDA 工具链命令注入",
    "CWE-22":  "Path Traversal — CUDA 工具文件路径遍历",
    "CWE-457": "Uninitialized Variable — GPU 内存分配后未初始化即使用",
}


class CudaLibrary:
    """CUDA 领域辅助函数库。

    提供所有 CUDA PoC 开发中常用的函数签名和领域知识，
    供 LLM 代码生成器在提示中引用。

    Attributes:
        domain: 固定为 "cuda"。
    """

    domain: str = "cuda"

    def get_signatures_text(self) -> str:
        """获取所有 CUDA 辅助函数的签名文本。

        Returns:
            格式化的函数签名文本，供插入 LLM 提示。
        """
        header = "# CUDA Domain Helper Functions — 优先使用这些函数而非硬编码 CUDA API\n"
        header += "# 若 PoC 需要其他 CUDA API，可使用 ctypes/pycuda 直接调用\n\n"
        return header + "\n".join(CUDA_HELPER_SIGNATURES)

    def get_error_codes_text(self) -> str:
        """获取 CUDA 错误码参考文本。"""
        lines = ["# CUDA Error Code Reference\n"]
        for code, name in CUDA_ERROR_CODES.items():
            lines.append(f"#   {code}: {name}")
        return "\n".join(lines)

    def get_cwe_map_text(self) -> str:
        """获取 CUDA 漏洞 CWE 分类参考文本。"""
        lines = ["# CUDA Vulnerability CWE Classification\n"]
        for cwe, desc in CUDA_VULN_CWE_MAP.items():
            lines.append(f"#   {cwe}: {desc}")
        return "\n".join(lines)

    def get_cuda_attack_surface_text(self) -> str:
        """获取 CUDA 攻击面概述文本。"""
        return """# CUDA Attack Surface Overview
#
# 1. CUDA Driver API (cu* functions)
#    - cuMemAlloc/cuMemFree: 内存分配/释放逻辑漏洞
#    - cuLaunchKernel: kernel 参数验证缺陷
#    - cuModuleLoad: cubin/PTX 解析漏洞
#    - cuCtxCreate/cuCtxDestroy: 上下文管理竞争条件
#
# 2. CUDA Runtime API (cuda* functions)
#    - cudaMalloc/cudaFree: 内存管理漏洞
#    - cudaMemcpy: 越界拷贝
#    - cudaLaunchKernel: 参数注入
#
# 3. CUDA Toolchain
#    - nvcc: 编译过程中的注入/解析漏洞
#    - cuobjdump: ELF 解析漏洞 (如 CVE-2025-23247)
#    - nvdisasm: 反汇编输入验证缺陷
#    - ptxas: PTX 汇编器漏洞
#
# 4. CUDA Libraries
#    - cuBLAS: 矩阵参数导致的缓冲区溢出
#    - cuDNN: 张量维度验证缺陷
#    - cuFFT: 变换大小导致的溢出
#
# 5. GPU Virtualization / MPS / MIG
#    - GPU 直通逃逸
#    - MPS 服务权限提升
#    - MIG 实例隔离绕过
"""

# =========================================================================
# ELF64 安全操作参考模式（已验证可工作于 CUDA 11.2 cubin，Windows 环境）
# =========================================================================
# 这些模式是经过实战验证的，LLM 生成的 PoC 应优先使用这些模式而非
# 从头构建 ELF 结构。每个模式都包含完整的错误处理。
# =========================================================================

# === 模式 1：ELF64 节头常量（与 NVIDIA cubin 兼容）===
# e_shentsize = 64（标准 ELF64），格式码 <IIQQQQIIQQ = 64 字节
# 字段索引: 0=sh_name, 1=sh_type, 2=sh_flags, 3=sh_addr,
#           4=sh_offset, 5=sh_size, 6=sh_link, 7=sh_info,
#           8=sh_addralign, 9=sh_entsize
ELF64_REFERENCE_SHDR_FMT = "<IIQQQQIIQQ"

# === 模式 2：按名称定位并替换 section 内容（已验证）===
"""
def replace_section_content(cubin_path: str, section_name: str, new_data: bytes, output_path: str) -> None:
    \"\"\"Replace the content of a section by name. Does NOT add new section headers.\"\"\"
    with open(cubin_path, 'rb') as f:
        data = f.read()

    # 1. Parse ELF header
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]

    # 2. Read .shstrtab to resolve section names
    shdr_raw = data[e_shoff + e_shstrndx * e_shentsize:
                    e_shoff + e_shstrndx * e_shentsize + e_shentsize]
    vals = struct.unpack(ELF64_REFERENCE_SHDR_FMT, shdr_raw)
    strtab_data = data[vals[4]:vals[4] + vals[5]]
    names = strtab_data.split(b'\\x00')

    # 3. Find target section by name
    target_idx = None
    for i in range(e_shnum):
        shdr = data[e_shoff + i * e_shentsize:
                    e_shoff + i * e_shentsize + e_shentsize]
        svals = struct.unpack(ELF64_REFERENCE_SHDR_FMT, shdr)
        name_end = strtab_data.find(b'\\x00', svals[0])
        if name_end > svals[0] and strtab_data[svals[0]:name_end].decode('ascii', errors='ignore') == section_name:
            target_idx = i
            break

    if target_idx is None:
        raise ValueError(f"Section '{section_name}' not found")

    # 4. Append new data at end of file
    working = bytearray(data)
    new_offset = len(working)
    working.extend(new_data)

    # 5. Update section header: sh_offset (idx 4) and sh_size (idx 5)
    hdr_pos = e_shoff + target_idx * e_shentsize
    struct.pack_into('<Q', working, hdr_pos + 24, new_offset)   # sh_offset
    struct.pack_into('<Q', working, hdr_pos + 32, len(new_data))  # sh_size

    with open(output_path, 'wb') as f:
        f.write(working)
"""

# === 模式 3：ELF 文件有效性自检（在调用 cuobjdump 前使用）===
"""
def validate_elf_structure(cubin_path: str) -> list:
    \"\"\"Validate ELF structure and return list of issues (empty = valid).\"\"\"
    issues = []
    with open(cubin_path, 'rb') as f:
        data = f.read()

    if len(data) < 64:
        return ['File too small for ELF64 header']

    if data[:4] != b'\\x7fELF':
        return ['Not an ELF file']

    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]

    if e_shentsize != 64:
        issues.append(f'Unexpected e_shentsize={e_shentsize} (expected 64)')

    if e_shoff + e_shnum * e_shentsize > len(data):
        issues.append('Section header table extends beyond file')

    for i in range(min(e_shnum, 50)):
        off = e_shoff + i * e_shentsize
        if off + e_shentsize > len(data):
            issues.append(f'Section {i} header truncated')
            continue
        raw = data[off:off + e_shentsize]
        vals = struct.unpack(ELF64_REFERENCE_SHDR_FMT, raw)
        if vals[4] + vals[5] > len(data):
            issues.append(f'Section {i}: sh_offset({vals[4]}) + sh_size({vals[5]}) exceeds file')

    return issues
"""

# === 模式 4：cubin 编译时的 MSVC 环境准备（Windows 专用）===
"""
def setup_msvc_env(msvc_version: str = "") -> bool:
    \"\"\"Set up MSVC environment variables for nvcc. Returns True if successful.\"\"\"
    import subprocess, os

    # Find vcvarsall.bat via vswhere
    vswhere = os.path.join(
        os.environ.get('ProgramFiles(x86)', 'C:\\\\Program Files (x86)'),
        'Microsoft Visual Studio', 'Installer', 'vswhere.exe'
    )
    vs_root = ""
    if os.path.isfile(vswhere):
        try:
            vs_root = subprocess.check_output(
                [vswhere, '-latest', '-property', 'installationPath'],
                text=True, timeout=10
            ).strip()
        except Exception:
            pass

    if not vs_root:
        return False

    vcvars = os.path.join(vs_root, 'VC', 'Auxiliary', 'Build', 'vcvarsall.bat')
    if not os.path.isfile(vcvars):
        return False

    # Capture env vars from vcvarsall.bat
    ver_arg = f' -vcvars_ver={msvc_version}' if msvc_version else ''
    result = subprocess.run(
        f'cmd /c ""{vcvars}" x64{ver_arg} >nul && set"',
        capture_output=True, text=True, timeout=30, shell=True
    )
    for line in result.stdout.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            os.environ[k] = v
    return True
"""

# === 模式 5：读取 cubin 中的 section 数据（调试用）===
"""
def read_section_data(cubin_path: str, section_name: str) -> bytes:
    \"\"\"Read raw content of a section by name.\"\"\"
    with open(cubin_path, 'rb') as f:
        data = f.read()

    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]

    # Read shstrtab
    shdr = data[e_shoff + e_shstrndx * e_shentsize:
                e_shoff + e_shstrndx * e_shentsize + e_shentsize]
    svals = struct.unpack(ELF64_REFERENCE_SHDR_FMT, shdr)
    strtab = data[svals[4]:svals[4] + svals[5]]

    for i in range(e_shnum):
        shdr = data[e_shoff + i * e_shentsize:
                    e_shoff + i * e_shentsize + e_shentsize]
        svals = struct.unpack(ELF64_REFERENCE_SHDR_FMT, shdr)
        name_end = strtab.find(b'\\x00', svals[0])
        if name_end > svals[0]:
            name = strtab[svals[0]:name_end].decode('ascii', errors='ignore')
            if name == section_name:
                return data[svals[4]:svals[4] + svals[5]]
    raise ValueError(f"Section '{section_name}' not found")
"""
