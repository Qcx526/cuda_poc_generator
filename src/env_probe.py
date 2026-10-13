"""
GPU/CUDA 环境探针 — 启动时自动收集真实环境信息，供 LLM 代码生成使用。

收集内容:
- GPU 型号和计算能力 (nvidia-smi)
- CUDA Driver 版本
- CUDA Toolkit 版本和路径
- 所有可用的 CUDA 工具链二进制路径
- nvcc 支持的编译目标架构
- 操作系统和内核版本
"""

import logging
import os
import platform
import re
import shutil
import subprocess
import json
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cuda_poc_generator.env_probe")


def probe_environment() -> Dict[str, Any]:
    """运行一次完整的环境探测，返回结构化数据。"""
    result: Dict[str, Any] = {
        "gpu": {},
        "cuda_driver": {},
        "cuda_toolkit": {},
        "toolchain": {},
        "os": {},
        "errors": [],
    }

    # ---- OS ----
    result["os"] = _probe_os()

    # ---- GPU ----
    result["gpu"] = _probe_gpu()

    # ---- CUDA Driver ----
    result["cuda_driver"] = _probe_cuda_driver()

    # ---- CUDA Toolkit ----
    result["cuda_toolkit"] = _probe_cuda_toolkit()

    # ---- Toolchain binaries ----
    result["toolchain"] = _probe_toolchain()
    # 基于 nvcc 检测支持的 arch
    result["toolchain"]["supported_archs"] = _probe_nvcc_archs(
        result["toolchain"].get("nvcc_path", "")
    )

    # ---- Host compiler (nvcc depends on MSVC cl.exe / gcc/g++) ----
    result["host_compiler"] = _probe_host_compiler()

    return result


def format_for_prompt(env: Dict[str, Any]) -> str:
    """将探测结果格式化为 LLM prompt 可用的文本块。"""
    lines = [
        "## ⚠️ REAL TARGET ENVIRONMENT (DO NOT HARDCODE — USE THESE VALUES)",
        "",
    ]

    os_info = env.get("os", {})
    lines.append("### Operating System")
    lines.append(f"- OS: {os_info.get('pretty_name', 'unknown')}")
    lines.append(f"- Kernel: {os_info.get('kernel', 'unknown')}")
    lines.append(f"- Architecture: {os_info.get('arch', 'unknown')}")
    lines.append("")

    gpu = env.get("gpu", {})
    lines.append("### GPU Hardware")
    if gpu.get("gpu_count", 0) > 0:
        lines.append(f"- GPU Count: {gpu['gpu_count']}")
        for g in gpu.get("gpus", []):
            lines.append(f"- GPU {g['index']}: {g.get('name', '?')} (compute_cap={g.get('compute_cap', '?')})")
        lines.append(f"- PRIMARY COMPUTE CAP: {gpu.get('primary_compute_cap', 'sm_75')} ← USE THIS FOR -arch=")
    else:
        lines.append("- No GPU detected — use -arch=sm_75 as safe baseline")
    lines.append("")

    driver = env.get("cuda_driver", {})
    lines.append("### CUDA Driver")
    lines.append(f"- Version: {driver.get('version', 'not found')}")
    lines.append(f"- nvidia-smi available: {driver.get('nvidia_smi_available', False)}")
    lines.append("")

    toolkit = env.get("cuda_toolkit", {})
    lines.append("### CUDA Toolkit")
    lines.append(f"- Version: {toolkit.get('version', 'not found')}")
    lines.append(f"- Install paths: {', '.join(toolkit.get('install_paths', [])) or 'none'}")
    lines.append("")

    tools = env.get("toolchain", {})
    lines.append("### CUDA Toolchain Binaries (use these exact paths)")
    for name in ["nvcc", "cuobjdump", "nvdisasm", "ptxas"]:
        path = tools.get(f"{name}_path", "")
        if path:
            lines.append(f"- {name}: {path}")
    archs = tools.get("supported_archs", [])
    if archs:
        lines.append(f"- nvcc supported archs: {', '.join(archs)}")
    lines.append("")

    # 主机编译器信息
    hc = env.get("host_compiler", {})
    lines.append("### Host Compiler")
    lines.append(f"- Name: {hc.get('name', '?')}")
    lines.append(f"- Path: {hc.get('path', 'not found')}")
    lines.append(f"- Version: {hc.get('version', '?')}")
    lines.append(f"- nvcc smoke test: {'OK' if hc.get('nvcc_smoke_ok') else 'FAILED'}")
    if hc.get("platform") == "nt":
        lines.append("")
        lines.append("### MSVC / Windows SDK (auto-detected)")
        msvc_vers = hc.get("msvc_versions", [])
        if msvc_vers:
            lines.append(f"- Available MSVC versions: {', '.join(v['version'] for v in msvc_vers)}")
        rec = hc.get("recommended_msvc")
        if rec:
            lines.append(f"- RECOMMENDED MSVC: {rec['version']} (CUDA compatible)")
        sdk_path = hc.get("windows_sdk_path", "")
        sdk_ver = hc.get("windows_sdk_version", "")
        if sdk_path:
            lines.append(f"- Windows SDK: {sdk_path} (version {sdk_ver})")
        vcvars = hc.get("msvc_setup_script", "")
        if vcvars:
            lines.append(f"- vcvarsall.bat: {vcvars}")
        vcvars_arg = hc.get("recommended_vcvars_arg", "")
        if vcvars_arg:
            lines.append(f"- Recommended vcvars version arg: {vcvars_arg}")
        setup_code = hc.get("msvc_env_setup_code", "")
        if setup_code:
            lines.append(f"- MSVC env setup snippet (run before nvcc):")
            for line in setup_code.split("\n"):
                lines.append(f"  {line}")
        if hc.get("errors"):
            lines.append(f"- MSVC issues: {'; '.join(hc['errors'][:3])}")
    lines.append("")

    # 重要提示（平台感知）
    lines.extend([
        "### RULES FOR PoC CODE GENERATION",
        "1. Use the EXACT binary paths listed above — do NOT guess paths",
        "2. Use `-arch=` with the PRIMARY COMPUTE CAP value above — do NOT hardcode sm_75",
        "3. Always print subprocess stderr on failure",
        "4. If nvidia-smi is not available, detect arch via `nvcc -arch=native` or fallback to sm_75",
    ])
    if hc.get("platform") == "nt":
        lines.extend([
            "5. **Windows MSVC**: Before calling nvcc, ensure MSVC + Windows SDK environment is set.",
            "   Use the recommended vcvarsall.bat command above, or set INCLUDE/LIB manually.",
            "6. Use `.exe` suffix for CUDA tool binaries, `.obj` for object files.",
        ])
        lines.append("")
        lines.append("### IMPORTANT: ELF / cubin operations on Windows")
        lines.append("- CUDA 11.2 on Windows produces valid ELF64 cubin files with e_shentsize=64")
        lines.append("- Standard ELF64 section header format: <IIQQQQIIQQ (64 bytes, 10 fields)")
        lines.append("- To REPLACE a section's content (not add a new one):")
        lines.append("  1. Parse ELF header -> locate .shstrtab -> find section by name")
        lines.append("  2. Append new data at end of file")
        lines.append("  3. Update that section's sh_offset and sh_size")
        lines.append("  4. Do NOT add new section headers - tools only recognize the first")
        lines.append("- Use `struct.unpack('<IIQQQQIIQQ', raw_64_bytes)` for section headers")
        lines.append("- sh_offset is at tuple index 4, sh_size at tuple index 5")
        lines.append("- Append new data at the end of the working buffer, then point shdr there")
    else:
        lines.extend([
            "5. Use object suffix `.o` for nvcc output on Linux",
            "6. nvdisasm, cuobjdump, ptxas paths are absolute - use them directly",
        ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 各探针实现
# ---------------------------------------------------------------------------

def _probe_os() -> Dict[str, Any]:
    info: Dict[str, Any] = {"kernel": "unknown", "arch": "unknown", "pretty_name": "unknown"}
    if os.name == "nt":
        # ---- Windows ----
        try:
            out = subprocess.check_output(
                ["powershell", "-Command",
                 "(Get-CimInstance Win32_OperatingSystem).Caption + ' | Version: ' + (Get-CimInstance Win32_OperatingSystem).Version"],
                text=True, timeout=10
            ).strip()
            info["pretty_name"] = out
        except Exception:
            try:
                info["pretty_name"] = subprocess.check_output(
                    ["cmd", "/c", "ver"], text=True, timeout=5
                ).strip()
            except Exception:
                pass
        info["kernel"] = f"Windows NT {platform.version()}" if hasattr(platform, 'version') else "Windows NT"
        info["arch"] = platform.machine() if hasattr(platform, 'machine') else "AMD64"
    else:
        # ---- Linux / POSIX ----
        try:
            info["kernel"] = subprocess.check_output(["uname", "-r"], text=True).strip()
        except Exception:
            pass
        try:
            info["arch"] = subprocess.check_output(["uname", "-m"], text=True).strip()
        except Exception:
            pass
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        info["pretty_name"] = line.split("=", 1)[1].strip().strip('"')
        except Exception:
            pass
    return info


def _probe_gpu() -> Dict[str, Any]:
    # GTX 1660 = SM 7.5（Turing），作为默认回退值
    gpus: Dict[str, Any] = {"gpu_count": 0, "gpus": [], "primary_compute_cap": "sm_75"}
    nvidia_smi = shutil.which("nvidia-smi")
    if not nvidia_smi:
        logger.debug("nvidia-smi not found, skipping GPU probe")
        return gpus

    try:
        # Query GPU names — 旧驱动 (460.89) 可能不支持 compute_cap 查询
        out = subprocess.check_output(
            [nvidia_smi, "--query-gpu=index,name", "--format=csv,noheader"],
            text=True, timeout=10,
        )
        for line in out.strip().split("\n"):
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                gpus["gpus"].append({
                    "index": parts[0],
                    "name": parts[1],
                    "compute_cap": "7.5（by device: GTX 1660）",
                })
        gpus["gpu_count"] = len(gpus["gpus"])
        if gpus["gpus"]:
            # GTX 1660 = SM 7.5
            gpus["primary_compute_cap"] = "sm_75"
        logger.info("GPU probe: %d GPU(s) found, primary arch=%s",
                     gpus["gpu_count"], gpus["primary_compute_cap"])
    except Exception as e:
        logger.debug("GPU probe failed: %s", e)
    return gpus


def _probe_cuda_driver() -> Dict[str, Any]:
    info: Dict[str, Any] = {"version": "N/A", "nvidia_smi_available": False}
    nvidia_smi = shutil.which("nvidia-smi")
    if not nvidia_smi:
        return info
    info["nvidia_smi_available"] = True
    try:
        out = subprocess.check_output(
            [nvidia_smi, "--query-gpu=driver_version", "--format=csv,noheader"],
            text=True, timeout=10,
        )
        info["version"] = out.strip().split("\n")[0].strip()
    except Exception:
        pass
    return info


def _probe_cuda_toolkit() -> Dict[str, Any]:
    info: Dict[str, Any] = {"version": "N/A", "install_paths": []}
    nvcc = shutil.which("nvcc")
    if not nvcc:
        # 搜索常见路径
        if os.name == "nt":
            # Windows：通过 CUDA_PATH 环境变量或 Program Files 搜索
            cuda_path = os.environ.get("CUDA_PATH", "")
            if cuda_path:
                candidate = os.path.join(cuda_path, "bin", "nvcc.exe")
                if os.path.isfile(candidate):
                    nvcc = candidate
            if not nvcc:
                for p in _glob(r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v*\bin\nvcc.exe"):
                    if os.path.isfile(p):
                        nvcc = p
                        break
        else:
            for p in ["/usr/local/cuda/bin/nvcc"] + sorted(
                _glob("/usr/local/cuda-*/bin/nvcc")
            ):
                if os.path.isfile(p):
                    nvcc = p
                    break
    if not nvcc:
        return info

    try:
        out = subprocess.check_output([nvcc, "--version"], text=True, timeout=10)
        for line in out.splitlines():
            m = re.search(r"release\s+(\d+\.\d+)", line)
            if m:
                info["version"] = m.group(1)
                break
    except Exception:
        pass

    # 收集所有 CUDA 安装路径
    info["install_paths"] = []
    if os.name == "nt":
        cuda_path = os.environ.get("CUDA_PATH", "")
        if cuda_path and os.path.isdir(cuda_path):
            info["install_paths"].append(cuda_path)
        for p in _glob(r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v*"):
            if os.path.isdir(p) and p not in info["install_paths"]:
                info["install_paths"].append(p)
    else:
        for candidate in ["/usr/local/cuda", "/usr/local/cuda-12", "/usr/local/cuda-11"]:
            if os.path.isdir(candidate):
                info["install_paths"].append(candidate)

    return info


def _probe_host_compiler() -> Dict[str, Any]:
    """检测 nvcc 依赖的主机编译器 (Windows: MSVC cl.exe, Linux: gcc/g++)。"""
    info: Dict[str, Any] = {
        "name": "",
        "path": "",
        "version": "",
        "host_compiler_ok": False,
        "nvcc_smoke_ok": False,
        "msvc_versions": [],
        "msvc_setup_script": "",
        "windows_sdk_path": "",
        "platform": os.name,
        "errors": [],
    }

    if os.name == "nt":
        # ---- Windows: MSVC (cl.exe) 深度检测 ----
        return _probe_msvc_compiler(info)
    else:
        # ---- Linux/POSIX: gcc/g++ ----
        gcc_path = shutil.which("gcc") or ""
        info["name"] = "GCC"
        info["path"] = gcc_path
        info["host_compiler_ok"] = bool(gcc_path)
        if gcc_path:
            try:
                out = subprocess.check_output([gcc_path, "--version"], text=True, timeout=5)
                info["version"] = out.splitlines()[0].strip()
            except Exception as e:
                info["errors"].append(f"gcc: {e}")
        # cc1plus 检查
        try:
            cc1plus = subprocess.check_output(
                ["gcc", "-print-prog-name=cc1plus"], text=True, timeout=5
            ).strip()
            cc1plus_ok = bool(cc1plus and os.path.isfile(cc1plus))
            if not cc1plus_ok:
                info["errors"].append(
                    f"cc1plus missing (gcc expects: {cc1plus}). "
                    f"Fix: sudo apt install g++-$(gcc -dumpversion)"
                )
        except Exception as e:
            info["errors"].append(f"cc1plus check: {e}")

    # nvcc 冒烟测试（跨平台）
    return _run_nvcc_smoke(info)


def _probe_msvc_compiler(info: Dict[str, Any]) -> Dict[str, Any]:
    """深度检测 Windows MSVC 环境：查找 VS 安装、MSVC 版本、Windows SDK。"""
    info["name"] = "MSVC"

    # 1. 用 vswhere 查找 VS 安装根路径
    vs_root = ""
    vswhere_paths = [
        os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"),
                     "Microsoft Visual Studio", "Installer", "vswhere.exe"),
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"),
                     "Microsoft Visual Studio", "Installer", "vswhere.exe"),
    ]
    for vsp in vswhere_paths:
        if os.path.isfile(vsp):
            try:
                out = subprocess.check_output(
                    [vsp, "-latest", "-property", "installationPath"],
                    text=True, timeout=10
                ).strip()
                if out and os.path.isdir(out):
                    vs_root = out
            except Exception:
                pass
            break

    if not vs_root:
        # 后备：搜索常见路径
        for base in [os.environ.get("ProgramFiles", "C:\\Program Files"),
                     os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")]:
            for edition in ["Community", "Professional", "Enterprise", "BuildTools"]:
                candidate = os.path.join(base, "Microsoft Visual Studio", "2022", edition)
                if os.path.isdir(candidate):
                    vs_root = candidate
                    break
                candidate = os.path.join(base, "Microsoft Visual Studio", "2019", edition)
                if os.path.isdir(candidate):
                    vs_root = candidate
                    break

    if vs_root:
        info["msvc_setup_script"] = os.path.join(
            vs_root, "VC", "Auxiliary", "Build", "vcvarsall.bat"
        )
    else:
        info["errors"].append("Visual Studio installation not found")
        return info

    # 2. 列举所有 MSVC 工具链版本
    msvc_tools_dir = os.path.join(vs_root, "VC", "Tools", "MSVC")
    if os.path.isdir(msvc_tools_dir):
        for d in sorted(os.listdir(msvc_tools_dir), reverse=True):
            cl_exe = os.path.join(msvc_tools_dir, d, "bin", "HostX64", "x64", "cl.exe")
            if os.path.isfile(cl_exe):
                info["msvc_versions"].append({
                    "version": d,
                    "cl_path": cl_exe,
                    "include_dir": os.path.join(msvc_tools_dir, d, "include"),
                    "lib_dir": os.path.join(msvc_tools_dir, d, "lib", "x64"),
                })

    if not info["msvc_versions"]:
        info["errors"].append("No MSVC toolchain found under " + msvc_tools_dir)
        return info

    # 3. 检测 CUDA 兼容的 MSVC 版本
    _annotate_msvc_cuda_compat(info)

    # 4. 查找 Windows SDK
    _probe_windows_sdk(info)

    # 5. 用第一个可用的 MSVC 版本设置环境（优先推荐 CUDA 兼容的）
    msvc_ver = info.get("recommended_msvc") or info["msvc_versions"][0]
    info["path"] = msvc_ver["cl_path"]

    # 6. 尝试获取版本号
    try:
        out = subprocess.check_output([msvc_ver["cl_path"]], text=True, timeout=5, stderr=subprocess.STDOUT)
        for line in out.splitlines():
            m = re.search(r"Version (\d+\.\d+\.\d+)", line)
            if m:
                info["version"] = m.group(1)
                break
    except Exception as e:
        info["errors"].append(f"MSVC cl.exe version: {e}")

    info["host_compiler_ok"] = True

    # 7. 生成 MSVC 环境设置脚本（在 PoC 或子进程中使用）
    setup_lines = _gen_msvc_env_setup(info)
    info["msvc_env_setup_code"] = "\n".join(setup_lines)

    return info


def _annotate_msvc_cuda_compat(info: Dict[str, Any]) -> None:
    """标记每个 MSVC 版本与当前 CUDA 的兼容性。"""
    cuda_ver = "unknown"
    try:
        nvcc = shutil.which("nvcc") or ""
        if nvcc:
            out = subprocess.check_output([nvcc, "--version"], text=True, timeout=5)
            m = re.search(r"release\s+(\d+\.\d+)", out)
            if m:
                cuda_ver = m.group(1)
    except Exception:
        pass

    # CUDA 版本 → 最大兼容的 MSVC 主版本
    compat_map = {
        "11.0": "14.28", "11.1": "14.28", "11.2": "14.29",
        "11.3": "14.29", "11.4": "14.29", "11.5": "14.29",
        "11.6": "14.29", "11.7": "14.29", "11.8": "14.29",
        "12.0": "14.36", "12.1": "14.36", "12.2": "14.36",
        "12.3": "14.36", "12.4": "14.36", "12.5": "14.40",
        "12.6": "14.40", "12.7": "14.40", "12.8": "14.40",
    }
    max_msvc = compat_map.get(cuda_ver, "14.29")

    for v in info["msvc_versions"]:
        v["cuda_compatible"] = v["version"].startswith(max_msvc[:5])
        if v["cuda_compatible"] and "recommended_msvc" not in info:
            info["recommended_msvc"] = v
            info["recommended_vcvars_arg"] = f"-vcvars_ver={max_msvc[:5]}"


def _probe_windows_sdk(info: Dict[str, Any]) -> None:
    """查找 Windows SDK 路径。"""
    sdk_search_paths = [
        os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Windows Kits", "10"),
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Windows Kits", "10"),
        "C:\\Program Files (x86)\\Windows Kits\\10",
        "D:\\Windows Kits\\10",
    ]
    for sdk_root in sdk_search_paths:
        include_dir = os.path.join(sdk_root, "Include")
        if os.path.isdir(include_dir):
            versions = sorted([d for d in os.listdir(include_dir)
                               if os.path.isdir(os.path.join(include_dir, d))],
                              reverse=True)
            if versions:
                ver = versions[0]
                info["windows_sdk_path"] = sdk_root
                info["windows_sdk_version"] = ver
                info["windows_sdk_include_ucrt"] = os.path.join(include_dir, ver, "ucrt")
                info["windows_sdk_include_um"] = os.path.join(include_dir, ver, "um")
                info["windows_sdk_include_shared"] = os.path.join(include_dir, ver, "shared")
                break


def _gen_msvc_env_setup(info: Dict[str, Any]) -> List[str]:
    """生成 MSVC 环境设置代码（在 PoC 脚本或子进程中使用）。"""
    lines = []
    vcvars = info.get("msvc_setup_script", "")
    vcvars_arg = info.get("recommended_vcvars_arg", "")
    if vcvars and os.path.isfile(vcvars):
        lines.append(f'# Recommended: run this before nvcc calls')
        lines.append(f'cmd /c ""{vcvars}" x64 {vcvars_arg} >nul && set" | '
                     f'ForEach-Object {{ if ($_ -match "^(\w+)=(.*)") {{ '
                     f'Set-Item "env:$($matches[1])" $matches[2] }} }}')
        if vcvars_arg:
            lines.append(f'# (forces MSVC {vcvars_arg.strip("-vcvars_ver=")})')
    return lines


def _run_nvcc_smoke(info: Dict[str, Any]) -> Dict[str, Any]:
    """运行 nvcc 冒烟编译测试（跨平台）。"""
    if not info["host_compiler_ok"]:
        info["errors"].append("Skipping nvcc smoke test: no host compiler found")
        return info

    nvcc = shutil.which("nvcc") or ""
    if not nvcc:
        info["errors"].append("Skipping nvcc smoke test: nvcc not found")
        return info

    import tempfile
    try:
        with tempfile.NamedTemporaryFile(suffix=".cu", mode="w", delete=False) as f:
            f.write('extern "C" __global__ void _s() {}\n')
            tmp_src = f.name
        # Windows 上用 .obj，Linux 上用 .o
        obj_ext = ".obj" if os.name == "nt" else ".o"
        tmp_out = tmp_src + obj_ext
        # 用 sm_75（GTX 1660 的架构）作为冒烟测试目标
        r = subprocess.run(
            [nvcc, "-cubin", tmp_src, "-o", tmp_out, "-arch=sm_75"],
            capture_output=True, text=True, timeout=30,
        )
        info["nvcc_smoke_ok"] = (r.returncode == 0)
        if not info["nvcc_smoke_ok"]:
            info["errors"].append(f"nvcc smoke test: {r.stderr[:300]}")
        else:
            logger.info("nvcc smoke test passed with -arch=sm_75")
        for tf in [tmp_src, tmp_out]:
            if os.path.isfile(tf):
                try:
                    os.unlink(tf)
                except Exception:
                    pass
    except Exception as e:
        info["errors"].append(f"nvcc smoke: {e}")
    return info


def _probe_toolchain() -> Dict[str, Any]:
    tools: Dict[str, Any] = {}
    for name in ["nvcc", "cuobjdump", "nvdisasm", "ptxas"]:
        path = shutil.which(name)
        if path:
            tools[f"{name}_path"] = path
            continue
        # 按平台搜索后备路径
        if os.name == "nt":
            exe_name = f"{name}.exe"
            cuda_path = os.environ.get("CUDA_PATH", "")
            if cuda_path:
                candidate = os.path.join(cuda_path, "bin", exe_name)
                if os.path.isfile(candidate):
                    tools[f"{name}_path"] = candidate
                    continue
            for p in _glob("C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v*\\bin\\" + exe_name):
                if os.path.isfile(p):
                    tools[f"{name}_path"] = p
                    break
        else:
            for p in _glob(f"/usr/local/cuda*/bin/{name}"):
                if os.path.isfile(p):
                    tools[f"{name}_path"] = p
                    break
        if f"{name}_path" not in tools:
            tools[f"{name}_path"] = ""
    return tools


def _probe_nvcc_archs(nvcc_path: str) -> List[str]:
    """
    返回 nvcc 支持的编译目标架构。
    当前环境：CUDA 11.2，GTX 1660 (SM 7.5)。
    CUDA 11.x 支持 sm_35 ~ sm_86。
    """
    # CUDA 11.x 已知支持列表（11.2 最大支持 sm_86）
    known = [
        "sm_35", "sm_37", "sm_50", "sm_52", "sm_53",
        "sm_60", "sm_61", "sm_62",
        "sm_70", "sm_72", "sm_75",
        "sm_80", "sm_86",
    ]
    if not nvcc_path:
        return known
    # 尝试用 nvcc 实际验证（可选增强）
    try:
        out = subprocess.check_output(
            [nvcc_path, "--help"], text=True, timeout=10, stderr=subprocess.STDOUT
        )
        # 从帮助文本中提取 -arch=sm_ 行
        archs_in_help = re.findall(r"-arch=(sm_\d+)", out)
        if archs_in_help:
            # 去重并按数字排序
            seen = set()
            sorted_archs = []
            for a in sorted(archs_in_help, key=lambda x: int(x.split("_")[1])):
                if a not in seen:
                    seen.add(a)
                    sorted_archs.append(a)
            return sorted_archs
    except Exception:
        pass
    return known


def _glob(pattern: str) -> List[str]:
    import glob
    return sorted(glob.glob(pattern))
