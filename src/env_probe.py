"""
GPU/CUDA 环境探针 — 收集当前宿主的只读平台快照，供代码生成使用。

收集内容:
- GPU 型号和计算能力 (nvidia-smi)
- Driver Release、驱动报告兼容版本（Driver API 当前 NOT_CHECKED）
- CUDA Toolkit 版本和路径
- 实际发现的 nvcc / Compute Sanitizer 路径
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
    """Capture a fresh local read-only snapshot and private evidence record."""
    from .platform_probe import run_platform_probe
    result = run_platform_probe(backend="local")
    if result["snapshot"] is None:
        raise RuntimeError("Local platform probe failed; no current snapshot is available.")
    return result["snapshot"]


def format_for_prompt(env: Dict[str, Any]) -> str:
    """Express observations, unknowns and selected backend without guessed values."""
    if env.get("schema_version") != "1.0":
        # Old external/mock contexts lack provenance; never promote them to observations.
        return "## SELECTED TARGET PLATFORM SNAPSHOT\nLegacy context: NOT_CHECKED. No observed GPU architecture or tool paths. Do not guess."
    from .models.platform import PlatformSnapshot
    snapshot = PlatformSnapshot.model_validate(env).model_dump(mode="json")
    lines = ["## SELECTED TARGET PLATFORM SNAPSHOT", "",
             f"Platform: {snapshot['platform_type']}; backend: {snapshot['execution_backend']}",
             "This is read-only platform observation, not execution or vulnerability evidence."]
    for name, value in snapshot.items():
        if isinstance(value, dict) and "status" in value and "value" in value:
            lines.append(f"- {name}: {value['status']}; value={json.dumps(value['value'], ensure_ascii=False)}; method={value['method']}")
    lines.extend(["", "Use only paths belonging to this selected target. Unknown capabilities remain unknown.",
                  "An inferred sm notation is derived only from observed compute capability, never from a GPU name.",
                  "Do not replace UNKNOWN/FAILED/NOT_CHECKED with a default architecture or historical Toolkit list.",
                  "Driver release, Driver API version, driver-reported compatibility and Toolkit version are distinct.",
                  "Compilation/kernel/PoC execution: NOT_EXECUTED. Vulnerability verification: NOT_VERIFIED."])
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
    """Compatibility projection; unknown device access is never zero or sm_75."""
    snapshot = probe_environment()
    devices = snapshot["gpu_devices"]
    values = devices["value"]
    return {"status": devices["status"], "gpu_count": None if values is None else len(values),
            "gpus": values, "primary_compute_cap": None if not values else values[0]["sm_arch"]["value"]}


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
        "nvcc_smoke_ok": None,
        "nvcc_smoke_status": "NOT_RUN",
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
    # Probe-only entry points must never compile or execute a CUDA kernel.
    return info


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
                     f'ForEach-Object {{ if ($_ -match "^(\\w+)=(.*)") {{ '
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


def _probe_nvcc_archs(nvcc_path: str) -> Optional[List[str]]:
    """Return actually queried nvcc architectures, or None when unavailable."""
    if not nvcc_path:
        return None
    from .probe_process import run_bounded
    import base64
    result = run_bounded([nvcc_path, "--list-gpu-code"], timeout_seconds=3, max_output_bytes=32768)
    if result["status"] != "COMPLETED" or result["returncode"] != 0:
        return None
    found = re.findall(r"\bsm_[0-9]+[a-z]?\b", base64.b64decode(result["stdout_b64"]).decode("utf-8", errors="replace"))
    return sorted(set(found)) or None


def _glob(pattern: str) -> List[str]:
    import glob
    return sorted(glob.glob(pattern))
