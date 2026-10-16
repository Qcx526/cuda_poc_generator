"""Fixed read-only Windows→WSL host diagnostic capability probe and archive.

Only four registered tools' ``--version`` commands are available. Installed
tools are never labelled validated memory diagnostics or an isolated sandbox.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid

from .models.host_diagnostics import (DiagnosticTarget, DiagnosticToolCapability,
                                      HostDiagnosticsProbe)
from .models.lifecycle import canonical_sha256
from .probe_artifacts import protect_directory
from .tools.process import measure_tool_identity, run_tool
from .wsl_bridge import validate_wsl_options


def _json(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate diagnostic JSON key")
            value[key] = item
        return value
    def constant(_):
        raise ValueError("non-finite diagnostic JSON value")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def build_diagnostic_worker_source(*, probe_id, nonce, backend, environment_label):
    """Bundle fixed local code with labels only; no arbitrary command fields."""
    if not re.fullmatch(r"[0-9a-f]{32}", probe_id) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("diagnostic identities must be 32 lowercase hexadecimal characters")
    if backend not in {"local", "wsl"}:
        raise ValueError("unsupported diagnostic backend")
    source = Path(__file__).with_name("host_diagnostics_worker.py").read_bytes()
    checksum = hashlib.sha256(source).hexdigest()
    request = {"schema_version": "1.0", "probe_id": probe_id, "nonce": nonce,
               "backend": backend, "environment_label": environment_label,
               "worker_source_sha256": checksum}
    payload = ("PROBE_REQUEST = " + repr(request) + "\n").encode("utf-8") + source
    return payload, checksum


def _version(tool_id, process, identity, after):
    if process is None or not process.ok or process.truncated or process.capture_failed or identity != after:
        return None
    text = (process.stdout_bytes() + b"\n" + process.stderr_bytes()).decode("utf-8", errors="strict")
    patterns = {"valgrind": r"(?m)^valgrind-([0-9]+(?:\.[0-9]+){1,3})\s*$",
                "gdb": r"(?m)^GNU gdb[^\n]*?\b([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*$",
                "cuobjdump": r"(?m)\bV([0-9]+\.[0-9]+\.[0-9]+)\b",
                "nvdisasm": r"(?m)\bV([0-9]+\.[0-9]+\.[0-9]+)\b"}
    versions = set(re.findall(patterns[tool_id], text))
    return next(iter(versions)) if len(versions) == 1 else None


def parse_diagnostic_packet(raw, *, probe_id, nonce, backend, environment_label, worker_source_sha256):
    """Reject stale, foreign or malformed responses before capability projection."""
    if len(raw) > 1048576:
        raise ValueError("diagnostic packet exceeds bound")
    value = _strict_json(raw)
    fields = {"schema_version", "probe_id", "nonce", "worker_source_sha256", "target", "tools"}
    if not isinstance(value, dict) or set(value) != fields or value["schema_version"] != "1.0":
        raise ValueError("unsupported diagnostic worker envelope")
    for key, expected in (("probe_id", probe_id), ("nonce", nonce), ("worker_source_sha256", worker_source_sha256)):
        if value[key] != expected:
            raise ValueError("diagnostic response identity mismatch")
    target = DiagnosticTarget.model_validate(value["target"])
    if backend == "wsl" and (target.platform_type != "wsl" or target.environment_label != environment_label):
        raise ValueError("diagnostic target environment mismatch")
    if not isinstance(value["tools"], list) or len(value["tools"]) != 4:
        raise ValueError("fixed diagnostic registry mismatch")
    tools = []
    for entry in value["tools"]:
        if not isinstance(entry, dict) or set(entry) != {"tool_id", "identity", "identity_after", "process"}:
            raise ValueError("diagnostic tool entry mismatch")
        initial = DiagnosticToolCapability.model_validate({**entry, "version": None, "version_status": "UNKNOWN"})
        try:
            version = _version(initial.tool_id, initial.process, initial.identity, initial.identity_after)
        except UnicodeError:
            version = None
        tools.append(DiagnosticToolCapability.model_validate({**entry, "version": version,
                                                             "version_status": "OBSERVED" if version else "UNKNOWN"}))
    if {tool.tool_id for tool in tools} != {"valgrind", "gdb", "cuobjdump", "nvdisasm"}:
        raise ValueError("duplicated or foreign diagnostic tool role")
    for tool in tools:
        if tool.process and (tool.process.target_environment != target.environment_label or tool.process.platform_type != target.platform_type):
            raise ValueError("diagnostic tool record target mismatch")
    return target, tools


def _capabilities():
    def fact(status, reason, value=None, sources=()):
        return {"status": status, "value": value, "reason_zh": reason, "sources": list(sources)}
    return {
        "valgrind_xml": fact("DOCUMENTED", "官方文档描述 Memcheck XML 输出；本轮未运行诊断目标，协议版本与诊断效果尚未实测。",
                             "Memcheck XML（仅文档能力）", ["https://valgrind.org/docs/manual/manual-core.html"]),
        "diagnostic_effectiveness": fact("NOT_CHECKED", "仅执行固定版本查询；未测试 Valgrind/GDB 对当前宿主工具的诊断适配。"),
        "target_source": fact("UNKNOWN", "未取得目标程序源码，不能假定可生成 ASan/UBSan 插桩构建。"),
        "target_debug_symbols": fact("UNKNOWN", "本轮未检查或取得目标程序调试符号；未知函数不能编造名称或根因身份。"),
        "trusted_affected_binary": fact("UNKNOWN", "版本字符串与文件哈希不等于受影响构建来源和根因已得到确认。"),
        "trusted_fixed_binary": fact("UNKNOWN", "未取得独立验证来源和身份的修复构建；没有实施修复前后差分。"),
        "cve_experiment_isolation": fact("UNSUPPORTED", "当前桥接只允许只读查询，未建立真实 CVE 所需的独立隔离、网络和文件访问策略。"),
        "cpu_memory_limits": fact("NOT_CHECKED", "版本查询仅实施超时、输出总量限制和 Linux 进程组终止；没有实施 CPU/地址空间或 GPU VRAM 配额。"),
        "experiment_readiness": fact("UNSUPPORTED", "未具备真实 CVE 实验准入：隔离、可信版本对照、目标输入审核和专项根因验证仍缺失。"),
    }


def render_diagnostics_report(record):
    """Render only immutable structured observations; never translate raw logs."""
    record = HostDiagnosticsProbe.model_validate(record.model_dump(mode="python"))
    def cell(value):
        return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    lines = ["# 主机侧诊断能力只读探测报告", "", "报告语言：zh-CN；报告版本：1.0。", "",
             "本报告是 READ_ONLY_CAPABILITY 真实版本查询记录，不是 CVE 实验或诊断效果证明。",
             "候选执行：NOT_EXECUTED；漏洞验证：NOT_VERIFIED。", "",
             "- 探测编号：`" + record.probe_id + "`",
             "- 结构化记录 SHA-256：`" + record.record_sha256 + "`",
             "- 采集时间：" + record.observed_at,
             "- 探测状态：" + record.status,
             "- 请求目标：" + cell(record.requested_environment), "", "## 实测目标身份", ""]
    if record.target:
        lines += ["- 目标环境：" + cell(record.target.environment_label),
                  "- 内核：" + cell(record.target.kernel), "- CPU 架构：" + cell(record.target.architecture),
                  "- 诊断环境内容身份：`" + record.target.diagnostic_environment_id + "`",
                  "该身份属于诊断探测，不能替代 PlatformSnapshot 身份或硬件可信证明。"]
    else:
        lines += ["UNKNOWN：未取得通过校验的目标响应，不能报告远端能力或进程已回收。"]
    lines += ["", "## 固定工具版本查询", "", "| 工具 | 身份 | 实测版本 | 进程状态 | 文件 SHA-256 | 诊断效果 |",
              "| --- | --- | --- | --- | --- | --- |"]
    for tool in record.tools:
        lines.append("| " + " | ".join(cell(value) for value in [tool.tool_id, tool.identity.status,
            tool.version or "UNKNOWN", tool.process.end_status if tool.process else "NOT_CHECKED",
            tool.identity.file_sha256 or "UNKNOWN", tool.diagnostic_effectiveness]) + " |")
    lines += ["", "已安装或 --version 正常退出，不表示可检测指定漏洞；缺失工具不自动安装。", "",
              "## 能力与阻断条件", "", "| 能力 | 状态 | 具体说明 |", "| --- | --- | --- |"]
    for name, item in sorted(record.capabilities.items()):
        lines.append("| " + cell(name) + " | " + item.status + " | " + cell(item.reason_zh) + " |")
    lines += ["", "## 原始证据与限制", "", "原始 stdout/stderr 保持原始字节，独立 .bin 文件、结构化 ToolResult 与清单 SHA-256 可离线相互核对。",
              "只允许固定工具的 --version；没有执行目标输入、畸形 ELF、生成 PoC 或 GPU kernel。",
              "没有实施真实诊断、根因关联或修复差分，因此不能证明任何指定 CVE。",
              "Windows launcher 结束不能证明远端后代已回收；本只读协议不作为漏洞进程生命周期管理器。",
              "历史报告、历史 PlatformSnapshot 和历史证据均未改写。", ""]
    lines += ["- " + cell(message) for message in record.diagnostics_zh]
    return "\n".join(lines) + "\n"


def _write_archive(root, record, worker_source):
    folder = Path(root) / record.probe_id
    protection = protect_directory(folder)
    files = {"diagnostic_probe.json": _json(record.model_dump(mode="json")),
             "report.zh-CN.md": render_diagnostics_report(record).encode("utf-8"),
             "worker_source.py": worker_source}
    if record.launcher:
        for name in ("stdout", "stderr"):
            files["launcher_" + name + ".bin"] = getattr(record.launcher, name + "_bytes")()
    for tool in record.tools:
        if tool.process:
            for name in ("stdout", "stderr"):
                files[tool.tool_id + "_" + name + ".bin"] = getattr(tool.process, name + "_bytes")()
    manifest = {"schema_version": "1.0", "probe_id": record.probe_id, "record_sha256": record.record_sha256,
                "report_locale": "zh-CN", "domain": "READ_ONLY_CAPABILITY", "access_control": protection,
                "files": {name: {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in files.items()},
                "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    files["artifact_manifest.json"] = _json(manifest)
    for name, raw in files.items():
        with (folder / name).open("xb") as stream:
            stream.write(raw)
        if os.name != "nt":
            (folder / name).chmod(0o600)
    read_host_diagnostics_archive(folder)
    return folder


def read_host_diagnostics_archive(folder):
    """Verify all original bytes and regenerate the Chinese report offline."""
    folder = Path(folder)
    if folder.is_symlink():
        raise ValueError("diagnostic archive cannot be a symlink")
    manifest_path = folder / "artifact_manifest.json"
    if manifest_path.is_symlink() or manifest_path.stat().st_size > 65536:
        raise ValueError("invalid diagnostic manifest")
    manifest = _strict_json(manifest_path.read_bytes())
    if set(manifest) != {"schema_version", "probe_id", "record_sha256", "report_locale", "domain", "access_control", "files", "candidate_execution_status", "verification_status"}:
        raise ValueError("unsupported diagnostic archive manifest")
    if (manifest["schema_version"] != "1.0" or manifest["report_locale"] != "zh-CN"
            or manifest["domain"] != "READ_ONLY_CAPABILITY" or manifest["candidate_execution_status"] != "NOT_EXECUTED"
            or manifest["verification_status"] != "NOT_VERIFIED"):
        raise ValueError("diagnostic archive scope mismatch")
    if not isinstance(manifest["access_control"], dict) or manifest["access_control"].get("status") != "APPLIED":
        raise ValueError("diagnostic archive file protection was not recorded as applied")
    if not isinstance(manifest["files"], dict):
        raise ValueError("diagnostic archive requires a fixed file index")
    contents = {}
    for name, identity in manifest["files"].items():
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in {".", ".."}:
            raise ValueError("unsafe diagnostic artifact name")
        if not isinstance(identity, dict) or set(identity) != {"size_bytes", "sha256"}:
            raise ValueError("invalid diagnostic artifact identity")
        file = folder / name
        if file.is_symlink() or type(identity["size_bytes"]) is not int or not 0 <= identity["size_bytes"] <= 4194304:
            raise ValueError("unsafe diagnostic artifact")
        with file.open("rb") as stream:
            raw = stream.read(identity["size_bytes"] + 1)
        if len(raw) != identity["size_bytes"] or hashlib.sha256(raw).hexdigest() != identity["sha256"]:
            raise ValueError("diagnostic artifact size/hash mismatch")
        contents[name] = raw
    record = HostDiagnosticsProbe.model_validate(_strict_json(contents["diagnostic_probe.json"]))
    if record.probe_id != manifest["probe_id"] or record.record_sha256 != manifest["record_sha256"]:
        raise ValueError("diagnostic archive run identity mismatch")
    expected = {"diagnostic_probe.json", "report.zh-CN.md", "worker_source.py"}
    if record.launcher:
        for name in ("stdout", "stderr"):
            filename = "launcher_" + name + ".bin"
            expected.add(filename)
            if contents.get(filename) != getattr(record.launcher, name + "_bytes")():
                raise ValueError("launcher raw bytes mismatch")
        if record.worker_packet_sha256 is not None:
            packet = contents["launcher_stdout.bin"]
            if hashlib.sha256(packet).hexdigest() != record.worker_packet_sha256:
                raise ValueError("worker packet digest mismatch")
            target, tools = parse_diagnostic_packet(packet, probe_id=record.probe_id, nonce=record.nonce,
                backend=record.backend, environment_label=record.requested_environment,
                worker_source_sha256=record.worker_source_sha256)
            if target != record.target or tools != record.tools:
                raise ValueError("stored diagnostic observations differ from original worker bytes")
    for tool in record.tools:
        if tool.process:
            for name in ("stdout", "stderr"):
                filename = tool.tool_id + "_" + name + ".bin"
                expected.add(filename)
                if contents.get(filename) != getattr(tool.process, name + "_bytes")():
                    raise ValueError("diagnostic tool raw bytes mismatch")
    if set(contents) != expected or contents["report.zh-CN.md"] != render_diagnostics_report(record).encode("utf-8"):
        raise ValueError("diagnostic archive/report artifact set mismatch")
    # The shipped worker contains the request prefix; verify the unmodified code
    # suffix independently of its archive file digest.
    _, separator, code = contents["worker_source.py"].partition(b"\n")
    if not separator or hashlib.sha256(code).hexdigest() != record.worker_source_sha256:
        raise ValueError("fixed diagnostic worker source mismatch")
    if record.launcher and (record.launcher.stdin_sha256 != hashlib.sha256(contents["worker_source.py"]).hexdigest()
                            or record.launcher.stdin_size_bytes != len(contents["worker_source.py"])):
        raise ValueError("diagnostic launcher did not receive the archived fixed worker bytes")
    return record


def run_host_diagnostics_probe(*, backend="wsl", distro="Ubuntu-22.04", user="pocdev",
                               linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python", output_root=None):
    if backend not in {"local", "wsl"}:
        raise ValueError("only local Linux and explicit WSL diagnostic probing are supported")
    if backend == "local" and sys.platform != "linux":
        raise ValueError("native Windows diagnostics are unsupported; select backend=wsl")
    if backend == "wsl":
        validate_wsl_options(distro, linux_python, user)
        if os.name != "nt":
            raise ValueError("the WSL backend must be launched from Windows Python")
    probe_id, nonce = uuid.uuid4().hex, uuid.uuid4().hex
    environment = "wsl:" + distro if backend == "wsl" else "local"
    source, source_sha = build_diagnostic_worker_source(probe_id=probe_id, nonce=nonce,
                                                        backend=backend, environment_label=environment)
    root = (Path(output_root) if output_root else (Path(__file__).resolve().parent.parent / "data" / "outputs" / "diagnostic_probes"
            if os.name == "nt" else Path.home() / ".local" / "state" / "cuda-poc-generator" / "diagnostic_probes"))
    executable = shutil.which("wsl.exe") if backend == "wsl" else sys.executable
    launcher, target, tools = None, None, []
    packet_sha, diagnostics = None, []
    if executable is not None:
        identity = measure_tool_identity(executable)
        argv = ([executable, "--distribution", distro, "--user", user, "--exec", linux_python, "-I", "-"]
                if backend == "wsl" else [executable, "-I", "-"])
        allow = {identity.resolved_path: identity.file_sha256} if identity.status == "OBSERVED" else {}
        launcher = run_tool(argv, timeout_seconds=20.0, max_output_bytes=1048576,
                            input_bytes=source, command_source="fixed P3-B read-only diagnostic worker v1",
                            allowed_tool_identities=allow, artifact_root=root / "_launcher")
        if launcher.ok:
            try:
                raw = launcher.stdout_bytes()
                target, tools = parse_diagnostic_packet(raw, probe_id=probe_id, nonce=nonce, backend=backend,
                    environment_label=environment, worker_source_sha256=source_sha)
                packet_sha = hashlib.sha256(raw).hexdigest()
            except (ValueError, TypeError, KeyError):
                diagnostics.append("远端响应的协议、身份、结构或原始字节校验失败；能力保持 UNKNOWN。")
        else:
            diagnostics.append("启动器未正常完成：" + launcher.end_status + "；不能确认远端能力或回收状态。")
    else:
        diagnostics.append("未发现 Windows wsl.exe；没有启动远端查询。")
    payload = {"probe_schema_version": "1.0", "probe_id": probe_id, "nonce": nonce,
               "report_locale": "zh-CN", "domain": "READ_ONLY_CAPABILITY", "backend": backend,
               "requested_environment": environment, "worker_source_sha256": source_sha,
               "observed_at": datetime.now(timezone.utc).isoformat(),
               "status": "FAILED" if target is None else ("COMPLETE" if all(tool.version_status == "OBSERVED" for tool in tools) else "PARTIAL"),
               "target": target.model_dump(mode="json") if target else None,
               "tools": [tool.model_dump(mode="json") for tool in tools], "capabilities": _capabilities(),
               "launcher": launcher.model_dump(mode="json") if launcher else None,
               "worker_packet_sha256": packet_sha, "diagnostics_zh": diagnostics,
               "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    payload["record_sha256"] = canonical_sha256(payload)
    record = HostDiagnosticsProbe.model_validate(payload)
    folder = _write_archive(root, record, source)
    return {"record": record, "evidence_directory": str(folder)}


def main():
    from .report_locale import configure_utf8_stdio
    configure_utf8_stdio()
    parser = argparse.ArgumentParser(description="只读探测主机侧诊断工具；不运行任何漏洞输入")
    parser.add_argument("--backend", choices=("local", "wsl"), default="wsl")
    parser.add_argument("--distro", default="Ubuntu-22.04")
    parser.add_argument("--wsl-user", default="pocdev")
    parser.add_argument("--linux-python", default="/home/pocdev/.venvs/cuda-poc-generator/bin/python")
    parser.add_argument("--output-root")
    parser.add_argument("--rebuild", help="离线校验并重建指定探测目录的中文报告；不执行命令")
    args = parser.parse_args()
    if args.rebuild:
        record = read_host_diagnostics_archive(args.rebuild)
        sys.stdout.buffer.write(render_diagnostics_report(record).encode("utf-8"))
        return 0
    result = run_host_diagnostics_probe(backend=args.backend, distro=args.distro, user=args.wsl_user,
                                        linux_python=args.linux_python, output_root=args.output_root)
    print(json.dumps({"status": result["record"].status, "probe_id": result["record"].probe_id,
                      "evidence_directory": result["evidence_directory"], "verification_status": "NOT_VERIFIED"}, ensure_ascii=False))
    return 1 if result["record"].status == "FAILED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
