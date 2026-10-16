#!/usr/bin/env python3
# =============================================================================
# CUDA PoC Generator — 程序入口（单次生成版）
# =============================================================================
# 免责声明: 本工具仅供经过合法授权的安全研究与渗透测试使用。
# =============================================================================

"""CUDA PoC Generator 程序入口。

示例:
  python main.py --cve-id CVE-2024-0124
  python main.py --input-dir ./my_data --output-dir ./out
  python main.py --cve-id CVE-2025-23339 --no-rag
"""

import argparse
import os
import sys
from typing import Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from src.utils import setup_logging


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CUDA PoC Generator — 单次生成 CUDA 漏洞 PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", type=str, default=None, help="配置文件路径")
    parser.add_argument("--cve-id", type=str, default=None, help="CVE 编号")
    parser.add_argument("--input-dir", type=str, default=None, help="输入目录（与 --cve-id 互斥）")
    parser.add_argument("--output-dir", type=str, default=None, help="输出目录")
    parser.add_argument("--no-rag", action="store_true", default=False, help="禁用 RAG")
    parser.add_argument("--package", action="store_true", default=False,
                        help="为本轮生成产物创建中文 CVE/run 归档和 ZIP，并独立校验；不执行候选")
    parser.add_argument("--target-backend", choices=["local", "wsl"], default=None, help="目标平台：当前宿主或显式 WSL 只读探测")
    parser.add_argument("--wsl-distro", default=None, help="显式 WSL 发行版，例如 Ubuntu-22.04")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG","INFO","WARNING","ERROR"], help="日志级别")
    return parser.parse_args()


def _list_available_cves() -> None:
    inputs_root = os.path.join(_PROJECT_ROOT, "data", "inputs")
    found = []
    if os.path.isdir(inputs_root):
        for d in sorted(os.listdir(inputs_root)):
            if os.path.isdir(os.path.join(inputs_root, d)) and d.startswith("CVE-"):
                found.append(f"    {d}/")
    if found:
        print("  可用的 CVE 数据:")
        for f in found:
            print(f)
    else:
        print("  (未找到 CVE 数据目录)")


def main() -> None:
    args = parse_args()
    setup_logging(level=args.log_level)

    if args.cve_id and args.input_dir:
        print("[ERROR] --cve-id 与 --input-dir 互斥。")
        sys.exit(1)

    input_dir: Optional[str] = None
    if args.cve_id:
        input_dir = os.path.join(_PROJECT_ROOT, "data", "inputs", args.cve_id)
        if not os.path.isdir(input_dir):
            print(f"[ERROR] 输入目录不存在: {input_dir}")
            _list_available_cves()
            sys.exit(1)
    elif args.input_dir:
        input_dir = args.input_dir
        if not os.path.isdir(input_dir):
            print(f"[ERROR] 输入目录不存在: {input_dir}")
            sys.exit(1)
    else:
        print("[ERROR] 请通过 --cve-id 或 --input-dir 指定输入。")
        _list_available_cves()
        sys.exit(1)

    if args.no_rag:
        os.environ["CPG_RAG_ENABLED"] = "false"

    try:
        # CLI help and input checks also work before dependencies are installed.
        from src.pipeline import CudaPipeline
        pipeline = CudaPipeline(config_path=args.config)
        pipeline.archive_artifacts = True
        pipeline.package_artifacts = args.package
        options = {}
        if args.target_backend is not None:
            options["target_backend"] = args.target_backend
        if args.wsl_distro is not None:
            if args.target_backend != "wsl":
                raise ValueError("--wsl-distro 需要显式 --target-backend wsl。")
            options["wsl_distro"] = args.wsl_distro
        pipeline.run(input_dir=input_dir, output_dir=args.output_dir, **options)
        if args.package:
            delivery = pipeline.last_delivery
            if not delivery or delivery.get("package_status") != "INTEGRITY_VERIFIED":
                raise RuntimeError("本轮 ZIP 交付未完整完成，请核对中文失败报告；未使用旧 run 替代。")
            print(f"[交付] 本轮 ZIP：{delivery['package_path']}")
            print(f"[交付] 包外 SHA-256：{delivery['package_sha256']}")
            print("[交付] INTEGRITY_VERIFIED；NOT_EXECUTED / NOT_VERIFIED。")
    except ImportError:
        print('[ERROR] 缺少运行依赖。请在项目 venv 中执行: python -m pip install -e "."')
        sys.exit(1)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
