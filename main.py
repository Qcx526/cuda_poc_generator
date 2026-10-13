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

# 自动加载 .env 文件中的环境变量
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.isfile(_env_path):
        load_dotenv(_env_path)
except ImportError:
    pass

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from src.pipeline import CudaPipeline
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

    pipeline = CudaPipeline(config_path=args.config)
    pipeline.run(input_dir=input_dir, output_dir=args.output_dir)


if __name__ == "__main__":
    main()
