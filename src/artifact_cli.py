"""Windows-friendly offline Chinese CVE research packaging interface."""

import argparse
import json

from .artifact_packaging import import_review_run, package_run, verify_package, rebuild_review_report


def main(argv=None):
    from .report_locale import configure_utf8_stdio
    configure_utf8_stdio()
    parser = argparse.ArgumentParser(description="按 CVE 归档公开资料审查；不执行 PoC，不验证真实漏洞")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("import-review", help="只读导入已审查公开资料和七维原始输入")
    create.add_argument("--cve", required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--output-root")
    create.add_argument("--parent-run-id")
    create.add_argument("--parent-manifest-sha256")
    package = commands.add_parser("package", help="校验已归档 run 并生成不会覆盖历史的研究资料 ZIP")
    package.add_argument("--cve", required=True)
    package.add_argument("--run-id", required=True)
    package.add_argument("--output-root")
    rebuild = commands.add_parser("rebuild-report", help="校验归档后，离线逐字节重建中文报告")
    rebuild.add_argument("--cve", required=True)
    rebuild.add_argument("--run-id", required=True)
    rebuild.add_argument("--output-root")
    verify = commands.add_parser("verify", help="独立检查 ZIP、原始字节和来源绑定，不作漏洞结论")
    verify.add_argument("--package", required=True)
    verify.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "import-review":
            run = import_review_run(args.cve, args.run_id, output_root=args.output_root,
                parent_run_id=args.parent_run_id, parent_manifest_sha256=args.parent_manifest_sha256)
            print(json.dumps({"status": "RESEARCH_ONLY", "run_directory": str(run),
                "report_locale": "zh-CN", "candidate_execution_status": "NOT_EXECUTED",
                "real_cve_verification": "NOT_VERIFIED"}, ensure_ascii=False))
        elif args.command == "package":
            path, result = package_run(args.cve, args.run_id, output_root=args.output_root)
            print(json.dumps({"package": str(path), "verification": result.model_dump(mode="json")},
                             ensure_ascii=False))
        elif args.command == "rebuild-report":
            print(rebuild_review_report(args.cve, args.run_id, output_root=args.output_root), end="")
        else:
            print(verify_package(args.package, expected_sha256=args.expected_sha256).model_dump_json(indent=2))
        return 0
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.exit(2, "归档失败，未声明成功：" + str(exc) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
