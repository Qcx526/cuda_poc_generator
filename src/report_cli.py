"""Read-only import into independent, deterministic Chinese report views."""

import argparse
import hashlib
import json
from pathlib import Path

from .report_locale import write_report_view, rebuild_report_view, configure_utf8_stdio
from .oracle_report import _read


def main(argv=None):
    configure_utf8_stdio()
    parser=argparse.ArgumentParser(description="中文报告离线重建；不执行程序，不改变原始科学结论")
    commands=parser.add_subparsers(dest="command",required=True)
    create=commands.add_parser("render",help="只读导入固定结构化对象，生成独立中文视图")
    create.add_argument("--kind",choices=["claim","oracle","generation","platform","execution","host-parser","failure"],required=True)
    create.add_argument("--source",required=True)
    create.add_argument("--source-sha256",required=True,help="文件或旧 bundle 清单的独立 SHA-256")
    create.add_argument("--output-dir",required=True)
    rebuild=commands.add_parser("rebuild",help="核对源字节和结果，逐字节重建中文文本；不等于独立重评估")
    rebuild.add_argument("--report-dir",required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=="rebuild":
            print(rebuild_report_view(args.report_dir),end="")
            return 0
        source=Path(args.source)
        kind=args.kind.upper().replace("-","_")
        if kind=="ORACLE":
            from .oracle_report import rebuild_oracle_report
            raw=_read(source/"oracle_manifest.json",65536)
            if hashlib.sha256(raw).hexdigest()!=args.source_sha256:
                raise ValueError("原 Oracle 清单的独立 SHA-256 不匹配")
            rebuild_oracle_report(source)
            sources={name:_read(source/name,16*1024*1024) for name in ("plan.json","result.json","claim.json") if (source/name).exists()}
        elif kind=="EXECUTION":
            from .lifecycle_artifacts import read_execution_evidence
            raw=_read(source/"manifest.json",131072)
            if hashlib.sha256(raw).hexdigest()!=args.source_sha256:
                raise ValueError("原执行清单的独立 SHA-256 不匹配")
            read_execution_evidence(source)
            sources={name:_read(source/name,16*1024*1024) for name in ("execution_record.json","manifest.json")}
        else:
            raw=_read(source,16*1024*1024)
            if hashlib.sha256(raw).hexdigest()!=args.source_sha256:
                raise ValueError("源记录的独立 SHA-256 不匹配")
            name={"CLAIM":"claim.json","GENERATION":"generation.json","PLATFORM":"platform.json",
                  "HOST_PARSER":"host_parser.json","FAILURE":"failure.json"}[kind]
            sources={name:raw}
        folder=write_report_view(args.output_dir,kind,sources)
        print(json.dumps({"report_locale":"zh-CN","report":str(folder/"report.zh-CN.md"),
            "status":"PRESENTATION_ONLY","real_cve_verification":"NOT_VERIFIED"},ensure_ascii=False))
        return 0
    except (ValueError,KeyError,TypeError,OSError) as exc:
        parser.exit(2,"中文报告生成失败，未声明成功："+str(exc)+"\n")


if __name__=="__main__":
    raise SystemExit(main())
