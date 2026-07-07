from __future__ import annotations

import argparse
import json
from pathlib import Path

from .batch import evaluate
from .datasets import convert_nvd
from .reports import markdown
from .signals import aggregate


def _write_json(path: str | Path, data: dict) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="aldir-almozza", description="الدرع الموزع: إشارات دفاع تشاركية.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    agg = sub.add_parser("aggregate")
    agg.add_argument("--input", required=True)
    convert = sub.add_parser("convert-nvd")
    convert.add_argument("--input", default="C:/Projects/kashif/data/external/nvd_cves_12000.jsonl")
    convert.add_argument("--out", default="data/benchmarks/aldir_nvd_signals.jsonl")
    convert.add_argument("--limit", type=int, default=12000)
    batch = sub.add_parser("batch")
    batch.add_argument("--input", default="data/benchmarks/aldir_nvd_signals.jsonl")
    batch.add_argument("--json-out", default="reports/aldir_benchmark.json")
    batch.add_argument("--report", default="reports/aldir_benchmark.md")
    stress = sub.add_parser("stress")
    stress.add_argument("--input", default="data/benchmarks/aldir_nvd_signals.jsonl")
    stress.add_argument("--repeat", type=int, default=3)
    stress.add_argument("--json-out", default="reports/aldir_stress.json")
    stress.add_argument("--report", default="reports/aldir_stress.md")
    serve = sub.add_parser("serve")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    sub.add_parser("version")
    args = parser.parse_args(argv)
    if args.cmd == "serve":
        from .service import run_server

        run_server(host=args.host, port=args.port)
        return 0
    if args.cmd == "version":
        from .version import __version__

        print(json.dumps({"service": "aldir-almozza", "version": __version__}, ensure_ascii=False))
        return 0
    if args.cmd == "aggregate":
        rows = [json.loads(line) for line in Path(args.input).read_text(encoding="utf-8").splitlines() if line.strip()]
        print(json.dumps(aggregate(rows), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "convert-nvd":
        print(json.dumps(convert_nvd(args.input, args.out, limit=args.limit), ensure_ascii=False, indent=2))
        return 0
    if args.cmd in {"batch", "stress"}:
        summary = evaluate(args.input, repeat=getattr(args, "repeat", 1))
        _write_json(args.json_out, summary)
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(markdown(summary, "تقرير ضغط الدرع الموزع" if args.cmd == "stress" else "تقرير الدرع الموزع"), encoding="utf-8")
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary["collapse_check"]["passed"] else 2
    raise ValueError(args.cmd)


if __name__ == "__main__":
    raise SystemExit(main())

