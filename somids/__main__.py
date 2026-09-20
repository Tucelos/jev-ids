"""CLI entry point: `python -m somids <download|split|run|metrics>`."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import cast

from somids import dataset, metrics, run
from somids.dataset import RowFormat


def _ints(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split(",") if part.strip())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="somids")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser(
        "download", help="fetch NSL-KDD from Kaggle and verify checksums"
    )
    subcommands.add_parser(
        "split", help="draw the internal, paper and smoke splits from KDDTest+"
    )
    runner = subcommands.add_parser("run", help="run one detector over one split")
    runner.add_argument(
        "--detector", required=True, help="jev, llm:deepseek, llm:chatgpt or rf"
    )
    runner.add_argument("--split", required=True, help="internal, paper or smoke")
    runner.add_argument(
        "--k",
        type=_ints,
        default=(0, 1, 2, 4, 8, 16),
        help="examples per category, comma separated",
    )
    runner.add_argument(
        "--seeds", type=_ints, default=(0, 1, 2), help="seeds, comma separated"
    )
    runner.add_argument("--reps", type=int, default=1)
    runner.add_argument("--batch", type=int, default=1)
    runner.add_argument("--format", choices=("csv", "kv"), default="csv")
    runner.add_argument("--prompt", default="v1", help="prompt version under prompts/")
    runner.add_argument(
        "--model", default=None, help="provider model id, for the LLM detectors"
    )
    runner.add_argument(
        "--resume", default=None, metavar="RUN_ID", help="append to an existing run"
    )
    runner.add_argument(
        "--allow-paper", action="store_true", help="required to touch the paper split"
    )
    reporter = subcommands.add_parser("metrics", help="summarize one or more runs")
    reporter.add_argument(
        "run_dirs", nargs="+", type=Path, help="results/<run_id> directories"
    )
    reporter.add_argument(
        "--out", type=Path, default=None, help="where to write summary.csv"
    )
    return parser


def spec_from_args(args: argparse.Namespace) -> run.RunSpec:
    return run.RunSpec(
        detector=str(args.detector),
        split=str(args.split),
        ks=tuple(args.k),
        seeds=tuple(args.seeds),
        reps=int(args.reps),
        batch=int(args.batch),
        fmt=cast(RowFormat, args.format),
        prompt_version=str(args.prompt),
        model=None if args.model is None else str(args.model),
        resume=None if args.resume is None else str(args.resume),
        allow_paper=bool(args.allow_paper),
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "download":
        for name, digest in dataset.download().items():
            print(f"{name}: sha256 {digest}")
    elif args.command == "split":
        manifest = dataset.write_splits()
        print(manifest.read_text(encoding="utf-8"), end="")
    elif args.command == "run":
        run.run_from_spec(spec_from_args(args))
    elif args.command == "metrics":
        metrics.report(list(args.run_dirs), args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
