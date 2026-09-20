"""CLI entry point: `python -m somids <download|split|run|metrics|compare>`."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

from dotenv import load_dotenv

from somids import compare, dataset, metrics, run
from somids.dataset import RowFormat


def parse_ks(text: str) -> tuple[int | None, ...]:
    """`--k 0,1,2,all`: integers, plus `all` for the whole Train+ (Random Forest)."""
    parts = [part.strip() for part in text.split(",") if part.strip()]
    return tuple(None if part == "all" else int(part) for part in parts)


def _ints(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split(",") if part.strip())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="somids")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser(
        "download", help="fetch NSL-KDD from Kaggle and verify checksums"
    )
    splitter = subcommands.add_parser(
        "split", help="draw the internal, paper and smoke splits from KDDTest+"
    )
    splitter.add_argument(
        "--band",
        choices=tuple(dataset.BANDS),
        default=None,
        help="draw only this balanced diagnostic split of a difficulty band",
    )
    _add_run_arguments(subcommands.add_parser("run", help="run one detector"))
    reporter = subcommands.add_parser("metrics", help="summarize one or more runs")
    reporter.add_argument(
        "run_dirs", nargs="+", type=Path, help="results/<run_id> directories"
    )
    reporter.add_argument(
        "--out", type=Path, default=None, help="where to write summary.csv"
    )
    comparer = subcommands.add_parser(
        "compare", help="paired comparison of two runs over the same split"
    )
    comparer.add_argument("run_a", type=Path, help="results/<run_id> of detector A")
    comparer.add_argument("run_b", type=Path, help="results/<run_id> of detector B")
    comparer.add_argument(
        "--bootstrap", type=int, default=2000, help="resamples for the ΔF1 interval"
    )
    return parser


def _add_run_arguments(runner: argparse.ArgumentParser) -> None:
    runner.add_argument(
        "--detector", required=True, help="jev, llm:deepseek, llm:chatgpt or rf"
    )
    runner.add_argument("--split", required=True, help="internal, paper, smoke, ...")
    runner.add_argument(
        "--k",
        type=parse_ks,
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


def _download(_args: argparse.Namespace) -> None:
    for name, digest in dataset.download().items():
        print(f"{name}: sha256 {digest}")


def _split(args: argparse.Namespace) -> None:
    """`split` draws the proportional splits; `split --band NAME` one diagnostic."""
    band = None if args.band is None else str(args.band)
    manifest = (
        dataset.write_splits() if band is None else dataset.write_band_split(band)
    )
    print(manifest.read_text(encoding="utf-8"), end="")


def _run(args: argparse.Namespace) -> None:
    run.run_from_spec(spec_from_args(args))


def _metrics(args: argparse.Namespace) -> None:
    metrics.report(list(args.run_dirs), args.out)


def _compare(args: argparse.Namespace) -> None:
    compare.report(Path(args.run_a), Path(args.run_b), int(args.bootstrap))


HANDLERS: dict[str, Callable[[argparse.Namespace], None]] = {
    "download": _download,
    "split": _split,
    "run": _run,
    "metrics": _metrics,
    "compare": _compare,
}


def main(argv: Sequence[str] | None = None) -> int:
    load_dotenv(dataset.ROOT / ".env")
    args = build_parser().parse_args(argv)
    HANDLERS[str(args.command)](args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
