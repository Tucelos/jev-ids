"""The command line: `python -m somids run|metrics|compare`.

In reading order:

- `parse_k`, `parse_ks`, `parse_ints`: the list arguments (`--k 0,1,all`).
- `build_parser`: the three subcommands and their arguments.
- `run_command`, `metrics_command`, `compare_command`: one handler per subcommand, each turning the parsed arguments into calls of `run` or
  `metrics`.
- `print_csv`: a table as CSV on stdout (grilling §15).
- `main`: parse, dispatch, return the exit code.

Nothing here knows how a Detector or a metric works, and no dataset is named here: `run` takes the card of the dataset as `--dataset`.
"""

import argparse
import csv
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from somids import metrics, run
from somids.records import read_predictions


def parse_k(text: str) -> int | None:
    """One k: an integer, or `all` for the whole pool (Random Forest only)."""
    return None if text.strip() == "all" else int(text)


def parse_ks(text: str) -> tuple[int | None, ...]:
    """`--k 0,1,2,all`: a comma-separated list of k."""
    return tuple(parse_k(part) for part in text.split(","))


def parse_ints(text: str) -> tuple[int, ...]:
    """`--seeds 0,1,2` as a tuple of integers."""
    return tuple(int(part) for part in text.split(","))


def build_parser() -> argparse.ArgumentParser:
    """The three subcommands; each one carries the function that handles it.

    The defaults of `run` are the bundle agreed in grilling Q27.
    """
    parser = argparse.ArgumentParser(prog="somids")
    commands = parser.add_subparsers(dest="command", required=True)

    runner = commands.add_parser("run", help="run one detector over one split")
    runner.add_argument("--dataset", required=True, type=Path, help="the card: data/<name>/dataset.json")
    runner.add_argument("--detector", required=True, help="jev, llm:deepseek, llm:chatgpt or rf")
    runner.add_argument("--split", required=True, help="internal, pilot, smoke, ...")
    runner.add_argument(
        "--k",
        type=parse_ks,
        default=(0, 1, 2, 4, 8, 16),
        help="examples per category, comma separated; `all` for the Random Forest",
    )
    runner.add_argument("--seeds", type=parse_ints, default=(0, 1, 2), help="seeds of the example draws")
    runner.add_argument("--reps", type=int, default=1, help="repetitions of each (k, seed) cell")
    runner.add_argument("--model", help="provider model id, for the LLM detectors")
    runner.set_defaults(handler=run_command)

    reporter = commands.add_parser("metrics", help="summarize one or more runs")
    reporter.add_argument("run_dirs", nargs="+", type=Path, help="results/<run_id> directories")
    reporter.set_defaults(handler=metrics_command)

    comparer = commands.add_parser("compare", help="paired comparison of two runs over the same split")
    comparer.add_argument("run_a", type=Path, help="results/<run_id> of detector A")
    comparer.add_argument("run_b", type=Path, help="results/<run_id> of detector B")
    comparer.add_argument(
        "--subset",
        choices=("all", "novel", "known"),
        default="all",
        help="every flow, only novel attacks or only known attacks",
    )
    comparer.add_argument("--k-a", help="cut run A to this k or `all`")
    comparer.add_argument("--k-b", help="cut run B to this k or `all`")
    comparer.set_defaults(handler=compare_command)
    return parser


def run_command(args: argparse.Namespace) -> None:
    """`run`: one detector over one split; argparse already converted the types."""
    spec = run.RunSpec(
        detector=args.detector,
        dataset=args.dataset,
        split=args.split,
        k_values=args.k,
        seeds=args.seeds,
        reps=args.reps,
        model_id=args.model,
    )
    run.run_from_spec(spec)


def metrics_command(args: argparse.Namespace) -> None:
    """`metrics`: one CSV row per group over every run given, on stdout."""
    predictions = [p for run_dir in args.run_dirs for p in read_predictions(run_dir)]
    print_csv(metrics.summarize(predictions))


def compare_command(args: argparse.Namespace) -> None:
    """`compare`: the paired comparison of two runs, optionally across k, as CSV."""
    if (args.k_a is None) != (args.k_b is None):
        raise SystemExit("--k-a and --k-b come together")
    across_k = None if args.k_a is None else (parse_k(args.k_a), parse_k(args.k_b))
    run_a = metrics.select(read_predictions(args.run_a), args.subset)
    run_b = metrics.select(read_predictions(args.run_b), args.subset)
    print_csv(metrics.compare(run_a, run_b, across_k))


def print_csv(rows: Sequence[dict[str, Any]]) -> None:
    """The rows as CSV on stdout, header first; nothing at all when there are none.

    The header is every key any row has, in order of first appearance: the usage columns of a summary follow the Detectors present. CSV on
    stdout by decision (grilling §15): the user redirects it when a file is wanted.
    """
    if not rows:
        return
    header = list(dict.fromkeys(key for row in rows for key in row))
    writer = csv.DictWriter(sys.stdout, fieldnames=header, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)


def main(argv: Sequence[str] | None = None) -> int:
    """Parse the command line and call the subcommand's handler."""
    args = build_parser().parse_args(argv)
    args.handler(args)
    return 0
