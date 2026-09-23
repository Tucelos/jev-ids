"""The command line: `jev-ids run|metrics|compare|arena|arena-eval|arena-report`, also reachable as `python -m jev_ids`.

In reading order:

- `parse_k` and `parse_list`: the list arguments (`--k 0,1,all`).
- `build_parser`: the seven subcommands and their arguments.
- `run_command`, `metrics_command`, `compare_command`, `arena_command`, `eval_command`, `arena_report_command`: one handler per
  subcommand, each turning the parsed arguments into calls of `run`, `metrics`, `arena.loop`, `arena.final` or `arena.report`.
- `print_csv`: a table as CSV on stdout.
- `main`: parse, dispatch, return the exit code.

Nothing here knows how a Detector or a metric works, and no dataset is named here: `run` takes the card of the dataset as `--dataset` and
`arena` takes every knob it has as a TOML file.
"""

import argparse
import csv
import json
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from jev_ids import ROOT, metrics, run
from jev_ids.arena import final, loop, report
from jev_ids.arena.config import ARENA_CONFIG, ArenaConfig, check_choices, check_ranges, load_arena_config
from jev_ids.records import read_predictions


def parse_k(text: str) -> int | None:
    """One k: an integer, or `all` for the whole pool (Random Forest only)."""
    return None if text.strip() == "all" else int(text)


def parse_list(text: str) -> tuple[int | None, ...]:
    """A comma-separated list of integers: `--k 0,1,2,all` and `--seeds 0,1,2`.

    Both arguments are read the same way, so `all` is accepted for `--seeds` too, where it means nothing; nobody writes it and one parser is
    worth that much looseness.
    """
    return tuple(parse_k(part) for part in text.split(","))


def build_parser() -> argparse.ArgumentParser:
    """The seven subcommands; each one carries the function that handles it."""
    parser = argparse.ArgumentParser(prog="jev-ids")
    commands = parser.add_subparsers(dest="command", required=True)

    runner = commands.add_parser("run", help="run one detector over one split")
    runner.add_argument("--dataset", required=True, type=Path, help="the card: data/<name>/dataset.json")
    runner.add_argument(
        "--detector",
        required=True,
        help="jev, llm:deepseek, llm:openai, llm:gemini, random_forest, isolation_forest or offline",
    )
    runner.add_argument("--split", required=True, help="internal, pilot, smoke, ...")
    runner.add_argument(
        "--k",
        type=parse_list,
        default=(0, 1, 2, 4, 8),
        help="examples per category, comma separated; `all` for the forests",
    )
    runner.add_argument("--seeds", type=parse_list, default=(0, 1, 2), help="seeds of the example draws")
    runner.add_argument("--reps", type=int, default=1, help="repetitions of each (k, seed) cell")
    runner.add_argument("--model", help="provider model id, for the LLM detectors")
    runner.add_argument("--results-dir", type=Path, default=run.RESULTS_DIR, help="where the run directory is created")
    runner.set_defaults(handler=run_command)

    redoer = commands.add_parser("redo-errors", help="complete a run in place: its error rows again, its missing flows for the first time")
    redoer.add_argument("run_dir", type=Path, help="results/<run_id> directory")
    redoer.set_defaults(handler=redo_command)

    reporter = commands.add_parser("metrics", help="summarize one or more runs")
    reporter.add_argument("run_dirs", nargs="+", type=Path, help="results/<run_id> directories")
    reporter.set_defaults(handler=metrics_command)

    comparer = commands.add_parser("compare", help="paired comparison of two detectors over the same split")
    comparer.add_argument("--a", nargs="+", required=True, type=Path, help="results/<run_id> directories of detector A")
    comparer.add_argument("--b", nargs="+", required=True, type=Path, help="results/<run_id> directories of detector B")
    comparer.add_argument(
        "--subset",
        choices=("all", "novel", "known"),
        default="all",
        help="every flow, only novel attacks or only known attacks",
    )
    comparer.add_argument("--k-a", help="cut run A to this k or `all`")
    comparer.add_argument("--k-b", help="cut run B to this k or `all`")
    comparer.set_defaults(handler=compare_command)

    arena = commands.add_parser("arena", help="play the adversarial loop: attacker, analyst, curator and gate, round after round")
    arena.add_argument("--config", type=Path, default=ARENA_CONFIG, help="the arena's TOML file: configs/arena.toml")
    arena.add_argument("--rounds", type=int, help="override [arena] rounds")
    arena.add_argument("--seeds", type=parse_list, help="override [arena] seeds, comma separated")
    arena.add_argument("--detector", help="override [detector] name: jev or offline")
    arena.add_argument("--dry-run", action="store_true", help="print the pre-flight projection and stop, without a single call")
    arena.set_defaults(handler=arena_command)

    evaluator = commands.add_parser(
        "arena-eval", help="measure a finished arena run on the eval split: four contexts over the very same flows"
    )
    evaluator.add_argument("run_dir", type=Path, help="results/arena/<run_id>, the finished run to measure")
    evaluator.add_argument("--dry-run", action="store_true", help="print the pre-flight projection and stop, without a single call")
    evaluator.add_argument("--results-dir", type=Path, default=final.EVAL_RESULTS, help="where the evaluation directory is created")
    evaluator.add_argument("--report", type=Path, help="print the table of a finished evaluation instead of running one")
    evaluator.set_defaults(handler=eval_command)

    tables = commands.add_parser("arena-report", help="the tables of one or more arena runs: per round, per run, or arm against arm")
    tables.add_argument("run_dirs", nargs="+", type=Path, help="results/arena/<run_id> directories")
    tables.add_argument(
        "--grain",
        choices=("rounds", "run", "compare"),
        default="rounds",
        help="one row per round, one per seed, or one per run and seed against the first directory given",
    )
    tables.set_defaults(handler=arena_report_command)
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
        results_dir=args.results_dir,
    )
    run.run_from_spec(spec)


def redo_command(args: argparse.Namespace) -> None:
    """`redo-errors`: complete the run directory given, in place."""
    run.redo_errors(args.run_dir)


def metrics_command(args: argparse.Namespace) -> None:
    """`metrics`: one CSV row per group over every run given, on stdout."""
    predictions = [p for run_dir in args.run_dirs for p in read_predictions(run_dir)]
    print_csv(metrics.summarize(predictions))


def compare_command(args: argparse.Namespace) -> None:
    """`compare`: the paired comparison of two detectors, optionally across k, as CSV."""
    if (args.k_a is None) != (args.k_b is None):
        raise SystemExit("--k-a and --k-b come together")
    across_k = None if args.k_a is None else (parse_k(args.k_a), parse_k(args.k_b))
    # A detector may be spread over several run directories (one k each, run in parallel); each side is the union of its rows.
    run_a = metrics.only_subset([p for run_dir in args.a for p in read_predictions(run_dir)], args.subset)
    run_b = metrics.only_subset([p for run_dir in args.b for p in read_predictions(run_dir)], args.subset)
    print_csv(metrics.compare(run_a, run_b, across_k))


def overridden(config: ArenaConfig, args: argparse.Namespace) -> ArenaConfig:
    """The TOML config with the flags that were given applied on top of it.

    A flag that was not given changes nothing, so the file stays the single statement of what a Run was: the three overrides exist for the
    three things a reader changes while debugging a Run, and each of them lands in that Run's own `config.json`.
    """
    arena = config.arena
    if args.rounds is not None:
        arena = replace(arena, rounds=args.rounds)
    if args.seeds is not None:
        arena = replace(arena, seeds=tuple(seed for seed in args.seeds if seed is not None))
    detector = config.detector if args.detector is None else replace(config.detector, name=args.detector)
    overrides = replace(config, arena=arena, detector=detector)
    # The file was checked when it was loaded; a flag can break it just as well, and a misspelled `--detector` that silently ran the other
    # one would be the worst kind of typo: the Run would finish, look healthy and answer a question nobody asked.
    check_ranges(overrides)
    check_choices(overrides)
    return overrides


def arena_command(args: argparse.Namespace) -> None:
    """`arena`: the adversarial loop, or with `--dry-run` only the pre-flight projection of what it would spend."""
    config = overridden(load_arena_config(args.config), args)
    if args.dry_run:
        print(json.dumps(loop.preflight(config).to_dict(), indent=2))
        return
    loop.run_arena(config)


def eval_command(args: argparse.Namespace) -> None:
    """`arena-eval`: the measurement that can be quoted, its projection, or the table of one already made.

    The loop's own numbers cannot answer whether the curator helped: across a Run the baseline and the final Context were judged in
    different Rounds against different mutations, and proposals were selected on the gate split that measured them. This judges four
    Contexts over one identical set of Flows, so the comparison is paired and the three steps of the decomposition are readable.
    """
    if args.report is not None:
        print_csv(final.summarize_eval(args.report))
        return
    if args.dry_run:
        print(json.dumps(final.preflight(args.run_dir).to_dict(), indent=2))
        return
    print_csv(final.summarize_eval(final.run_final(args.run_dir, results_dir=args.results_dir)))


def arena_report_command(args: argparse.Namespace) -> None:
    """`arena-report`: a finished Run's tables at the grain asked for, as CSV.

    `compare` puts arms side by side and refuses Runs that are not comparable, naming the facet that differs; it takes the first
    directory as the reference. The other two grains read one Run each, so they take the first directory given.
    """
    if args.grain == "compare":
        print_csv(report.compare_runs(args.run_dirs))
        return
    summarize = report.summarize_rounds if args.grain == "rounds" else report.summarize_run
    print_csv([row for run_dir in args.run_dirs for row in summarize(run_dir)])


def print_csv(rows: Sequence[dict[str, Any]]) -> None:
    """The rows as CSV on stdout, header first; nothing at all when there are none.

    The header is every key any row has, in order of first appearance: the usage columns of a summary follow the Detectors present. CSV on
    stdout: the user redirects it when a file is wanted.
    """
    if not rows:
        return
    header = list(dict.fromkeys(key for row in rows for key in row))
    writer = csv.DictWriter(sys.stdout, fieldnames=header, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)


def main(argv: Sequence[str] | None = None) -> int:
    """Load the secrets of `.env`, parse the command line and call the subcommand's handler."""
    # The API keys live in `.env` and never in git (README); the console script and `python -m jev_ids` both pass through here.
    load_dotenv(ROOT / ".env")
    args = build_parser().parse_args(argv)
    args.handler(args)
    return 0
