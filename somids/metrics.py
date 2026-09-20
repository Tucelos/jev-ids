"""Summary tables computed offline from one or more `predictions.jsonl` files.

Per (detector, model, split, k, format, prompt version): attack-class F1 as
mean ± sd over the (seed, rep) cells, recall on novel and on known attacks,
error rate, mean tokens, list cost per 1M Flows, mean latencies and, when a
cell was repeated, how often the Verdict flipped between repetitions.
"""

from __future__ import annotations

import csv
import statistics
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from somids.records import Prediction, RunFiles

GroupKey = tuple[str, str, str, int | None, str, str]
CellKey = tuple[int, int]
PER_FLOWS = 1_000_000
TABLE_COLUMNS = (
    "detector",
    "k",
    "cells",
    "f1_mean",
    "f1_sd",
    "recall_novel_mean",
    "recall_known_mean",
    "error_rate",
    "input_tokens_mean",
    "cost_usd_per_1m",
    "latency_e2e_ms_mean",
    "verdict_flip_rate",
)


@dataclass(frozen=True, slots=True)
class Summary:
    detector: str
    model: str
    split: str
    k: int | None
    format: str
    prompt_version: str
    cells: int
    flows: int
    predictions: int
    f1_mean: float | None
    f1_sd: float | None
    recall_novel_mean: float | None
    recall_known_mean: float | None
    error_rate: float
    input_tokens_mean: float | None
    output_tokens_mean: float | None
    cost_usd_per_1m: float | None
    latency_e2e_ms_mean: float | None
    latency_provider_ms_mean: float | None
    verdict_flip_rate: float | None
    p_attack_sd_mean: float | None


def verdict(prediction: Prediction) -> int:
    """The Verdict used by every metric; an error row counts as `normal`."""
    return prediction.y_pred or 0


def f1_attack(predictions: Sequence[Prediction]) -> float | None:
    """F1 of the attack class; None when there is neither an attack nor an alert."""
    tp = sum(p.y_true == 1 and verdict(p) == 1 for p in predictions)
    fp = sum(p.y_true == 0 and verdict(p) == 1 for p in predictions)
    fn = sum(p.y_true == 1 and verdict(p) == 0 for p in predictions)
    denominator = 2 * tp + fp + fn
    return None if denominator == 0 else 2 * tp / denominator


def recall(predictions: Sequence[Prediction], novel: bool) -> float | None:
    """Share of attacks detected among the novel (or the known) attack Flows."""
    attacks = [p for p in predictions if p.y_true == 1 and p.novel_attack == novel]
    if not attacks:
        return None
    return sum(verdict(p) == 1 for p in attacks) / len(attacks)


def mean_of(values: Iterable[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return statistics.fmean(present) if present else None


def sd_of(values: Sequence[float]) -> float | None:
    return statistics.stdev(values) if len(values) > 1 else None


def group_key(prediction: Prediction) -> GroupKey:
    return (
        prediction.detector,
        prediction.model,
        prediction.split,
        prediction.k,
        prediction.format,
        prediction.prompt_version,
    )


def by_cell(predictions: Sequence[Prediction]) -> dict[CellKey, list[Prediction]]:
    cells: dict[CellKey, list[Prediction]] = defaultdict(list)
    for prediction in predictions:
        cells[(prediction.seed, prediction.rep)].append(prediction)
    return cells


def stability(predictions: Sequence[Prediction]) -> tuple[float | None, float | None]:
    """Verdict flip rate and mean p_attack sd across the reps of each (Flow, seed)."""
    repeated = _repeated_series(predictions)
    if not repeated:
        return None, None
    flips = sum(_flipped(group) for group in repeated)
    return flips / len(repeated), mean_of(_p_attack_sd(group) for group in repeated)


def _repeated_series(predictions: Sequence[Prediction]) -> list[list[Prediction]]:
    """The Predictions of each (Flow, seed) that was judged more than once."""
    series: dict[tuple[int, int], list[Prediction]] = defaultdict(list)
    for prediction in predictions:
        series[(prediction.row_id, prediction.seed)].append(prediction)
    return [group for group in series.values() if len(group) > 1]


def _flipped(group: Sequence[Prediction]) -> bool:
    return len({verdict(p) for p in group}) > 1


def _p_attack_sd(group: Sequence[Prediction]) -> float | None:
    return sd_of([p.p_attack for p in group if p.p_attack is not None])


def summarize_group(key: GroupKey, predictions: Sequence[Prediction]) -> Summary:
    cells = by_cell(predictions)
    f1s = [f1 for cell in cells.values() if (f1 := f1_attack(cell)) is not None]
    flip_rate, p_sd = stability(predictions)
    return Summary(
        detector=key[0],
        model=key[1],
        split=key[2],
        k=key[3],
        format=key[4],
        prompt_version=key[5],
        cells=len(cells),
        flows=len({p.row_id for p in predictions}),
        predictions=len(predictions),
        f1_mean=mean_of(f1s),
        f1_sd=sd_of(f1s),
        recall_novel_mean=mean_of(recall(cell, True) for cell in cells.values()),
        recall_known_mean=mean_of(recall(cell, False) for cell in cells.values()),
        error_rate=sum(p.error is not None for p in predictions) / len(predictions),
        input_tokens_mean=mean_of(p.input_tokens for p in predictions),
        output_tokens_mean=mean_of(p.output_tokens for p in predictions),
        cost_usd_per_1m=_scaled(mean_of(p.cost_usd for p in predictions)),
        latency_e2e_ms_mean=mean_of(p.latency_e2e_ms for p in predictions),
        latency_provider_ms_mean=mean_of(p.latency_provider_ms for p in predictions),
        verdict_flip_rate=flip_rate,
        p_attack_sd_mean=p_sd,
    )


def _scaled(mean_cost: float | None) -> float | None:
    return None if mean_cost is None else mean_cost * PER_FLOWS


def summarize(predictions: Iterable[Prediction]) -> list[Summary]:
    groups: dict[GroupKey, list[Prediction]] = defaultdict(list)
    for prediction in predictions:
        groups[group_key(prediction)].append(prediction)
    ordered = sorted(
        groups, key=lambda key: (key[0], key[1], key[2], key[3] is None, key[3] or 0)
    )
    return [summarize_group(key, groups[key]) for key in ordered]


def load_predictions(run_dirs: Iterable[Path]) -> list[Prediction]:
    predictions: list[Prediction] = []
    for run_dir in run_dirs:
        predictions.extend(RunFiles(run_dir).read_predictions())
    return predictions


def _cell(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.4g}"
    return str(value)


def to_markdown(summaries: Sequence[Summary]) -> str:
    header = "| " + " | ".join(TABLE_COLUMNS) + " |"
    rule = "|" + "|".join(" --- " for _ in TABLE_COLUMNS) + "|"
    rows = [
        "| "
        + " | ".join(_cell(getattr(summary, column)) for column in TABLE_COLUMNS)
        + " |"
        for summary in summaries
    ]
    return "\n".join([header, rule, *rows]) + "\n"


def write_csv(summaries: Sequence[Summary], path: Path) -> None:
    names = [field.name for field in fields(Summary)]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=names)
        writer.writeheader()
        for summary in summaries:
            writer.writerow(asdict(summary))


def report(run_dirs: Sequence[Path], out: Path | None = None) -> Path:
    """Summarize the runs, print the table and write `summary.csv`."""
    summaries = summarize(load_predictions(run_dirs))
    target = (
        out
        or (run_dirs[0] if len(run_dirs) == 1 else run_dirs[0].parent) / "summary.csv"
    )
    write_csv(summaries, target)
    print(to_markdown(summaries), end="")
    return target
