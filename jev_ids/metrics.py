"""Tables from predictions.jsonl rows: `summarize` one or more runs, `compare` two.

Helpers first (`verdict`, `mean`, `ratio`, `rate`, `only_subset`, `only_k`, `group_by_fields`), then the scores of one set of rows
(`scores`), the priced usage (`cost_usd_per_1m`, `usage`), the summary (`summary`, `none_last_key`, `summarize`) and the paired comparison
(`mcnemar_exact`, `compare_cell`, `compare`). Attack-class F1, not macro; a row without a Verdict counts as `normal` (fail-open); the CLI
turns the dicts into CSV.
"""

import json
import statistics
from collections import defaultdict
from collections.abc import Iterable, Sequence
from math import comb
from typing import Any

from jev_ids import ROOT
from jev_ids.records import Prediction

PRICES_PATH = ROOT / "prices.json"
PredictionPair = tuple[Prediction, Prediction]


def verdict(prediction: Prediction) -> int:
    """The Verdict of a row; without one (a failed call) it counts as normal."""
    return int(prediction.get("classification_verdict") or 0)


def mean(values: Iterable[float | None]) -> float | None:
    """Mean of the values present; None when all are missing."""
    present = [value for value in values if value is not None]
    return statistics.fmean(present) if present else None


def ratio(numerator: float, denominator: float) -> float | None:
    """A share, or None when the denominator is zero."""
    return None if denominator == 0 else numerator / denominator


def rate(rows: Sequence[Prediction]) -> float | None:
    """Share of the rows that raised an alert: the recall, over attacks."""
    return ratio(sum(verdict(p) for p in rows), len(rows))


def only_subset(predictions: Sequence[Prediction], subset: str) -> list[Prediction]:
    """`all` the rows, only the `novel` attacks or only the `known` ones."""
    if subset == "all":
        return list(predictions)
    novel = subset == "novel"
    return [p for p in predictions if p["is_attack"] == 1 and p["novel_attack"] == novel]


def only_k(predictions: Iterable[Prediction], k: int | None) -> list[Prediction]:
    """The rows of one k; None is k = all (the Random Forest on the whole pool)."""
    return [p for p in predictions if p["k"] == k]


def group_by_fields(predictions: Iterable[Prediction], fields: Sequence[str]) -> dict[tuple[Any, ...], list[Prediction]]:
    """The rows sharing the given fields, keyed by their values."""
    groups: dict[tuple[Any, ...], list[Prediction]] = defaultdict(list)
    for prediction in predictions:
        groups[tuple(prediction.get(field) for field in fields)].append(prediction)
    return dict(groups)


def scores(rows: Sequence[Prediction]) -> dict[str, float | None]:
    """Attack-class F1, precision, the three recalls and the error rate of the rows."""
    attacks = [p for p in rows if p["is_attack"] == 1]
    hits = sum(verdict(p) for p in attacks)  # alerts on attacks: true positives
    alerts = sum(verdict(p) for p in rows)
    return {
        "f1": ratio(2 * hits, alerts + len(attacks)),
        "precision": ratio(hits, alerts),
        "recall": rate(attacks),
        "recall_novel": rate(only_subset(rows, "novel")),
        "recall_known": rate(only_subset(rows, "known")),
        # A row without a Verdict is a call that failed.
        "error_rate": ratio(sum(p.get("classification_verdict") is None for p in rows), len(rows)),
    }


def cost_usd_per_1m(row: Prediction, prices: dict[str, Any]) -> float | None:
    """List cost in USD of 1M calls like this row: tokens × the per-1M-token prices."""
    tokens: dict[str, Any] = row.get("usage", {})
    price: dict[str, float] | None = prices.get(row.get("model", ""))
    if price is None or "input_tokens" not in tokens:
        return None
    cached = tokens.get("cache_read_tokens", 0)  # part of the input, at its own rate
    return (
        (tokens["input_tokens"] - cached) * price["input"]
        + cached * price["cached_input"]
        + tokens.get("output_tokens", 0) * price["output"]
    )


def usage(rows: Sequence[Prediction], prices: dict[str, Any]) -> dict[str, float | None]:
    """Mean of every number in the rows' usage, cost per 1M Flows and mean latency."""
    usages: list[dict[str, Any]] = [p.get("usage", {}) for p in rows]
    # Every key that holds a number in at least one row: Detectors report different token fields, so the columns follow the rows.
    counted = sorted({name for u in usages for name, value in u.items() if isinstance(value, int | float)})
    return {
        **{f"{name}_mean": mean(u.get(name) for u in usages) for name in counted},
        "cost_usd_per_1m": mean(cost_usd_per_1m(p, prices) for p in rows),
        "latency_ms_mean": mean(p.get("latency_ms") for p in rows),
    }


def summary(members: Sequence[Prediction], prices: dict[str, Any]) -> dict[str, Any]:
    """Counts, every score averaged over the (seed, rep) cells, sd of F1 and usage."""
    cells = [scores(cell) for cell in group_by_fields(members, ("seed", "repetition")).values()]
    # The paper reports mean ± sd of F1 across the cells; a cell whose F1 is undefined does not enter the spread, and one cell has none.
    f1_values = [cell["f1"] for cell in cells if cell["f1"] is not None]
    return {
        "cells": len(cells),
        "flows": len({p["row_id"] for p in members}),
        "predictions": len(members),
        **{f"{name}_mean": mean(cell[name] for cell in cells) for name in cells[0]},
        "f1_sd": statistics.stdev(f1_values) if len(f1_values) > 1 else None,
        **usage(members, prices),
    }


def none_last_key(values: Sequence[Any]) -> tuple[Any, ...]:
    """Sort key that puts None (k = all, or a row without dataset) last."""
    return tuple((value is None, 0 if value is None else value) for value in values)


def summarize(predictions: Iterable[Prediction]) -> list[dict[str, Any]]:
    """One row per (dataset, detector, model, split, k), k = all last."""
    prices: dict[str, Any] = json.loads(PRICES_PATH.read_text("utf-8"))["models"]
    fields = ("dataset", "detector", "model", "split", "k")
    groups = group_by_fields(predictions, fields)
    return [{**dict(zip(fields, key, strict=True)), **summary(groups[key], prices)} for key in sorted(groups, key=none_last_key)]


def mcnemar_exact(a_correct: int, b_correct: int) -> float:
    """Exact two-sided binomial test that the discordant pairs split evenly."""
    total = a_correct + b_correct  # p = 1 without any discordant pair
    tail = sum(comb(total, i) for i in range(min(a_correct, b_correct) + 1)) / 2**total
    return min(1.0, 2 * tail)


def compare_cell(pairs: Sequence[PredictionPair]) -> dict[str, Any]:
    """Counts over the pairs; only the discordant ones tell A from B."""
    discordant = [(row_a, row_b) for row_a, row_b in pairs if verdict(row_a) != verdict(row_b)]
    a_correct = sum(verdict(row_a) == row_a["is_attack"] for row_a, _ in discordant)
    b_correct = len(discordant) - a_correct
    return {
        "pairs": len(pairs),
        "discordant": len(discordant),
        "a_correct": a_correct,
        "b_correct": b_correct,
        "mcnemar_p": mcnemar_exact(a_correct, b_correct),
        "f1_a": scores([row_a for row_a, _ in pairs])["f1"],
        "f1_b": scores([row_b for _, row_b in pairs])["f1"],
    }


def compare(
    run_a: Sequence[Prediction], run_b: Sequence[Prediction], across_k: tuple[int | None, int | None] | None = None
) -> list[dict[str, Any]]:
    """One table row per (k of A, k of B, rep) over the pairs of run A and run B.

    A pair is a row of A and a row of B that judged the same Flow in the same cell: same k, seed and repetition. With
    `across_k = (k_a, k_b)` the runs are first cut to those k and the pairs cross k, which is how zero-shot Jev meets the Random Forest
    at k = all (None).
    """
    # What a row of A and a row of B must share to form a pair: the Flow (row_id) and the cell (k, seed, repetition). When comparing across
    # k, each run is first reduced to one k (A to k_a, B to k_b) and k leaves the list, so the same Flow at two different k pairs up.
    if across_k is None:
        pair_fields = ("row_id", "k", "seed", "repetition")
    else:
        run_a, run_b = only_k(run_a, across_k[0]), only_k(run_b, across_k[1])
        pair_fields = ("row_id", "seed", "repetition")

    # Index each run by those fields: one key per Flow judged in a cell, holding the single row the run wrote for it. The comparison
    # table has one row per (k of A, k of B, repetition); `pairs_by_table_row` collects the pairs that fall into each of them.
    rows_a_by_cell, rows_b_by_cell = group_by_fields(run_a, pair_fields), group_by_fields(run_b, pair_fields)
    pairs_by_table_row: dict[tuple[Any, ...], list[PredictionPair]] = defaultdict(list)

    # Pair up: a cell judged by both runs gives one pair (A's row, B's row), filed under its table row. A cell only one run judged is
    # dropped, because a paired test needs both Verdicts on the same Flow.
    for cell in rows_a_by_cell:
        if cell in rows_b_by_cell:
            row_a, row_b = rows_a_by_cell[cell][0], rows_b_by_cell[cell][0]
            pairs_by_table_row[(row_a["k"], row_b["k"], row_a["repetition"])].append((row_a, row_b))

    # One dict per table row, ascending in (k of A, k of B, repetition) with k = all (None) last, carrying the counts of `compare_cell`.
    return [
        {"k_a": k_a, "k_b": k_b, "repetition": repetition, **compare_cell(pairs_by_table_row[(k_a, k_b, repetition)])}
        for k_a, k_b, repetition in sorted(pairs_by_table_row, key=none_last_key)
    ]
