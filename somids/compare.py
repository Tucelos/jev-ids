"""Paired comparison of two runs over the same split.

Two Detectors judged the same Flows, so only the discordant pairs (Flows where
their Verdicts differ) tell them apart. Per k: pairs, discordant pairs, who was
right in each, McNemar's exact two-sided p-value on that score, both attack-class
F1 values and their difference with a percentile bootstrap interval over paired
resamples of the Flows.
"""

from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, fields
from math import comb
from pathlib import Path

from somids.metrics import f1_attack, format_cell, load_predictions, verdict
from somids.records import Prediction

Pair = tuple[Prediction, Prediction]
PairKey = tuple[int, int | None, int, int]
CI_LOW, CI_HIGH = 0.025, 0.975


@dataclass(frozen=True, slots=True)
class Comparison:
    k: int | None
    pairs: int
    discordant: int
    a_right: int
    b_right: int
    mcnemar_p: float | None
    f1_a: float | None
    f1_b: float | None
    delta_f1: float | None
    ci95_low: float | None
    ci95_high: float | None


def pair_runs(
    a: Sequence[Prediction], b: Sequence[Prediction]
) -> dict[int | None, list[Pair]]:
    """Match rows of the same Flow, k, seed and rep; unmatched rows are dropped."""
    lookup = {_key(prediction): prediction for prediction in b}
    pairs: dict[int | None, list[Pair]] = defaultdict(list)
    for prediction in a:
        other = lookup.get(_key(prediction))
        if other is not None:
            pairs[prediction.k].append((prediction, other))
    return dict(pairs)


def _key(prediction: Prediction) -> PairKey:
    return (prediction.row_id, prediction.k, prediction.seed, prediction.rep)


def score(pairs: Sequence[Pair]) -> tuple[int, int]:
    """Over the discordant pairs: (a right and b wrong, b right and a wrong)."""
    a_right = b_right = 0
    for left, right in pairs:
        if verdict(left) == verdict(right):
            continue
        if verdict(left) == left.y_true:
            a_right += 1
        else:
            b_right += 1
    return a_right, b_right


def mcnemar_exact(a_right: int, b_right: int) -> float | None:
    """Exact two-sided binomial test that the discordant pairs split evenly."""
    total = a_right + b_right
    if total == 0:
        return None
    tail = sum(comb(total, i) for i in range(min(a_right, b_right) + 1)) / 2**total
    return min(1.0, 2 * tail)


def delta_f1(pairs: Sequence[Pair]) -> float | None:
    f1_a = f1_attack([left for left, _ in pairs])
    f1_b = f1_attack([right for _, right in pairs])
    return None if f1_a is None or f1_b is None else f1_a - f1_b


def bootstrap_delta(
    pairs: Sequence[Pair], resamples: int, seed: int = 0
) -> tuple[float | None, float | None]:
    """95% percentile interval of F1_a - F1_b over paired resamples of the Flows."""
    rng = random.Random(seed)  # noqa: S311  # seeded, reproducible
    deltas: list[float] = []
    for _ in range(resamples):
        delta = delta_f1(rng.choices(pairs, k=len(pairs)))
        if delta is not None:
            deltas.append(delta)
    if not deltas:
        return None, None
    deltas.sort()
    return _quantile(deltas, CI_LOW), _quantile(deltas, CI_HIGH)


def _quantile(sorted_values: Sequence[float], q: float) -> float:
    return sorted_values[round(q * (len(sorted_values) - 1))]


def compare(
    a: Sequence[Prediction], b: Sequence[Prediction], resamples: int = 2000
) -> list[Comparison]:
    """One Comparison per k, in ascending k."""
    grouped = pair_runs(a, b)
    ordered = sorted(grouped, key=lambda k: (k is None, k or 0))
    return [_compare_k(k, grouped[k], resamples) for k in ordered]


def _compare_k(k: int | None, pairs: Sequence[Pair], resamples: int) -> Comparison:
    a_right, b_right = score(pairs)
    low, high = bootstrap_delta(pairs, resamples)
    return Comparison(
        k=k,
        pairs=len(pairs),
        discordant=a_right + b_right,
        a_right=a_right,
        b_right=b_right,
        mcnemar_p=mcnemar_exact(a_right, b_right),
        f1_a=f1_attack([left for left, _ in pairs]),
        f1_b=f1_attack([right for _, right in pairs]),
        delta_f1=delta_f1(pairs),
        ci95_low=low,
        ci95_high=high,
    )


def to_markdown(comparisons: Sequence[Comparison], name_a: str, name_b: str) -> str:
    columns = [field.name for field in fields(Comparison)]
    labels = {
        "a_right": f"{name_a} right",
        "b_right": f"{name_b} right",
        "f1_a": f"f1 {name_a}",
        "f1_b": f"f1 {name_b}",
    }
    header = [labels.get(column, column) for column in columns]
    lines = [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join("---" for _ in header) + " |",
    ]
    lines += [
        "| " + " | ".join(format_cell(getattr(c, column)) for column in columns) + " |"
        for c in comparisons
    ]
    return "\n".join(lines) + "\n"


def report(run_a: Path, run_b: Path, resamples: int = 2000) -> list[Comparison]:
    """Pair two runs of the same split and print the comparison table."""
    a, b = load_predictions([run_a]), load_predictions([run_b])
    if not a or not b:
        msg = "both runs need at least one prediction"
        raise ValueError(msg)
    if a[0].split != b[0].split:
        msg = f"runs are on different splits: {a[0].split} vs {b[0].split}"
        raise ValueError(msg)
    comparisons = compare(a, b, resamples)
    print(to_markdown(comparisons, a[0].detector, b[0].detector), end="")
    return comparisons
