"""Paired comparison: pairing, discordant score, McNemar, bootstrap and report."""

from __future__ import annotations

from pathlib import Path

import pytest

from somids import compare
from somids.records import Prediction, RunFiles


def make(  # noqa: PLR0913
    row_id: int,
    y_true: int,
    y_pred: int | None,
    *,
    k: int | None = 0,
    detector: str = "a",
    split: str = "mid",
) -> Prediction:
    return Prediction(
        run_id="r",
        detector=detector,
        model="m",
        split=split,
        row_id=row_id,
        k=k,
        n_examples=0,
        seed=0,
        rep=0,
        batch=1,
        format="csv",
        prompt_version="v1",
        prompt_hash="h",
        y_true=y_true,
        y_pred=y_pred,
        p_attack=None if y_pred is None else float(y_pred),
        category_true="dos" if y_true else "normal",
        category_pred=None,
        confidence=None,
        novel_attack=False,
        input_tokens=None,
        output_tokens=None,
        cache_tokens=None,
        reasoning_tokens=None,
        cost_usd=None,
        billed_cost_usd=None,
        latency_e2e_ms=None,
        latency_provider_ms=None,
        time_to_first_token_ms=None,
        train_time_ms=None,
        retries=0,
        error=None,
        request_id="",
        ts_utc="t",
    )


def runs() -> tuple[list[Prediction], list[Prediction]]:
    """Flows 0..5 are attacks, 6..9 normals. A is right where B is wrong on 0, 1,
    2 and 6; B is right where A is wrong on 3; both are wrong on 5 and 7."""
    a_pred = {0: 1, 1: 1, 2: 1, 3: 0, 4: 1, 5: 0, 6: 0, 7: 1, 8: 0, 9: 0}
    b_pred = {0: 0, 1: 0, 2: 0, 3: 1, 4: 1, 5: 0, 6: 1, 7: 1, 8: 0, 9: 0}
    a = [make(i, int(i < 6), a_pred[i]) for i in range(10)]
    b = [make(i, int(i < 6), b_pred[i], detector="b") for i in range(10)]
    return a, b


def test_pair_runs_matches_by_flow_and_k_and_drops_unmatched() -> None:
    a, b = runs()
    pairs = compare.pair_runs([*a, make(99, 1, 1, k=8)], b)
    assert set(pairs) == {0}
    assert len(pairs[0]) == 10
    assert all(left.row_id == right.row_id for left, right in pairs[0])


def test_score_counts_only_discordant_pairs() -> None:
    a, b = runs()
    assert compare.score(compare.pair_runs(a, b)[0]) == (4, 1)


def test_mcnemar_exact_is_two_sided_and_none_without_discordance() -> None:
    assert compare.mcnemar_exact(0, 0) is None
    assert compare.mcnemar_exact(5, 5) == 1.0
    assert compare.mcnemar_exact(4, 1) == pytest.approx(2 * 6 / 32)
    assert compare.mcnemar_exact(10, 0) == pytest.approx(2 / 1024)


def test_bootstrap_delta_brackets_the_observed_difference() -> None:
    a, b = runs()
    pairs = compare.pair_runs(a, b)[0]
    observed = compare.delta_f1(pairs)
    low, high = compare.bootstrap_delta(pairs, resamples=200, seed=1)
    assert observed is not None and low is not None and high is not None
    assert low <= observed <= high


def test_bootstrap_delta_is_none_when_f1_is_undefined() -> None:
    pairs = [(make(0, 0, 0), make(0, 0, 0))]
    assert compare.bootstrap_delta(pairs, resamples=5) == (None, None)


def test_compare_orders_k_and_fills_every_field() -> None:
    a, b = runs()
    a_k8 = [make(i, 1, 1, k=8) for i in range(2)]
    b_k8 = [make(i, 1, 0, k=8) for i in range(2)]
    results = compare.compare([*a_k8, *a], [*b_k8, *b], resamples=50)
    assert [result.k for result in results] == [0, 8]
    first = results[0]
    assert (first.pairs, first.discordant, first.a_right, first.b_right) == (
        10,
        5,
        4,
        1,
    )
    assert first.f1_a == pytest.approx(8 / 11)
    assert first.f1_b == pytest.approx(4 / 10)
    assert first.delta_f1 == pytest.approx(8 / 11 - 4 / 10)


def test_report_prints_a_table_with_the_detector_names(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_a, run_b = tmp_path / "a", tmp_path / "b"
    a, b = runs()
    for prediction in a:
        RunFiles(run_a).append(prediction, {})
    for prediction in b:
        RunFiles(run_b).append(prediction, {})

    results = compare.report(run_a, run_b, resamples=20)

    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith(
        "| k | pairs | discordant | a right | b right |"
    )
    assert len(results) == 1


def test_report_rejects_empty_runs_and_different_splits(tmp_path: Path) -> None:
    run_a, run_b = tmp_path / "a", tmp_path / "b"
    RunFiles(run_a).append(runs()[0][0], {})
    with pytest.raises(ValueError, match="at least one prediction"):
        compare.report(run_a, run_b, resamples=1)
    RunFiles(run_b).append(make(0, 1, 1, split="hard"), {})
    with pytest.raises(ValueError, match="different splits"):
        compare.report(run_a, run_b, resamples=1)
