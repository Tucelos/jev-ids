"""Summary metrics over synthetic predictions."""

from __future__ import annotations

from pathlib import Path

import pytest

from somids import metrics
from somids.records import Prediction, RunFiles


def make(  # noqa: PLR0913
    row_id: int,
    y_true: int,
    p_attack: float | None,
    *,
    k: int | None = 1,
    seed: int = 0,
    rep: int = 0,
    novel: bool = False,
    error: str | None = None,
    detector: str = "jev",
) -> Prediction:
    return Prediction(
        run_id="r",
        detector=detector,
        model="m",
        split="internal",
        row_id=row_id,
        k=k,
        n_examples=0 if k is None else 5 * k,
        seed=seed,
        rep=rep,
        batch=1,
        format="csv",
        prompt_version="v1",
        prompt_hash="h",
        y_true=y_true,
        y_pred=None if p_attack is None else int(p_attack >= 0.5),
        p_attack=p_attack,
        category_true="dos" if y_true else "normal",
        category_pred=None,
        confidence=None,
        novel_attack=novel,
        input_tokens=100,
        output_tokens=10,
        cache_tokens=None,
        reasoning_tokens=None,
        cost_usd=None if error else 0.001,
        billed_cost_usd=0.0,
        latency_e2e_ms=None if error else 500.0,
        latency_provider_ms=None if error else 200.0,
        time_to_first_token_ms=None,
        train_time_ms=None,
        retries=0,
        error=error,
        request_id=f"q{row_id}-{seed}-{rep}",
        ts_utc="t",
    )


def test_f1_and_recalls_treat_errors_as_normal() -> None:
    cell = [
        make(1, 1, 0.9, novel=True),
        make(2, 1, 0.2, novel=True),
        make(3, 1, None, error="HTTP 429"),
        make(4, 0, 0.1),
        make(5, 0, 0.7),
    ]
    # tp = 1 (row 1), fp = 1 (row 5), fn = 2 (rows 2 and 3): f1 = 2 / (2 + 1 + 2)
    assert metrics.f1_attack(cell) == pytest.approx(0.4)
    assert metrics.recall(cell, novel=True) == 0.5
    assert metrics.recall(cell, novel=False) == 0.0
    assert metrics.f1_attack([make(4, 0, 0.1)]) is None
    assert metrics.recall([make(4, 0, 0.1)], novel=True) is None


def test_summarize_aggregates_cells_and_stability() -> None:
    predictions = [
        make(1, 1, 0.9, seed=0, rep=0),
        make(2, 0, 0.1, seed=0, rep=0),
        make(1, 1, 0.4, seed=0, rep=1),
        make(2, 0, 0.1, seed=0, rep=1),
        make(1, 1, 0.9, seed=1, rep=0),
        make(2, 0, 0.6, seed=1, rep=0),
        make(1, 1, None, k=0, error="boom"),
    ]
    summaries = metrics.summarize(predictions)
    assert [s.k for s in summaries] == [0, 1]
    zero_shot, one_shot = summaries
    assert zero_shot.error_rate == 1.0
    assert zero_shot.cost_usd_per_1m is None
    assert one_shot.cells == 3
    assert one_shot.flows == 2
    assert one_shot.f1_mean == pytest.approx((1.0 + 0.0 + 2 / 3) / 3)
    assert one_shot.f1_sd is not None
    assert one_shot.cost_usd_per_1m == pytest.approx(1000.0)
    assert one_shot.latency_e2e_ms_mean == 500.0
    # Flow 1 flips between rep 0 and rep 1 for seed 0; flow 2 does not.
    assert one_shot.verdict_flip_rate == 0.5
    # Flow 1's sd across reps averaged with flow 2's sd of 0.
    expected_sd = metrics.sd_of([0.9, 0.4])
    assert expected_sd is not None
    assert one_shot.p_attack_sd_mean == pytest.approx(expected_sd / 2)


def test_stability_is_undefined_without_repetitions() -> None:
    summary = metrics.summarize([make(1, 1, 0.9), make(2, 0, 0.1)])[0]
    assert summary.verdict_flip_rate is None
    assert summary.p_attack_sd_mean is None
    assert summary.f1_sd is None


def test_report_prints_markdown_and_writes_csv(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    files = RunFiles(tmp_path / "run-a")
    for prediction in [
        make(1, 1, 0.9),
        make(2, 0, 0.1),
        make(3, 0, 0.8, detector="rf"),
    ]:
        files.append(prediction, {})

    target = metrics.report([tmp_path / "run-a"])

    out = capsys.readouterr().out
    assert out.startswith("| detector | k | cells | f1_mean |")
    assert "| jev | 1 | 1 | 1 |" in out
    assert "| rf | 1 | 1 | 0 |" in out
    assert target == tmp_path / "run-a" / "summary.csv"
    lines = target.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("detector,model,split,k,")
    assert len(lines) == 3


def test_report_over_several_runs_writes_next_to_them(tmp_path: Path) -> None:
    for name in ("run-a", "run-b"):
        RunFiles(tmp_path / name).append(make(1, 1, 0.9), {})
    target = metrics.report([tmp_path / "run-a", tmp_path / "run-b"])
    assert target == tmp_path / "summary.csv"
    assert metrics.to_markdown([]).count("\n") == 2
