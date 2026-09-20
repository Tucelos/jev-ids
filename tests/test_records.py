"""Prediction records and the run files."""

from __future__ import annotations

from pathlib import Path

from somids import dataset
from somids.detectors.base import Outcome
from somids.records import RunContext, RunFiles, to_prediction

FLOW = dataset.Flow(
    row_id=3,
    text=",".join(["0"] * 41),
    attack_name="apache2",
    difficulty=5,
    novel_attack=True,
)
CONTEXT = RunContext(
    run_id="r1",
    detector="jev",
    split="smoke",
    k=2,
    n_examples=10,
    seed=0,
    rep=0,
    batch=1,
    format="csv",
    prompt_version="v1",
    prompt_hash="abc",
)


def make_outcome(p_attack: float | None, error: str | None = None) -> Outcome:
    return Outcome(
        flow=FLOW,
        model="typesafe-ai/jev",
        p_attack=p_attack,
        category_pred="dos",
        confidence=0.8,
        probabilities={"dos": 0.9},
        input_tokens=100,
        output_tokens=5,
        cache_tokens=None,
        reasoning_tokens=None,
        cost_usd=0.001,
        billed_cost_usd=0.0,
        latency_e2e_ms=500.0,
        latency_provider_ms=200.0,
        time_to_first_token_ms=None,
        train_time_ms=None,
        retries=1,
        error=error,
        request_id="req-1",
        raw={"ok": True},
    )


def test_to_prediction_merges_outcome_and_context() -> None:
    prediction = to_prediction(make_outcome(0.7), CONTEXT, "2026-09-20T00:00:00Z")
    assert prediction.y_true == 1
    assert prediction.y_pred == 1
    assert prediction.category_true == "dos"
    assert prediction.novel_attack
    assert prediction.key == (3, 2, 0, 0)
    assert to_prediction(make_outcome(None, "HTTP 500"), CONTEXT, "t").y_pred is None


def test_run_files_append_and_read_back(tmp_path: Path) -> None:
    files = RunFiles(tmp_path / "run")
    files.write_config({"spec": {"k": [0]}})
    files.append(to_prediction(make_outcome(0.2), CONTEXT, "t1"), {"ok": True})
    files.append(to_prediction(make_outcome(0.9), CONTEXT, "t2"), {"ok": False})

    predictions = list(files.read_predictions())
    assert [p.p_attack for p in predictions] == [0.2, 0.9]
    assert files.existing_keys() == {(3, 2, 0, 0)}
    assert files.config_path.read_text(encoding="utf-8").startswith("{")
    assert files.responses_path.read_text(encoding="utf-8").count("\n") == 2


def test_existing_keys_is_empty_for_a_fresh_run(tmp_path: Path) -> None:
    assert RunFiles(tmp_path / "fresh").existing_keys() == set()
