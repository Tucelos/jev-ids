"""The run loop with a fake detector: order, resume, guard and files."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from somids import dataset, run
from somids.detectors.base import Outcome
from somids.prompt import load_prompt

TRAIN = [
    dataset.Flow(row_id=i, text=",".join([str(i)] * 41), attack_name=name, difficulty=1)
    for i, name in enumerate(
        [
            "normal",
            "normal",
            "neptune",
            "neptune",
            "satan",
            "satan",
            "phf",
            "phf",
            "perl",
            "perl",
        ]
    )
]
FLOWS = [
    dataset.Flow(
        row_id=100 + i, text=",".join(["7"] * 41), attack_name=name, difficulty=1
    )
    for i, name in enumerate(["normal", "apache2", "neptune"])
]


class FakeDetector:
    """Counts calls and records the Examples it saw."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, int]] = []

    @property
    def name(self) -> str:
        return "fake"

    @property
    def model(self) -> str:
        return "fake-1"

    def predict(
        self, flows: Sequence[dataset.Flow], examples: Sequence[dataset.Example]
    ) -> list[Outcome]:
        self.calls.append((len(flows), len(examples)))
        return [
            Outcome(
                flow=flow,
                model=self.model,
                p_attack=float(flow.is_attack),
                category_pred=flow.category,
                confidence=None,
                probabilities=None,
                input_tokens=10,
                output_tokens=1,
                cache_tokens=None,
                reasoning_tokens=None,
                cost_usd=0.5,
                billed_cost_usd=0.0,
                latency_e2e_ms=1.0,
                latency_provider_ms=None,
                time_to_first_token_ms=None,
                train_time_ms=None,
                retries=0,
                error=None,
                request_id=f"req-{flow.row_id}",
            )
            for flow in flows
        ]


def test_execute_covers_every_cell_and_writes_the_three_files(tmp_path: Path) -> None:
    spec = run.RunSpec(
        detector="fake", split="smoke", ks=(0, 1), seeds=(0,), reps=2, batch=2
    )
    detector = FakeDetector()

    run_dir = run.execute(
        spec, detector, load_prompt("v1"), run.RunData(FLOWS, TRAIN), tmp_path
    )

    predictions = list(run.RunFiles(run_dir).read_predictions())
    assert len(predictions) == 2 * 1 * 2 * 3
    assert detector.calls == [
        (2, 0),
        (1, 0),
        (2, 0),
        (1, 0),
        (2, 5),
        (1, 5),
        (2, 5),
        (1, 5),
    ]
    assert {p.n_examples for p in predictions} == {0, 5}
    assert (run_dir / "config.json").exists()
    assert (run_dir / "responses.jsonl").exists()
    assert run_dir.name.endswith("-fake-smoke")


def test_resume_skips_what_is_already_written(tmp_path: Path) -> None:
    first = run.RunSpec(detector="fake", split="smoke", ks=(0,), seeds=(0,), reps=1)
    run_dir = run.execute(
        first, FakeDetector(), load_prompt("v1"), run.RunData(FLOWS, TRAIN), tmp_path
    )
    resumed = run.RunSpec(
        detector="fake",
        split="smoke",
        ks=(0, 1),
        seeds=(0,),
        reps=1,
        resume=run_dir.name,
    )
    detector = FakeDetector()

    run.execute(
        resumed, detector, load_prompt("v1"), run.RunData(FLOWS, TRAIN), tmp_path
    )

    assert detector.calls == [(1, 5), (1, 5), (1, 5)]
    assert len(list(run.RunFiles(run_dir).read_predictions())) == 6


def test_paper_split_requires_the_flag(tmp_path: Path) -> None:
    spec = run.RunSpec(detector="fake", split="paper", ks=(0,), seeds=(0,))
    with pytest.raises(PermissionError, match="--allow-paper"):
        run.execute(
            spec, FakeDetector(), load_prompt("v1"), run.RunData(FLOWS, TRAIN), tmp_path
        )


def test_progress_line_counts_errors_and_cost() -> None:
    progress = run.Progress()
    outcome = FakeDetector().predict(FLOWS[:1], [])[0]
    progress.add([outcome])
    assert progress.line() == "calls=1 predictions=1 errors=0 list_cost_usd=0.5000"


def test_build_detector_knows_jev_and_rejects_unknown_names() -> None:
    prompt = load_prompt("v1")
    assert (
        run.build_detector(run.RunSpec("jev", "smoke", (0,), (0,)), prompt).name
        == "jev"
    )
    with pytest.raises(NotImplementedError):
        run.build_detector(run.RunSpec("llm:deepseek", "smoke", (0,), (0,)), prompt)


def test_chunks_and_run_id() -> None:
    assert [len(c) for c in run.chunks(FLOWS, 2)] == [2, 1]
    assert [len(c) for c in run.chunks(FLOWS, 0)] == [1, 1, 1]
    spec = run.RunSpec("llm:deepseek", "internal", (0,), (0,))
    assert (
        run.make_run_id(spec, datetime(2026, 9, 20, 18, 0, 0, tzinfo=UTC))
        == "20260920T180000Z-llm-deepseek-internal"
    )


def test_k_all_uses_every_train_flow_and_is_rf_only(tmp_path: Path) -> None:
    examples = run.examples_for(TRAIN, None, seed=0)
    assert len(examples) == len(TRAIN)
    assert run.examples_for(TRAIN, 0, seed=0) == []
    spec = run.RunSpec(detector="fake", split="smoke", ks=(None,), seeds=(0,))
    with pytest.raises(ValueError, match="only meaningful for the Random Forest"):
        run.execute(
            spec, FakeDetector(), load_prompt("v1"), run.RunData(FLOWS, TRAIN), tmp_path
        )


def test_rf_cannot_start_at_zero_shot() -> None:
    class RfLike(FakeDetector):
        @property
        def name(self) -> str:
            return "rf"

    spec = run.RunSpec(detector="rf", split="smoke", ks=(0, 1), seeds=(0,))
    with pytest.raises(ValueError, match="starts at k = 1"):
        run.check_ks(spec, RfLike())
