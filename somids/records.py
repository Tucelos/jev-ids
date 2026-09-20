"""Prediction records and the append-only JSONL files of a run."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from somids.dataset import Flow
from somids.detectors.base import Outcome

PREDICTIONS_FILE = "predictions.jsonl"
RESPONSES_FILE = "responses.jsonl"
CONFIG_FILE = "config.json"

# One Prediction is identified inside a run by these four fields (used by --resume).
Key = tuple[int, int | None, int, int]


@dataclass(frozen=True, slots=True)
class Prediction:
    """One row of predictions.jsonl: a detector's output for one Flow in a run."""

    run_id: str
    detector: str
    model: str
    split: str
    row_id: int
    k: int | None
    n_examples: int
    seed: int
    rep: int
    batch: int
    format: str
    prompt_version: str
    prompt_hash: str
    y_true: int
    y_pred: int | None
    p_attack: float | None
    category_true: str
    category_pred: str | None
    confidence: float | None
    novel_attack: bool
    input_tokens: int | None
    output_tokens: int | None
    cache_tokens: int | None
    reasoning_tokens: int | None
    cost_usd: float | None
    billed_cost_usd: float | None
    latency_e2e_ms: float | None
    latency_provider_ms: float | None
    time_to_first_token_ms: float | None
    train_time_ms: float | None
    retries: int
    error: str | None
    request_id: str
    ts_utc: str

    @property
    def key(self) -> Key:
        return (self.row_id, self.k, self.seed, self.rep)


@dataclass(frozen=True, slots=True)
class RunContext:
    """The run-level values shared by every Prediction of one (k, seed, rep)."""

    run_id: str
    detector: str
    split: str
    k: int | None
    n_examples: int
    seed: int
    rep: int
    batch: int
    format: str
    prompt_version: str
    prompt_hash: str


def to_prediction(outcome: Outcome, context: RunContext, ts_utc: str) -> Prediction:
    flow: Flow = outcome.flow
    return Prediction(
        run_id=context.run_id,
        detector=context.detector,
        model=outcome.model,
        split=context.split,
        row_id=flow.row_id,
        k=context.k,
        n_examples=context.n_examples,
        seed=context.seed,
        rep=context.rep,
        batch=context.batch,
        format=context.format,
        prompt_version=context.prompt_version,
        prompt_hash=context.prompt_hash,
        y_true=int(flow.is_attack),
        y_pred=outcome.y_pred,
        p_attack=outcome.p_attack,
        category_true=flow.category,
        category_pred=outcome.category_pred,
        confidence=outcome.confidence,
        novel_attack=flow.novel_attack,
        input_tokens=outcome.input_tokens,
        output_tokens=outcome.output_tokens,
        cache_tokens=outcome.cache_tokens,
        reasoning_tokens=outcome.reasoning_tokens,
        cost_usd=outcome.cost_usd,
        billed_cost_usd=outcome.billed_cost_usd,
        latency_e2e_ms=outcome.latency_e2e_ms,
        latency_provider_ms=outcome.latency_provider_ms,
        time_to_first_token_ms=outcome.time_to_first_token_ms,
        train_time_ms=outcome.train_time_ms,
        retries=outcome.retries,
        error=outcome.error,
        request_id=outcome.request_id,
        ts_utc=ts_utc,
    )


class RunFiles:
    """The three files of `results/<run_id>/`, opened in append mode."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        run_dir.mkdir(parents=True, exist_ok=True)
        self.predictions_path = run_dir / PREDICTIONS_FILE
        self.responses_path = run_dir / RESPONSES_FILE
        self.config_path = run_dir / CONFIG_FILE

    def write_config(self, config: dict[str, Any]) -> None:
        text = json.dumps(config, indent=2, sort_keys=True) + "\n"
        self.config_path.write_text(text, encoding="utf-8")

    def append(self, prediction: Prediction, raw: dict[str, Any]) -> None:
        with self.predictions_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(prediction)) + "\n")
        with self.responses_path.open("a", encoding="utf-8") as handle:
            record = {"request_id": prediction.request_id, "response": raw}
            handle.write(json.dumps(record) + "\n")

    def existing_keys(self) -> set[Key]:
        """Keys already written, so that `--resume` can skip them."""
        return {prediction.key for prediction in self.read_predictions()}

    def read_predictions(self) -> Iterator[Prediction]:
        if not self.predictions_path.exists():
            return
        with self.predictions_path.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    yield Prediction(**json.loads(line))
