"""The main loop of a run: k, then seed, then rep, then the Flows of the split,
one request at a time; detectors do their own retries and timing.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from somids import dataset
from somids.dataset import Example, Flow, RowFormat
from somids.detectors import jev
from somids.detectors.base import Detector, Outcome
from somids.prices import load_prices
from somids.prompt import Prompt, load_prompt
from somids.records import Key, RunContext, RunFiles, to_prediction

RESULTS_DIR = dataset.ROOT / "results"
PROGRESS_EVERY = 50


@dataclass(frozen=True, slots=True)
class RunSpec:
    """Everything the CLI resolved for one run."""

    detector: str
    split: str
    ks: tuple[int, ...]
    seeds: tuple[int, ...]
    reps: int = 1
    batch: int = 1
    fmt: RowFormat = "csv"
    prompt_version: str = "v1"
    model: str | None = None
    resume: str | None = None
    allow_paper: bool = False


@dataclass(frozen=True, slots=True)
class RunData:
    """Flows to judge and Train+ Flows to draw Examples from; None means load."""

    flows: Sequence[Flow] | None = None
    train: Sequence[Flow] | None = None


@dataclass(frozen=True, slots=True)
class Cell:
    """One (k, seed, rep) combination of the run."""

    k: int
    seed: int
    rep: int


@dataclass(slots=True)
class Progress:
    calls: int = 0
    predictions: int = 0
    errors: int = 0
    cost_usd: float = 0.0

    def add(self, outcomes: Sequence[Outcome]) -> None:
        self.calls += 1
        for outcome in outcomes:
            self.predictions += 1
            self.errors += outcome.error is not None
            self.cost_usd += outcome.cost_usd or 0.0

    def line(self) -> str:
        return (
            f"calls={self.calls} predictions={self.predictions} errors={self.errors} "
            f"list_cost_usd={self.cost_usd:.4f}"
        )


@dataclass(slots=True)
class RunState:
    """Mutable state of a run in progress."""

    files: RunFiles
    done: set[Key]
    progress: Progress = field(default_factory=Progress)


def make_run_id(spec: RunSpec, now: datetime) -> str:
    detector = spec.detector.replace(":", "-")
    return f"{now:%Y%m%dT%H%M%SZ}-{detector}-{spec.split}"


def build_detector(spec: RunSpec, prompt: Prompt) -> Detector:
    if spec.detector == "jev":
        return jev.JevDetector(prompt=prompt, fmt=spec.fmt)
    msg = f"detector {spec.detector!r} is not implemented yet"
    raise NotImplementedError(msg)


def chunks(flows: Sequence[Flow], size: int) -> Iterator[Sequence[Flow]]:
    step = max(size, 1)
    for start in range(0, len(flows), step):
        yield flows[start : start + step]


def run_config(
    spec: RunSpec, run_id: str, prompt: Prompt, detector: Detector
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "spec": asdict(spec),
        "detector": detector.name,
        "model": detector.model,
        "prompt": {"version": prompt.version, "sha256": prompt.sha256},
        "jev_question_templates": {
            "is_attack": jev.IS_ATTACK_TEMPLATE,
            "category": jev.CATEGORY_TEMPLATE,
            "examples_clause": jev.EXAMPLES_CLAUSE,
        },
        "category_table_version": dataset.CATEGORY_TABLE_VERSION,
        "prices_date": load_prices().date,
        "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }


@dataclass(slots=True)
class Plan:
    """A run after its inputs were resolved and its files opened."""

    spec: RunSpec
    detector: Detector
    prompt: Prompt
    run_id: str
    state: RunState
    flows: list[Flow]
    train: Sequence[Flow]


def execute(
    spec: RunSpec,
    detector: Detector,
    prompt: Prompt,
    data: RunData | None = None,
    results_dir: Path = RESULTS_DIR,
) -> Path:
    """Run `detector` over the split and return the run directory."""
    if spec.split == "paper" and not spec.allow_paper:
        msg = "the paper split needs --allow-paper"
        raise PermissionError(msg)
    plan = _prepare(spec, detector, prompt, data or RunData(), results_dir)
    for k, seed in itertools.product(spec.ks, spec.seeds):
        _run_k_seed(plan, k, seed)
    print(f"done: {plan.state.files.run_dir} {plan.state.progress.line()}")
    return plan.state.files.run_dir


def _prepare(
    spec: RunSpec, detector: Detector, prompt: Prompt, data: RunData, results_dir: Path
) -> Plan:
    run_id = spec.resume or make_run_id(spec, datetime.now(UTC))
    files = RunFiles(results_dir / run_id)
    state = RunState(files, files.existing_keys() if spec.resume else set())
    files.write_config(run_config(spec, run_id, prompt, detector))
    flows = (
        list(data.flows) if data.flows is not None else dataset.load_split(spec.split)
    )
    return Plan(
        spec, detector, prompt, run_id, state, flows, _train_if_needed(spec, data.train)
    )


def _run_k_seed(plan: Plan, k: int, seed: int) -> None:
    """Every rep of one (k, seed): the Examples are drawn once and reused."""
    examples = dataset.sample_examples(plan.train, k, seed) if k else []
    for rep in range(plan.spec.reps):
        context = _context(
            plan.spec, plan.run_id, plan.detector, Cell(k, seed, rep), plan.prompt
        )
        pending = [
            f for f in plan.flows if (f.row_id, k, seed, rep) not in plan.state.done
        ]
        _run_cell(plan.detector, pending, examples, context, plan.state)


def _train_if_needed(spec: RunSpec, train: Sequence[Flow] | None) -> Sequence[Flow]:
    if train is not None:
        return train
    return dataset.load_train() if any(spec.ks) else []


def _context(
    spec: RunSpec, run_id: str, detector: Detector, cell: Cell, prompt: Prompt
) -> RunContext:
    return RunContext(
        run_id=run_id,
        detector=detector.name,
        split=spec.split,
        k=cell.k,
        n_examples=cell.k * len(dataset.CATEGORIES),
        seed=cell.seed,
        rep=cell.rep,
        batch=spec.batch,
        format=spec.fmt,
        prompt_version=prompt.version,
        prompt_hash=prompt.sha256,
    )


def _run_cell(
    detector: Detector,
    pending: Sequence[Flow],
    examples: Sequence[Example],
    context: RunContext,
    state: RunState,
) -> None:
    """One (k, seed, rep) cell: every pending Flow, `batch` at a time."""
    for chunk in chunks(pending, context.batch):
        outcomes = detector.predict(chunk, examples)
        ts_utc = datetime.now(UTC).isoformat(timespec="milliseconds")
        for outcome in outcomes:
            state.files.append(to_prediction(outcome, context, ts_utc), outcome.raw)
        state.progress.add(outcomes)
        if state.progress.calls % PROGRESS_EVERY == 0:
            print(
                f"k={context.k} seed={context.seed} rep={context.rep} "
                f"{state.progress.line()}"
            )


def run_from_spec(spec: RunSpec) -> Path:
    prompt = load_prompt(spec.prompt_version)
    return execute(spec, build_detector(spec, prompt), prompt)
