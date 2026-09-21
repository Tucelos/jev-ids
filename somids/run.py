"""One run: a Detector over one split, cell by cell, Flow by Flow.

In reading order:

- `RunSpec`: what the CLI resolved for one run.
- `load_prompt`: any prompt file as text plus its sha256; Jev and the LLMs load their files (`jev.json`, `llm.md`) through it alike.
- `build_detector` and `check_spec`: the Detector named in the spec, and the two combinations of Detector and k that would only waste calls.
- `sample_examples`: k Examples per Category, seeded and nested across k.
- `execute`: the loop itself, cell by cell and Flow by Flow, and the three files of the run.
- `run_from_spec`: the CLI entry that strings the above together.

The loop runs k outermost, then seed, then rep, then every Flow of the split, so the prompt prefix stays constant for as long as possible
and provider prefix caches get their best chance. One request judges one Flow (B = 1). A call that fails ends as a row with `error`, never
as a crash, and the run goes on.
"""

import hashlib
import itertools
import random
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from somids import ROOT, dataset
from somids.dataset import Config, Flow
from somids.detectors import random_forest
from somids.detectors.jev import JevDetector
from somids.detectors.llm import LLMDetector
from somids.detectors.random_forest import RandomForestDetector
from somids.records import append_prediction, complete_prediction, write_config

RESULTS_DIR = ROOT / "results"

# The three detectors share no base class; the run loop only needs `name`, `model`, `prompt_hash` and `predict`, which each of them has.
Detector = JevDetector | LLMDetector | RandomForestDetector


@dataclass(frozen=True)
class RunSpec:
    """Everything the CLI resolved for one run; a parameter bundle, nothing more.

    Attributes:
        detector: `jev`, `llm:deepseek`, `llm:openai` or `random_forest`.
        dataset: the card of the dataset, `data/<name>/dataset.json`.
        split: the split to judge, a file under `data/<name>/splits/`.
        k_values: Examples per Category to try; None means the whole pool (rf).
        seeds: the seeds of the Example draws.
        reps: how often each (k, seed) cell is repeated, for stability.
        model_id: the provider model, for the LLM detectors; None means default.
        results_dir: where run directories are created.
    """

    detector: str
    dataset: Path
    split: str
    k_values: tuple[int | None, ...]
    seeds: tuple[int, ...]
    reps: int = 1
    model_id: str | None = None
    results_dir: Path = RESULTS_DIR


def load_prompt(path: Path) -> dict[str, Any]:
    """A prompt file as `text`, plus the `sha256` of its bytes.

    The hash goes into config.json and into every row as `prompt_hash`, so any change of wording is visible in the records.
    """
    raw_bytes = path.read_bytes()
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    return {"text": raw_bytes.decode("utf-8"), "sha256": sha256}


def build_detector(spec: RunSpec, config: Config) -> Detector:
    """The Detector named in the spec; Jev and the LLMs get their prompt file."""
    prompts = ROOT / "prompts" / config["name"]
    if spec.detector == "jev":
        return JevDetector(load_prompt(prompts / "jev.json"))
    if spec.detector in ("llm:deepseek", "llm:openai"):
        provider = spec.detector.removeprefix("llm:")
        return LLMDetector(load_prompt(prompts / "llm.md"), provider, spec.model_id)
    if spec.detector == "random_forest":
        # The one-hot vocabulary comes from the whole pool, never from the Examples.
        pool = dataset.load_split(config["dir"] / "pool.csv", config)
        return RandomForestDetector(random_forest.vocabulary(pool, config), config["benign"])
    raise NotImplementedError(f"detector {spec.detector!r} is not implemented")


def check_spec(spec: RunSpec, detector_name: str) -> None:
    """Refuse what would waste calls.

    k = all exists only for the Random Forest, which in turn cannot train on nothing at k = 0.
    """
    if None in spec.k_values and detector_name != "random_forest":
        raise ValueError("k = all is only meaningful for the Random Forest")
    if detector_name == "random_forest" and 0 in spec.k_values:
        raise ValueError("the Random Forest starts at k = 1")


def sample_examples(train: Sequence[Flow], k: int, seed: int, categories: Sequence[str]) -> list[Flow]:
    """Draw k Examples per Category, at random within each Category.

    Each Category is shuffled by a random stream seeded with `seed` and its name, and its first k Flows are taken; so for one seed the draws
    are nested across k (the Examples of k = 4 are among those of k = 8) and independent of the other Categories. The final order is one
    more seeded shuffle, shared by every Detector, so no Detector sees the Examples grouped by Category. A Category with no Flow in the pool
    (held out as novel) contributes nothing; one with fewer than k Flows raises.
    """
    chosen: list[Flow] = []
    for category in categories:
        pool = [flow for flow in train if flow.category == category]
        if 0 < len(pool) < k:
            raise ValueError(f"category {category!r}: {len(pool)} flows, k = {k} asked")
        random.Random(f"{seed}:{category}").shuffle(pool)  # noqa: S311  # seeded, not secret
        chosen.extend(pool[:k])
    random.Random(f"{seed}:order").shuffle(chosen)  # noqa: S311  # seeded, not secret
    return chosen


def execute(spec: RunSpec, detector: Detector, config: Config, flows: Sequence[Flow], train: Sequence[Flow]) -> Path:
    """Run `detector` over `flows` with Examples drawn from `train`; the run directory.

    `config.json` is written first, with what is needed to trace the run to its exact inputs: the resolved spec, the card's name and hash,
    the prompt hash. Then each (k, seed, rep) cell judges every Flow of the split, one call and one row each, and closes with a progress
    line counting the Flows judged and the rows that came back with an error.
    """
    check_spec(spec, detector.name)
    # `<UTC timestamp>-<dataset>-<detector>-<split>` names the directory under results/; the colon of `llm:openai` is not a path character.
    started = datetime.now(UTC)
    run_id = f"{started:%Y%m%dT%H%M%SZ}-{spec.dataset.parent.name}-{spec.detector.replace(':', '-')}-{spec.split}"
    run_dir = spec.results_dir / run_id
    write_config(
        run_dir,
        {
            "run_id": run_id,
            "spec": asdict(spec),
            "detector": detector.name,
            "model": detector.model,
            "dataset": {"name": config["name"], "sha256": config["sha256"]},
            "prompt_hash": detector.prompt_hash,
            "started_at": started.isoformat(timespec="seconds"),
        },
    )
    # The fields every row of this run shares; a cell adds k, seed, rep and the number of Examples.
    run_fields: dict[str, Any] = {
        "run_id": run_id,
        "dataset": config["name"],
        "detector": detector.name,
        "model": detector.model,
        "split": spec.split,
        "prompt_hash": detector.prompt_hash,
    }
    for k, seed in itertools.product(spec.k_values, spec.seeds):
        # Drawn once per (k, seed) and reused by every rep, so the Random Forest keeps its fit across the repetitions. k = None is
        # the whole pool.
        examples = list(train) if k is None else sample_examples(train, k, seed, config["categories"])
        for repetition in range(spec.reps):
            cell = {**run_fields, "k": k, "seed": seed, "repetition": repetition, "n_examples": len(examples)}
            errors = 0
            for flow in flows:
                prediction = complete_prediction(detector.predict(flow, examples), flow, cell)
                append_prediction(run_dir, prediction)
                errors += int(prediction.get("error") is not None)
            print(f"k={k} seed={seed} rep={repetition} flows={len(flows)} errors={errors}")
    print(f"done: {run_dir}")
    return run_dir


def run_from_spec(spec: RunSpec) -> Path:
    """The CLI entry: load the card, the split and the pool, build the detector, run."""
    config = dataset.load_config(spec.dataset)
    flows = dataset.load_split(config["dir"] / "splits" / f"{spec.split}.csv", config)
    train = dataset.load_split(config["dir"] / "pool.csv", config)
    return execute(spec, build_detector(spec, config), config, flows, train)
