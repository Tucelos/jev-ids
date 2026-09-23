"""What one Run of the Arena writes down: the Round record and the four files of the Run directory.

In reading order:

- `EvasionRecord` and `AttackRecord`: what the attacker did to one Flow, and to the Round's Flows together.
- `AnalystRecord`, `ShortlistRecord`, `CuratorRecord`, `GateRecord`: the other four parts of a Round.
- `RoundRecord` and `to_dict`: the whole Round, and the exact line it writes to `rounds.jsonl`.
- `Inputs`: the sha256 of everything one Run was made from.
- `Stamp` and `arena_fields`: the three fields the Arena adds to an ordinary Prediction row.
- `code_commit`: the commit the Run's code was at, `-dirty` when the working tree was.
- `run_id` and `start_run`: the Run directory and its `config.json`, written before the first call.
- `append_line`, `append_round` and `append_context`: one line appended to `rounds.jsonl` or to `contexts.jsonl`.
- `read_rounds` and `sha256`: the Rounds of a finished Run, and the hash of one input file.

The discipline is `run.execute`'s, for the same reason: `config.json` is written before a single call is made, and every other line is
appended the moment it exists, so a Run killed by a quota error, a crash or a laptop lid loses at most the Round it was in. A Round is
expensive -- hundreds of Detector calls and a curator call -- and one that buffered its Rounds to the end would lose all of them at once.

Four files, because they answer four different questions. `config.json` says what was run; `rounds.jsonl` says what happened, one line per
(seed, Round); `predictions.jsonl` carries the Predictions themselves in the ordinary shape of `jev_ids.records`, so `jev_ids.metrics` reads
an Arena Run with no special case, plus the three fields that say which Round and which Context version wrote a row; `contexts.jsonl` keeps
every Context ever proposed, accepted or not, so a rejected proposal stays readable beside the one that beat it.
"""

import hashlib
import json
import subprocess
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jev_ids import ROOT
from jev_ids.arena.budget import Budget
from jev_ids.arena.config import ArenaConfig
from jev_ids.arena.context import Context
from jev_ids.arena.gate import GateVerdict
from jev_ids.records import write_config

# The three stages a Prediction of an Arena Run can come from: the Round's own traffic, and the two sides of the gate. The attacker's
# probes are not among them: they are the same Flow judged up to `max_queries_per_flow` times under mutations that were then thrown away,
# and writing them here would multiply a Flow's rows and quietly move every rate `jev_ids.metrics` computes.
STAGES = ("traffic", "gate-candidate", "gate-incumbent")


@dataclass(frozen=True)
class EvasionRecord:
    """What the attacker did to one attack Flow, as the Round record keeps it.

    Attributes:
        row_id: the Flow attacked; a mutated Flow keeps its parent's row_id, so this is also the row_id of every Prediction about it.
        evaded: whether the Detector stopped alerting on it.
        bucket: the donor bucket of the Strategy reported, which for a Flow that did not evade is the best one tried; None when the
            attacker reports no Strategy at all.
        padding_bytes: that Strategy's padding, or None when there is no Strategy.
        added_seconds: that Strategy's added latency, or None when there is no Strategy.
        queries: Detector calls the attacker spent on this Flow.
        start_p_attack: what the Detector gave the Flow before the attacker touched it, or None when the first call failed.
        final_p_attack: what it gave the Flow the attacker settled on, or None when that call failed.
    """

    row_id: int
    evaded: bool
    bucket: str | None
    padding_bytes: int | None
    added_seconds: int | None
    queries: int
    start_p_attack: float | None
    final_p_attack: float | None


@dataclass(frozen=True)
class AttackRecord:
    """One Round's attack phase: how many Flows were attacked, how many got through, and at what price.

    Attributes:
        flows: attack Flows the attacker was given this Round.
        evaded: how many of them the Detector stopped alerting on.
        evasion_rate: `evaded / flows`, or None when no Flow was attacked.
        queries: Detector calls the attacker spent in total, the largest line of a Round's budget.
        strategies: one entry per attacked Flow, in the order they were attacked.
    """

    flows: int
    evaded: int
    evasion_rate: float | None
    queries: int
    strategies: tuple[EvasionRecord, ...]


@dataclass(frozen=True)
class AnalystRecord:
    """How much of one Round the simulated analyst actually looked at.

    The design doc asks for these counts beside the curator's Evidence for one reason: a curator can conclude a Category is rare when the
    analyst simply never reached it, and only the number of Flows reviewed tells the two apart.

    Attributes:
        reviewed: Flows the analyst labeled this Round, alerts and quiet together.
        alerts_reviewed: how many of them had raised an alert; the queue is truncated at `alert_budget`.
        quiet_reviewed: how many were sampled from the Flows that raised none; the only channel through which a miss becomes knowledge.
        poisoned: how many of the labels the curator was given this Round had been flipped by THREAT A2.
    """

    reviewed: int
    alerts_reviewed: int
    quiet_reviewed: int
    poisoned: int


@dataclass(frozen=True)
class ShortlistRecord:
    """How the Round drew the Pool Flows it offered the curator as candidate Examples.

    `how` is written down because the draw decides the experiment: a shortlist drawn uniformly over the whole Pool cripples the heuristic
    baseline and flatters the LLM, and the headline result would then be an artefact of this one line.

    Attributes:
        size: how many Pool Flows were offered.
        how: the rule that drew them, in words.
    """

    size: int
    how: str


@dataclass(frozen=True)
class CuratorRecord:
    """What the curator was and what it answered this Round.

    Attributes:
        kind: `llm` or `heuristic`, the arm of the experiment this Run is.
        model: the provider's model id, empty for the heuristic baseline.
        proposals: how many candidate Contexts came back; zero when the call failed.
        error: what went wrong on the call, or None; an LLM curator that failed proposes nothing and the Round keeps its Context.
        notes: the curator's own reason per Proposal, with whatever `curator.resolve` had to repair appended to it.
    """

    kind: str
    model: str
    proposals: int
    error: str | None
    notes: tuple[str, ...]


@dataclass(frozen=True)
class GateRecord:
    """One gate decision: the version it was about and the Verdict it reached.

    Attributes:
        version: the version the proposal would have become; it is written down whether or not the proposal was kept.
        verdict: the whole `GateVerdict`, its reason and every number it was taken on.
    """

    version: int
    verdict: GateVerdict


@dataclass(frozen=True)
class RoundRecord:
    """Everything one (seed, Round) did, the one object appended to `rounds.jsonl`.

    Attributes:
        run_id: the Run directory's name, so a line can be traced back to its config.
        seed: the seed whose lineage this Round belongs to; each seed carries its own Context.
        round_index: the Round, counting from one.
        context: the Context in force while the Round's traffic was judged.
        prompt_hash: that Context rendered onto the template, the hash every traffic row carries.
        attack: the attacker's Round.
        analyst: the analyst's Round.
        shortlist: the Pool Flows offered to the curator.
        curator: the curator's Round.
        gate: one decision per proposal, in the order they were judged.
        accepted_version: the version in force after the gate; the incumbent's own when nothing was accepted.
        budget: what the Run had spent when the Round closed.
    """

    run_id: str
    seed: int
    round_index: int
    context: Context
    prompt_hash: str
    attack: AttackRecord
    analyst: AnalystRecord
    shortlist: ShortlistRecord
    curator: CuratorRecord
    gate: tuple[GateRecord, ...]
    accepted_version: int
    budget: Mapping[str, int]

    def to_dict(self) -> dict[str, Any]:
        """This Round as the JSON object `rounds.jsonl` holds, one line.

        `round` and not `round_index` in the file: the Python name avoids the builtin, the JSON name is the one the design doc fixed and
        the report reads.
        """
        return {
            "run_id": self.run_id,
            "seed": self.seed,
            "round": self.round_index,
            "context": self.context.to_dict(),
            "prompt_hash": self.prompt_hash,
            "attack": {**asdict(self.attack), "strategies": [asdict(item) for item in self.attack.strategies]},
            "analyst": asdict(self.analyst),
            "shortlist": asdict(self.shortlist),
            "curator": {**asdict(self.curator), "notes": list(self.curator.notes)},
            "gate": [{"version": item.version, **asdict(item.verdict)} for item in self.gate],
            "accepted_version": self.accepted_version,
            "budget": dict(self.budget),
        }


@dataclass(frozen=True)
class Inputs:
    """The sha256 of everything one Run was made from, so a Round can be traced to the exact bytes that produced it.

    The Card's hash does not cover the Flows that were judged and none of them covers the prompt, so each is hashed on its own; a Run whose
    numbers surprise a reader is read from here first. Every field is None when the file it names was not there.

    Attributes:
        dataset: the Card, `data/<name>/dataset.json`.
        learn_split: the Split the Rounds are played on.
        gate_split: the held-out Split the gate scores on.
        prompt: the Detector's request template, before any Context is rendered onto it.
        curator_prompt: `prompts/arena/curator.md`, or None for the heuristic baseline, which reads no prompt.
        mutations: the constraint model the attacker obeys, or None when the Dataset has none.
    """

    dataset: str | None
    learn_split: str | None
    gate_split: str | None
    prompt: str | None
    curator_prompt: str | None
    mutations: str | None


@dataclass(frozen=True)
class Stamp:
    """Which Round and which Context version a Prediction came from, and which side of the Round.

    A parameter bundle rather than three more arguments on every call that writes a row.

    Attributes:
        round_index: the Round that judged the Flow.
        context_version: the version of the Context it was judged under.
        stage: one of `STAGES`.
    """

    round_index: int
    context_version: int
    stage: str


def arena_fields(cell: Mapping[str, Any], stamp: Stamp) -> dict[str, Any]:
    """The run fields of one Prediction with the three the Arena adds to them.

    The row stays the ordinary shape of `jev_ids.records`, so `jev_ids.metrics` reads it unchanged; the three extra keys are what lets a
    reader cut the same rows by Round, by Context version and by which side of the gate wrote them.
    """
    return {**cell, "round": stamp.round_index, "context_version": stamp.context_version, "arena_stage": stamp.stage}


def code_commit() -> str:
    """The commit the code was at, with `-dirty` when the working tree had uncommitted changes."""
    described = subprocess.run(  # noqa: S603  # constant arguments
        ["git", "describe", "--always", "--dirty", "--abbrev=40"],  # noqa: S607  # git is on PATH by assumption, as in `run.execute`
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    return described.stdout.strip()


def run_id(started: datetime, config: ArenaConfig) -> str:
    """`<UTC timestamp>-<dataset>-<detector>-<curator>`, the name of the Run directory.

    The timestamp keeps its microseconds, as `run.execute`'s does, so two Runs launched together never share a directory; the three names
    after it are the three things a reader compares two Arena Runs by.
    """
    return f"{started:%Y%m%dT%H%M%S.%fZ}-{config.arena.dataset.parent.name}-{config.detector.name}-{config.curator.kind}"


def start_run(config: ArenaConfig, inputs: Inputs, projection: Mapping[str, Any], budget: Budget) -> Path:
    """Create the Run directory and write `config.json`; the directory.

    Called before the first Detector call and before the pre-flight refusal is even relevant, so a Run that refuses to start still leaves
    the projection that refused it on disk.

    Args:
        config: the resolved knobs of this Run, every section of them.
        inputs: the sha256 of the Card, the Splits, the prompts and the constraint model.
        projection: the pre-flight worst case, as `loop.Projection.to_dict` renders it.
        budget: the Run's Budget, snapshotted as it starts.

    Returns:
        `results/arena/<run_id>/`, created.
    """
    started = datetime.now(UTC)
    identifier = run_id(started, config)
    run_dir = config.arena.results_dir / identifier
    write_config(
        run_dir,
        {
            "run_id": identifier,
            "config": asdict(config),
            "inputs": asdict(inputs),
            "projection": dict(projection),
            "budget": budget.snapshot(),
            "code_commit": code_commit(),
            "started_at": started.isoformat(timespec="seconds"),
        },
    )
    return run_dir


def append_line(path: Path, data: Mapping[str, Any]) -> None:
    """Append one JSON object to a .jsonl file, creating it if it is the first line."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, default=str) + "\n")


def append_round(run_dir: Path, record: RoundRecord) -> None:
    """Append one Round to `rounds.jsonl`, the moment the Round closes."""
    append_line(run_dir / "rounds.jsonl", record.to_dict())


def append_context(run_dir: Path, context: Context, *, seed: int, round_index: int, accepted: bool) -> None:
    """Append one proposed Context to `contexts.jsonl`, accepted or not.

    Keyword arguments for the three fields that are not the Context itself, so a call reads as what it is: this Context, proposed in this
    Round of this seed, and kept or not. A rejected proposal is written for the same reason a rejected hypothesis is: without it the record
    shows only what survived, and a Run that rejected fifteen Contexts looks exactly like one that proposed none.
    """
    append_line(run_dir / "contexts.jsonl", {"seed": seed, "round": round_index, "accepted": accepted, **context.to_dict()})


def read_rounds(run_dir: Path) -> list[dict[str, Any]]:
    """Every Round of a Run directory; an absent file is a Run that wrote none."""
    path = run_dir / "rounds.jsonl"
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sha256(path: Path) -> str | None:
    """The sha256 of a file, or None when it is not there.

    None rather than a raise: a Dataset without a `mutations.json` is a Dataset the mimicry attacker cannot run on, which the attacker says
    in its own words; the Run record should not fail to be written over a file that was never promised.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
