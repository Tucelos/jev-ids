"""One Round of the Arena, played over and over: attack, traffic, labels, learn, gate.

In reading order:

- `Strategy`, `Evasion`, `Judge`, `Attacker` and `Mutate`: the contract of `arena.attacker`, as this module needs it.
- `attacker_module`, `load_donors` and `build_attacker`: that module, imported by name when a Run starts.
- `Projection`, `project`, `preflight` and `refuse_if_short`: the worst case of a whole Run, before its first call.
- `Arena`, `SeedState` and `Draft`: the Run's fixed inputs, what carries from Round to Round, and a Round being filled in.
- `induced_failure`, `as_row`, `Bench`: every Detector call of the Arena, and the only place one is made.
- `build_detector`, `examples_for`, `cell_fields`, `bench_for`, `build_curator`: a Context turned into something that judges Flows.
- `attack_flows`, `attack`, `attack_record`, `Plan`, `plan_of`, `mutate`: the attacker's half of a Round.
- `traffic`, `counts`, `labels`, `observations`, `draw`, `draw_shortlist`, `learn`: the defence's half, up to the curator's answer.
- `judge_split`, `best`, `gate_round`: the gate, one seed at a time.
- `round_steps`, `play_round`, `play_seed`: one Round, one Round written down, one seed's lineage.
- `prepare` and `run_arena`: the Run.

The protocol is `docs/arena/loop-design.md` and this module is its implementation; where the two could drift, the comment says which
way to read them. Three of its rules shape everything below. The gate evaluates one seed at a time, because `gate.pairing` needs each
row_id once per side and pooled seeds lose the McNemar test. The gate's evaluation set is the held-out Split put through THIS Round's
Strategies, because a Context that only memorised the Flows the curator saw must fail there. And the Example shortlist is evidence rather
than plumbing: it is drawn the same way for both curators, and how it was drawn is written into every Round record.

Every Detector call in a Run goes through `Bench.judge`, which is what makes the Budget a real cap rather than a hope: the attacker's
probes, the Round's traffic and both sides of the gate are booked there, and a `BudgetExhausted` ends the Run with the Round it was in
written down instead of a traceback.
"""

import json
import random
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path
from typing import Any, Protocol, cast

from jev_ids import ROOT, dataset, metrics, run
from jev_ids.arena import analyst, gate
from jev_ids.arena.analyst import AnalystParams, Feedback
from jev_ids.arena.budget import Budget, BudgetExhausted
from jev_ids.arena.config import ArenaConfig, ThreatSettings
from jev_ids.arena.context import Context, baseline_context
from jev_ids.arena.curator import Candidate, Curator, Evidence, HeuristicCurator, Limits, LLMCurator, Observation, Proposal
from jev_ids.arena.gate import GatePolicy, GateVerdict
from jev_ids.arena.records import (
    AnalystRecord,
    AttackRecord,
    CuratorRecord,
    EvasionRecord,
    GateRecord,
    Inputs,
    RoundRecord,
    ShortlistRecord,
    Stamp,
    append_context,
    append_round,
    arena_fields,
    sha256,
    start_run,
)
from jev_ids.dataset import Config, Flow
from jev_ids.detectors.jev import JevDetector
from jev_ids.detectors.offline import OfflineDetector
from jev_ids.detectors.random_forest import Vocabulary, vocabulary
from jev_ids.records import Prediction, append_prediction, complete_prediction

# What a Detector call made to fail says in its row; the wording names the knob, so nobody reads it as a provider outage.
INDUCED_FAILURE = "induced failure (threats.failure_rate)"
# The class of `arena.attacker` each `[attacker] kind` names.
ATTACKERS = {"mimicry": "MimicryAttacker", "llm": "LLMAttacker"}
# How the Example shortlist is drawn. These three numbers decide an experiment, so they are named, written into every Round record and
# kept out of the config on purpose: both curators must be offered the very same shortlist, and a knob invites one Run to differ.
SHORTLIST_PER_MISS = 3
# Comfortably more than `curator.max_examples` (10), and that margin is the point. When the shortlist is no larger than the number of
# Examples a Context may hold, every curator has the same forced choice and the heuristic baseline can only vary the ORDER it shows them
# in, which is a far smaller perturbation than the LLM arm's genuinely different playbooks. The two arms would then differ in how much
# their draws differ, which is the same bias as differing in how many draws they get.
SHORTLIST_UNIFORM = 30
SHORTLIST_CAP = 40
SHORTLIST_HOW = (
    f"per missed record, {SHORTLIST_PER_MISS} Pool Flows of the Category the analyst reported, seeded, capped at {SHORTLIST_CAP}; "
    f"plus {SHORTLIST_UNIFORM} Pool Flows drawn uniformly; plus the Context's current Examples"
)


class Strategy(Protocol):
    """The knob setting an attacker found, as this module reads it.

    A structural mirror of `arena.attacker.Strategy`, so the loop type-checks and its tests run while that module is being written; the
    real frozen dataclass satisfies it. The loop never builds one and never looks inside one beyond writing it into the Round record.

    Attributes:
        bucket: the donor bucket the mimicry attacker copied its derived features from.
        padding_bytes: how many bytes were added to `src_bytes`.
        added_seconds: how much latency was added to `duration`.
    """

    bucket: str
    padding_bytes: int
    added_seconds: int


class Evasion(Protocol):
    """What an attacker reports about one attack Flow; a structural mirror of `arena.attacker.Evasion`.

    Attributes:
        row_id: the Flow attacked. A mutated Flow keeps its parent's row_id, so the gate's pairing still matches.
        evaded: whether the Detector stopped alerting on it.
        strategy: the Strategy reported, which for a Flow that did not evade is the best one tried; None when there is none. Only the
            Strategies of the Flows that DID evade are replayed, which `plan_of` is where.
        queries: Detector calls spent on this Flow.
        start_p_attack: what the Detector gave the Flow untouched, or None when that call failed.
        final_p_attack: what it gave the Flow the attacker settled on, or None when that call failed.
    """

    row_id: int
    evaded: bool
    strategy: Strategy | None
    queries: int
    start_p_attack: float | None
    final_p_attack: float | None


# What the loop hands the attacker: one Flow judged by the Detector under the Context in force, booked against the Run's Budget.
Judge = Callable[[Flow], Prediction]


class Attacker(Protocol):
    """The attacker, as the loop uses it; a structural mirror of `arena.attacker.MimicryAttacker`."""

    name: str

    def evade(self, flow: Flow, judge: Judge, max_queries: int) -> Evasion:
        """Search for a Strategy the Detector no longer alerts on, spending at most `max_queries` calls of `judge`."""
        ...


# `arena.attacker.Donors`: the benign Pool Flows bucketed by behaviour, carrying the constraint model. Opaque here on purpose -- the loop
# builds it once, hands it back to `apply` and never looks inside it, so it is the attacker's type and not one this module mirrors.
Donors = Any
# `arena.attacker.apply`: one Flow with one Strategy applied to it, its derived block copied from a donor.
Mutate = Callable[[Flow, Strategy, Donors, random.Random], Flow]


def attacker_module() -> Any:
    """`jev_ids.arena.attacker`, imported by name when a Run starts.

    By name rather than at module load, and deliberately: the attacker is another package written to the contract above, so this module
    compiles, type-checks and tests against that contract alone. It is also the one seam a test replaces to run the loop without it.
    """
    return import_module("jev_ids.arena.attacker")


def load_donors(card: Config, pool: Sequence[Flow]) -> Donors:
    """The benign Pool Flows the attacker copies derived blocks from, bucketed by behaviour and carrying the constraint model.

    Built once for the whole Run: it is a pass over the whole Pool, and every seed's attacker and every replay of a Strategy reads the
    same one. Donors come from the Pool and never from a Split under judgement, which `attacker.build_donors` enforces rather than trusts.
    """
    return attacker_module().donors_from_pool(list(pool), card)


def build_attacker(config: ArenaConfig, donors: Donors, seed: int) -> Attacker:
    """The attacker of one seed's lineage, on the donors the Run studied once.

    One per seed, because the search's own tie-breaks are seeded from it: two seeds are two independent replications and must not share a
    draw. The cast is where the attacker's contract is taken on trust.

    Raises:
        NotImplementedError: the attacker module has no class for that kind.
    """
    kind = config.attacker.kind
    made: Any = getattr(attacker_module(), ATTACKERS[kind], None)
    if made is None:
        raise NotImplementedError(f"attacker kind {kind!r} needs {ATTACKERS[kind]} in jev_ids.arena.attacker")
    return cast(Attacker, made(donors, observes=config.attacker.observes, seed=seed))


@dataclass(frozen=True)
class Projection:
    """The Detector calls a whole Run would make in the worst case, term by term.

    The terms are the design doc's, with one line the doc's budget section leaves out and this module counts anyway: the Round's traffic
    pass over the learn Split. It is the second largest line of a Round, and a projection that ignored it would be exactly the kind of
    optimistic number the pre-flight exists to prevent. The gate line carries `proposals + 1` sides, not `proposals`: the incumbent's
    Predictions are cached across a Round's proposals but never across Rounds, because this Round's Strategies change the Flows it judged.

    Attributes:
        attacker: calls per seed per Round, `flows_per_round x max_queries_per_flow`.
        traffic: calls per seed per Round, the whole learn Split judged under the Context in force.
        gate: calls per seed per Round, `|gate_split| x (proposals_per_round + 1)`.
        rounds: Rounds per seed.
        seeds: seeds in the Run.
        detector_calls: the three terms times the Rounds times the seeds.
        max_detector_calls: the cap they are held to.
        curator_calls: one per seed per Round.
        max_curator_calls: the cap those are held to.
    """

    attacker: int
    traffic: int
    gate: int
    rounds: int
    seeds: int
    detector_calls: int
    max_detector_calls: int
    curator_calls: int
    max_curator_calls: int

    @property
    def shortfall(self) -> str | None:
        """Why this Run cannot finish, naming the number and the cap, or None when it fits.

        An experiment that dies in Round 7 is worth less than one that was never begun: the Rounds it did play were played against a
        Context that never faced the Rounds it did not, and no arm of the protocol can be compared with it.
        """
        over = [
            f"{name}: {asked:,} projected against a cap of {cap:,}"
            for name, asked, cap in (
                ("detector_calls", self.detector_calls, self.max_detector_calls),
                ("curator_calls", self.curator_calls, self.max_curator_calls),
            )
            if asked > cap
        ]
        if not over:
            return None
        return (
            f"this Run cannot finish: {'; '.join(over)}. "
            f"Per seed per Round: {self.attacker:,} attacker + {self.traffic:,} traffic + {self.gate:,} gate "
            f"= {self.attacker + self.traffic + self.gate:,}, over {self.rounds} Rounds and {self.seeds} seed(s). "
            f"Raise the cap in [budget] deliberately, or run fewer seeds, Rounds or queries."
        )

    def to_dict(self) -> dict[str, Any]:
        """The projection as `config.json` keeps it, with the one line that says whether the Run was allowed to start."""
        return {
            "attacker_calls_per_seed_per_round": self.attacker,
            "traffic_calls_per_seed_per_round": self.traffic,
            "gate_calls_per_seed_per_round": self.gate,
            "rounds": self.rounds,
            "seeds": self.seeds,
            "detector_calls": self.detector_calls,
            "max_detector_calls": self.max_detector_calls,
            "curator_calls": self.curator_calls,
            "max_curator_calls": self.max_curator_calls,
            "fits": self.shortfall is None,
        }


def project(config: ArenaConfig, learn_flows: int, gate_flows: int) -> Projection:
    """The worst case of the Run `config` describes, over Splits of the given sizes."""
    rounds, seeds = config.arena.rounds, len(config.arena.seeds)
    attacker = config.attacker.flows_per_round * config.attacker.max_queries_per_flow
    judged = gate_flows * (config.curator.proposals_per_round + 1)
    return Projection(
        attacker=attacker,
        traffic=learn_flows,
        gate=judged,
        rounds=rounds,
        seeds=seeds,
        detector_calls=(attacker + learn_flows + judged) * rounds * seeds,
        max_detector_calls=config.budget.max_detector_calls,
        curator_calls=rounds * seeds,
        max_curator_calls=config.budget.max_curator_calls,
    )


def preflight(config: ArenaConfig) -> Projection:
    """The projection of a Run, from the config and the two Splits alone; no Detector and no curator is called.

    The Card and the two Splits are read because the projection needs their sizes, and reading a file is not spending a call: this is what
    `--dry-run` prints.
    """
    card = dataset.load_config(config.arena.dataset)
    learn = dataset.load_split(card["dir"] / "splits" / f"{config.arena.learn_split}.csv", card)
    held_out = dataset.load_split(card["dir"] / "splits" / f"{config.arena.gate_split}.csv", card)
    return project(config, len(learn), len(held_out))


def refuse_if_short(projection: Projection) -> None:
    """Raise before the first call when the Run cannot finish under its caps.

    Raises:
        BudgetExhausted: the projection is over one of the two caps; the message names both numbers.
    """
    short = projection.shortfall
    if short is not None:
        raise BudgetExhausted(short)


@dataclass(frozen=True)
class Arena:
    """Everything one Run of the Arena holds fixed: its inputs, its caps and where it writes.

    Attributes:
        config: the resolved knobs, every section.
        card: the Dataset's Card.
        pool: the Pool, where Examples and donor Flows come from.
        by_row_id: the Pool keyed by row_id, for a Context that chose its own Examples.
        by_category: the Pool grouped by Category, for the Example shortlist.
        donors: the benign Pool Flows the attacker copies derived blocks from, bucketed as `attacker.Donors`.
        learn: the Split the Rounds are played on.
        held_out: the Split the gate scores on.
        template: the Detector's request template, before any Context is rendered onto it.
        columns: the feature names the curator may write a rule about, as the template states them.
        categories: the Categories and what each means, as the template describes them.
        vocabulary: the one-hot vocabulary of the Pool; empty unless the offline Detector needs it.
        curator_prompt: `prompts/arena/curator.md`, or None for the heuristic baseline.
        apply: how a Strategy is applied to a Flow; the attacker itself is per seed and lives on the `SeedState`.
        analyst_params: the simulated analyst's budget, sampling share and noise.
        policy: what the gate accepts.
        budget: the Run's two counters; shared by every seed, because the caps are the Run's.
        failures: the stream that decides which Detector calls are made to fail.
        run_dir: the Run directory.
        run_id: its name, stamped on every row and every Round.
    """

    config: ArenaConfig
    card: Config
    pool: tuple[Flow, ...]
    by_row_id: Mapping[int, Flow]
    by_category: Mapping[str, tuple[Flow, ...]]
    donors: Donors
    learn: tuple[Flow, ...]
    held_out: tuple[Flow, ...]
    template: str
    columns: str
    categories: Mapping[str, str]
    vocabulary: Vocabulary
    curator_prompt: dict[str, Any] | None
    apply: Mutate
    analyst_params: AnalystParams
    policy: GatePolicy
    budget: Budget
    failures: random.Random
    run_dir: Path
    run_id: str


@dataclass
class SeedState:
    """What carries from Round to Round inside one seed's lineage.

    One per seed and never shared: two seeds are two independent histories of the same experiment, and a Context, a Feedback queue or a
    version number that leaked between them would make the seeds correlated and the spread across them meaningless.

    Attributes:
        seed: the seed of this lineage.
        context: the Context in force.
        attacker: the attacker of this lineage, seeded from this seed.
        curator: the curator of this lineage.
        rng: the analyst's random stream, one per seed.
        next_version: the version the next proposal will be given.
        feedback: every Feedback the analyst has written so far, of every Round.
        observed: the values a Flow had when it was judged, keyed by (Round, row_id), since a mutated Flow keeps its parent's row_id.
    """

    seed: int
    context: Context
    attacker: Attacker
    curator: Curator
    rng: random.Random
    next_version: int = 1
    feedback: list[Feedback] = field(default_factory=list[Feedback])
    observed: dict[tuple[int, int], str] = field(default_factory=dict[tuple[int, int], str])


@dataclass
class Draft:
    """One Round's record as it is filled in, step by step.

    Mutable and pre-filled with empty parts, so a Round that a `BudgetExhausted` cut short still writes down everything it had reached:
    the attacker's Round is worth reading even when the gate never ran.

    Attributes:
        attack: the attacker's Round.
        analyst: the analyst's Round.
        shortlist: the Pool Flows offered to the curator.
        curator: the curator's Round.
        gate: one decision per proposal.
    """

    attack: AttackRecord = AttackRecord(flows=0, evaded=0, evasion_rate=None, queries=0, strategies=())
    analyst: AnalystRecord = AnalystRecord(reviewed=0, alerts_reviewed=0, quiet_reviewed=0, poisoned=0)
    shortlist: ShortlistRecord = ShortlistRecord(size=0, how="not drawn")
    curator: CuratorRecord = CuratorRecord(kind="", model="", proposals=0, error=None, notes=())
    gate: tuple[GateRecord, ...] = ()


def induced_failure() -> dict[str, Any]:
    """What a Detector call made to fail measures: the ordinary error row of `jev_ids.records`, with no p_attack."""
    return {"p_attack": None, "category_pred": None, "latency_ms": 0.0, "retries": 0, "error": INDUCED_FAILURE}


def as_row(measured: dict[str, Any], flow: Flow, fields: Mapping[str, Any], on_failure: str) -> Prediction:
    """One Prediction row, with THREAT A3's `on_failure` applied to it.

    `open` is upstream's behaviour and needs no line here: a row without a p_attack carries no Verdict and `metrics.verdict` reads that as
    `normal`. `closed` is the other horn, and it writes the alert in. The policy is applied to every failed call and not only to an induced
    one, because a real provider error is the same event the arm is about.

    Note what `closed` costs the record: `metrics.scores` measures `error_rate` by the missing Verdict, so a fail-closed Run reports an
    error rate of zero and `gate.integrity` can never fire on it. The failures stay visible in `error`, which the row keeps either way.
    """
    row = complete_prediction(measured, flow, dict(fields))
    if on_failure == "closed" and row.get("error") is not None:
        row["classification_verdict"] = 1
    return row


@dataclass(frozen=True)
class Bench:
    """The Detector under one Context over one Split: the single place a Detector call is made in an Arena Run.

    Attributes:
        run_dir: where a recorded row is appended.
        detector: the Detector, already carrying the Context's rendered prompt.
        examples: the Examples that Context shows.
        cell: the fields every row of this bench shares.
        threats: `on_failure` and `failure_rate`.
        budget: the Run's counters; a call is booked before it is made.
        failures: the stream that decides which calls fail.
    """

    run_dir: Path
    detector: run.Detector
    examples: tuple[Flow, ...]
    cell: Mapping[str, Any]
    threats: ThreatSettings
    budget: Budget
    failures: random.Random

    def judge(self, flow: Flow, stamp: Stamp | None = None) -> Prediction:
        """One Flow judged; the row, appended to `predictions.jsonl` when `stamp` says which Round and stage it belongs to.

        Without a stamp the call is an attacker probe: it is booked against the Budget and it can fail like any other, but it is not
        written down. The attacker judges one Flow up to `max_queries_per_flow` times under mutations it then throws away, and those rows
        would multiply a Flow in `predictions.jsonl` and move every rate `jev_ids.metrics` computes over the file.

        Raises:
            BudgetExhausted: the Run has spent its Detector calls; nothing is called and the Round closes where it stands.
        """
        self.budget.spend_detector()
        # The coin is tossed on every call whatever `failure_rate` is, so two Runs that differ only in that rate keep comparable streams.
        broken = self.failures.random() < self.threats.failure_rate
        measured = induced_failure() if broken else self.detector.predict(flow, self.examples)
        fields = self.cell if stamp is None else arena_fields(self.cell, stamp)
        row = as_row(measured, flow, fields, self.threats.on_failure)
        if stamp is not None:
            append_prediction(self.run_dir, row)
        return row


def build_detector(arena: Arena, context: Context) -> run.Detector:
    """The Detector reading one Context: Jev, or the offline stand-in when the Run has no API key to spend."""
    prompt = context.to_prompt(arena.template)
    if arena.config.detector.name == "offline":
        return OfflineDetector(prompt, arena.vocabulary, arena.card["benign"])
    return JevDetector(prompt)


def examples_for(arena: Arena, context: Context, seed: int) -> tuple[Flow, ...]:
    """The Examples a Context shows: the Pool Flows it chose, or the Arena's own draw when it chose none.

    The fallback is `run.sample_examples` and not a draw of this module's own, so version 0 of every Arena Run is exactly the upstream Run
    at that k, and the first Round is comparable with the published rows.
    """
    if context.example_ids:
        return tuple(arena.by_row_id[row_id] for row_id in context.example_ids if row_id in arena.by_row_id)
    return tuple(run.sample_examples(arena.pool, arena.config.detector.k, seed, arena.card["categories"]))


def cell_fields(arena: Arena, detector: run.Detector, split: str, n_examples: int, seed: int) -> dict[str, Any]:
    """The fields every Prediction of one bench shares, in the shape `jev_ids.metrics` groups by.

    `k` is the k the Arena would draw at, even for a Context that chose its own Examples; `n_examples` is what was actually shown, so the
    two together say whether a Context picked its Examples or took the draw.
    """
    return {
        "run_id": arena.run_id,
        "dataset": arena.card["name"],
        "detector": detector.name,
        "model": detector.model,
        "split": split,
        "prompt_hash": detector.prompt_hash,
        "k": arena.config.detector.k,
        "seed": seed,
        "repetition": 0,
        "n_examples": n_examples,
    }


def bench_for(arena: Arena, context: Context, split: str, seed: int) -> Bench:
    """A bench judging one Split under one Context, with the Run's Budget and failures around it."""
    detector = build_detector(arena, context)
    examples = examples_for(arena, context, seed)
    return Bench(
        run_dir=arena.run_dir,
        detector=detector,
        examples=examples,
        cell=cell_fields(arena, detector, split, len(examples), seed),
        threats=arena.config.threats,
        budget=arena.budget,
        failures=arena.failures,
    )


def build_curator(arena: Arena, seed: int) -> Curator:
    """The curator of one seed's lineage: the LLM under study, or the heuristic baseline it has to beat.

    Built per seed and not per Run, so the heuristic's tie-breaking draw is a function of the seed like every other draw of the Run.

    Raises:
        ValueError: the LLM curator was asked for without its prompt, which only happens if `prepare` was bypassed.
    """
    settings = arena.config.curator
    limits = Limits(max_rules=settings.max_rules, max_examples=settings.max_examples)
    if settings.kind == "heuristic":
        return HeuristicCurator(limits, seed=seed)
    if arena.curator_prompt is None:
        raise ValueError("the llm curator needs prompts/arena/curator.md")
    return LLMCurator(arena.curator_prompt, settings.provider, limits, model_id=settings.model or None)


def attack_flows(arena: Arena, seed: int, round_index: int) -> list[Flow]:
    """The attack Flows of this Round: `flows_per_round` of the configured Categories, drawn from the learn Split.

    Drawn afresh each Round, so a Run does not spend ten Rounds on the same twenty Flows; seeded by (seed, Round), so it replays.
    """
    wanted = [flow for flow in arena.learn if flow.category in arena.config.attacker.categories]
    stream = random.Random(f"{seed}:{round_index}:attack")  # noqa: S311  # seeded, not secret
    return stream.sample(wanted, min(len(wanted), arena.config.attacker.flows_per_round))


def attack(arena: Arena, bench: Bench, state: SeedState, round_index: int, draft: Draft) -> list[Evasion]:
    """The attacker's Round: every chosen Flow probed until it evades or runs out of queries.

    The Judge handed over is the bench's own, so every probe is booked against the Run's Budget and obeys `threats.failure_rate` exactly as
    the traffic does; the attacker sees the whole Prediction and `[attacker] observes` is its own business.

    The draft is rewritten after every Flow and not once at the end: the attack phase is the largest line of a Round's budget, so it is
    where a `BudgetExhausted` lands, and a Round that stops there should still record the Flows the attacker did get through.
    """
    evasions: list[Evasion] = []
    for flow in attack_flows(arena, state.seed, round_index):
        evasions.append(state.attacker.evade(flow, bench.judge, arena.config.attacker.max_queries_per_flow))
        draft.attack = attack_record(evasions)
    return evasions


def attack_record(evasions: Sequence[Evasion]) -> AttackRecord:
    """The attacker's Round as the record keeps it, one line per Flow."""
    strategies = tuple(
        EvasionRecord(
            row_id=item.row_id,
            evaded=item.evaded,
            bucket=None if item.strategy is None else item.strategy.bucket,
            padding_bytes=None if item.strategy is None else item.strategy.padding_bytes,
            added_seconds=None if item.strategy is None else item.strategy.added_seconds,
            queries=item.queries,
            start_p_attack=item.start_p_attack,
            final_p_attack=item.final_p_attack,
        )
        for item in evasions
    )
    evaded = sum(item.evaded for item in evasions)
    return AttackRecord(
        flows=len(evasions),
        evaded=evaded,
        evasion_rate=metrics.ratio(evaded, len(evasions)),
        queries=sum(item.queries for item in evasions),
        strategies=strategies,
    )


@dataclass(frozen=True)
class Plan:
    """This Round's Strategies, as they are applied to a Split.

    Two fields because the two Splits are mutated by the same Strategies for different reasons. On the learn Split a Flow the attacker
    actually worked on gets the Strategy found for it; every other attack Flow, there and on the whole held-out Split, gets one drawn from
    the Round's successes. That draw is the generalisation test: a Strategy transfers to Flows the attacker never touched, and a Context
    that only learned the twenty Flows of this Round has to fail on the two hundred it did not.

    Attributes:
        own: the Strategy found for a Flow, by row_id.
        drawn: the Strategies that worked this Round; empty when nothing evaded, and then nothing is mutated at all.
    """

    own: Mapping[int, Strategy]
    drawn: tuple[Strategy, ...]


def plan_of(evasions: Sequence[Evasion]) -> Plan:
    """The Round's Plan: only the Strategies that evaded, since a setting the Detector still alerts on is not a technique."""
    own = {item.row_id: item.strategy for item in evasions if item.evaded and item.strategy is not None}
    return Plan(own=own, drawn=tuple(own.values()))


def mutate(arena: Arena, flows: Sequence[Flow], plan: Plan, key: str) -> list[Flow]:
    """A Split as this Round's attacker leaves it: benign Flows untouched, attack Flows through `attacker.apply`.

    A Round in which nothing evaded mutates nothing, and the Split is judged as it is; the Round record's `evasion_rate` of 0.0 is what
    says so.
    """
    if not plan.drawn:
        return list(flows)
    stream = random.Random(key)  # noqa: S311  # seeded, not secret

    def one(flow: Flow) -> Flow:
        if not flow.is_attack:
            return flow
        strategy = plan.own.get(flow.row_id) or stream.choice(plan.drawn)
        return arena.apply(flow, strategy, arena.donors, stream)

    return [one(flow) for flow in flows]


def traffic(arena: Arena, state: SeedState, bench: Bench, plan: Plan, round_index: int) -> list[Prediction]:
    """The Round's observed traffic judged under the Context in force: the learn Split, its attack Flows mutated.

    The values each Flow carried when it was judged are kept on the state, because the curator is later shown the record the analyst
    labeled and a mutated Flow's values are not the Split's.
    """
    flows = mutate(arena, arena.learn, plan, f"{state.seed}:{round_index}:traffic")
    for flow in flows:
        state.observed[(round_index, flow.row_id)] = flow.attributes_csv
    stamp = Stamp(round_index=round_index, context_version=state.context.version, stage="traffic")
    return [bench.judge(flow, stamp) for flow in flows]


def counts(predictions: Sequence[Prediction]) -> tuple[int, int]:
    """The Round's misses and false alarms, over every Flow judged and not only over the ones the analyst reached.

    Round-wide on purpose, and the analyst's own counts are recorded beside them: a curator reads these two numbers through a truncated
    alert queue and can conclude a Category is rare when the analyst simply never got to it.
    """
    misses = sum(item["is_attack"] == 1 and metrics.verdict(item) == 0 for item in predictions)
    false_alarms = sum(item["is_attack"] == 0 and metrics.verdict(item) == 1 for item in predictions)
    return misses, false_alarms


def labels(arena: Arena, state: SeedState, predictions: Sequence[Prediction], round_index: int) -> tuple[list[Feedback], AnalystRecord]:
    """The analyst's Round, and the Feedback this Round's curator is allowed to see.

    Three steps in the order the design doc fixes them: review this Round, keep what `delay_rounds` allows of every Round so far, and then
    poison. Poisoning runs over the delayed view, as `analyst.poison` documents, which means an entry's poisoned flag is redrawn each
    Round rather than carried: the arm measures a labeling channel under continuous attack, not one that was tampered with once.
    """
    fresh = analyst.review(predictions, round_index, arena.analyst_params, state.rng)
    state.feedback.extend(fresh)
    visible = analyst.delay(state.feedback, round_index, arena.config.analyst.delay_rounds)
    if arena.config.threats.poisoning:
        visible = analyst.poison(visible, arena.config.threats.poisoned_fraction, arena.card["benign"], state.rng)
    alerts = sum(item.detector_verdict for item in fresh)
    record = AnalystRecord(
        reviewed=len(fresh),
        alerts_reviewed=alerts,
        quiet_reviewed=len(fresh) - alerts,
        poisoned=sum(item.poisoned for item in visible),
    )
    return visible, record


def observations(state: SeedState, visible: Sequence[Feedback]) -> list[Observation]:
    """The Feedback as the curator may read it: `analyst.for_curator`'s projection, with the Flow's own values beside it.

    The label, the Verdict and the p_attack come from the projection and from nowhere else, which is what keeps `true_category` and
    `poisoned` out of a curator's reach; the Feedback itself is used only to find which values the Flow carried in the Round it was
    reviewed in, and a mutated Flow's values are the ones the analyst actually saw.
    """
    projected = analyst.for_curator(visible)
    return [
        Observation(
            row_id=item["row_id"],
            label=item["label"],
            detector_verdict=item["detector_verdict"],
            p_attack=item["p_attack"],
            attributes_csv=state.observed.get((source.observed_round, source.row_id), ""),
        )
        for item, source in zip(projected, visible, strict=True)
    ]


def draw(flows: Sequence[Flow], count: int, key: str) -> list[Flow]:
    """`count` Flows drawn without replacement and seeded by `key`; fewer when there are fewer to draw from."""
    return random.Random(key).sample(list(flows), min(count, len(flows)))  # noqa: S311  # seeded, not secret


def draw_shortlist(arena: Arena, seen: Sequence[Observation], context: Context, key: str) -> tuple[tuple[Candidate, ...], ShortlistRecord]:
    """The Pool Flows offered to the curator as candidate Examples, and how they were drawn.

    THE SHORTLIST IS EVIDENCE. A Context's Examples must be Pool Flows, but the misses happen in the learn Split, so neither curator can
    offer a missed Flow itself; what it can offer is a Pool Flow that resembles one. Drawn uniformly over 125,973 Pool Flows, that
    resemblance is a coincidence, the heuristic baseline is crippled, the LLM wins by default and the headline result is an artefact of
    this function. So the draw is per missed record, of the Category the analyst reported for it, and it is the same draw whichever
    curator reads it. The uniform remainder keeps a Category the analyst never reported reachable at all.

    The Context's current Examples are added last, because a curator that cannot see them cannot choose to keep them.
    """
    missed = [item for item in seen if not item.detector_verdict and item.label != arena.card["benign"]]
    wanted = Counter(item.label for item in missed)
    per_miss = [
        flow
        for label, misses in sorted(wanted.items())
        for flow in draw(arena.by_category.get(label, ()), SHORTLIST_PER_MISS * misses, f"{key}:{label}")
    ]
    current = [arena.by_row_id[row_id] for row_id in context.example_ids if row_id in arena.by_row_id]
    offered = {flow.row_id: flow for flow in (*per_miss[:SHORTLIST_CAP], *draw(arena.pool, SHORTLIST_UNIFORM, f"{key}:uniform"), *current)}
    candidates = tuple(
        Candidate(row_id=flow.row_id, attributes_csv=flow.attributes_csv, category=flow.category) for flow in offered.values()
    )
    return candidates, ShortlistRecord(size=len(candidates), how=SHORTLIST_HOW)


def learn(arena: Arena, state: SeedState, evidence: Evidence) -> tuple[list[Proposal], CuratorRecord]:
    """The curator's Round: one call, `proposals_per_round` candidate Contexts, and what it cost.

    Raises:
        BudgetExhausted: the Run has spent its curator calls.
    """
    arena.budget.spend_curator()
    proposals = state.curator.propose(state.context, evidence, arena.config.curator.proposals_per_round)
    return proposals, CuratorRecord(
        kind=arena.config.curator.kind,
        model=state.curator.model,
        proposals=len(proposals),
        # Only the LLM curator can fail: the baseline makes no call, and a record with an empty error column is how a Run is read as one.
        error=state.curator.last_error if isinstance(state.curator, LLMCurator) else None,
        notes=tuple(proposal.note for proposal in proposals),
    )


def judge_split(arena: Arena, state: SeedState, context: Context, flows: Sequence[Flow], stamp: Stamp) -> list[Prediction]:
    """One Context judging the gate's evaluation set, every row written down under its stage."""
    bench = bench_for(arena, context, arena.config.arena.gate_split, state.seed)
    return [bench.judge(flow, stamp) for flow in flows]


def best(kept: Sequence[tuple[Context, GateVerdict]]) -> Context | None:
    """The accepted proposal that becomes the Context in force, or None when none was accepted.

    Highest recall first, then the lower false-alarm rate, then the lower version. Recall is the number the loop pushes on and the gate has
    already refused anything that bought it too dearly, so among the survivors the most recall is the choice; the two tie-breaks only make
    the pick deterministic.

    What this costs, and it is not small: each proposal was measured against the INCUMBENT and never against the other proposals, so the
    pick between two accepted Contexts is a comparison the gate never ran, and it is made on the very Split the gate measured them on. Over
    ten Rounds and two proposals a Run selects on `gate_split` twenty times, and the winner's recall there is biased upwards by exactly that
    selection. The held-out number of a finished Run is the one measured on `eval_split`, by the separate final command; a recall read off
    `gate_split` is a training curve wearing a test set's clothes.
    """
    if not kept:
        return None
    return max(kept, key=lambda pair: (pair[1].candidate_recall or 0.0, -(pair[1].candidate_false_alarm_rate or 0.0), -pair[0].version))[0]


def gate_round(
    arena: Arena, state: SeedState, proposals: Sequence[Proposal], plan: Plan, round_index: int
) -> tuple[Context, tuple[GateRecord, ...]]:
    """The gate's Round: every proposal against the incumbent over the same held-out Flows, this seed alone.

    One `gate.evaluate` call per proposal and never one over several seeds pooled: `gate.pairing` needs each row_id once per side, and
    pooled seeds fall back to the unpaired rule with no warning and lose the McNemar test.

    The incumbent judges the same Flows as every candidate, so its Predictions are made once here and reused across this Round's
    proposals. They are never cached across Rounds: this Round's Strategies change the evaluation set itself, so a cached incumbent would
    be compared with candidates that judged different Flows, and `gate.pairing` would quietly drop to the unpaired rule.

    Returns:
        The Context in force after the gate, and one `GateRecord` per proposal in the order they were judged.
    """
    if not proposals:
        return state.context, ()
    flows = mutate(arena, arena.held_out, plan, f"{state.seed}:{round_index}:gate")
    incumbent = judge_split(arena, state, state.context, flows, Stamp(round_index, state.context.version, "gate-incumbent"))
    records: list[GateRecord] = []
    kept: list[tuple[Context, GateVerdict]] = []
    for proposal in proposals:
        candidate = state.context.child(
            rules=proposal.rules, example_ids=proposal.example_ids, version=state.next_version, note=proposal.note
        )
        state.next_version += 1
        rows = judge_split(arena, state, candidate, flows, Stamp(round_index, candidate.version, "gate-candidate"))
        verdict = gate.evaluate(rows, incumbent, policy=arena.policy)
        append_context(arena.run_dir, candidate, seed=state.seed, round_index=round_index, accepted=verdict.accepted)
        records.append(GateRecord(version=candidate.version, verdict=verdict))
        if verdict.accepted:
            kept.append((candidate, verdict))
    return best(kept) or state.context, tuple(records)


def round_steps(arena: Arena, state: SeedState, round_index: int, draft: Draft) -> Context:
    """One Round, in the design doc's five steps; the Context in force when it closes.

    The draft is filled step by step rather than at the end, so a Round cut short by the Budget still writes down what it reached.
    """
    bench = bench_for(arena, state.context, arena.config.arena.learn_split, state.seed)
    evasions = attack(arena, bench, state, round_index, draft)
    plan = plan_of(evasions)
    predictions = traffic(arena, state, bench, plan, round_index)
    visible, draft.analyst = labels(arena, state, predictions, round_index)
    seen = observations(state, visible)
    candidates, draft.shortlist = draw_shortlist(arena, seen, state.context, f"{state.seed}:{round_index}")
    misses, false_alarms = counts(predictions)
    evidence = Evidence(
        round_index=round_index,
        columns=arena.columns,
        categories=arena.categories,
        benign=arena.card["benign"],
        observations=tuple(seen),
        candidates=candidates,
        misses=misses,
        false_alarms=false_alarms,
    )
    proposals, draft.curator = learn(arena, state, evidence)
    context, draft.gate = gate_round(arena, state, proposals, plan, round_index)
    return context


def play_round(arena: Arena, state: SeedState, round_index: int) -> bool:
    """One Round played and written down; whether the Run may go on.

    The Round record is appended whatever happened, including to a Round a `BudgetExhausted` cut short: a Run that hit its cap is read
    from the last Round it wrote and from the budget snapshot in it, never from a traceback. The Context in force is the one the Round's
    traffic was judged under, and `accepted_version` is what the gate left behind, which is the incumbent's own version when the Round
    died early or nothing was accepted.
    """
    # The arm of the experiment is known before the Round starts and only whether the curator answered is not, so a Round the Budget cuts
    # short still names its curator instead of leaving an empty column for a reader to aggregate over.
    draft = Draft(curator=CuratorRecord(kind=arena.config.curator.kind, model="", proposals=0, error=None, notes=()))
    context = state.context
    alive = True
    try:
        state.context = round_steps(arena, state, round_index, draft)
    except BudgetExhausted as exhausted:
        print(f"seed={state.seed} round={round_index} stopped: {exhausted}")
        alive = False
    append_round(
        arena.run_dir,
        RoundRecord(
            run_id=arena.run_id,
            seed=state.seed,
            round_index=round_index,
            context=context,
            prompt_hash=context.to_prompt(arena.template)["sha256"],
            attack=draft.attack,
            analyst=draft.analyst,
            shortlist=draft.shortlist,
            curator=draft.curator,
            gate=draft.gate,
            accepted_version=state.context.version,
            budget=arena.budget.snapshot(),
        ),
    )
    print(
        f"seed={state.seed} round={round_index} evaded={draft.attack.evaded}/{draft.attack.flows} "
        f"proposals={draft.curator.proposals} context=v{state.context.version} calls={arena.budget.snapshot()['detector_calls']}"
    )
    return alive


def play_seed(arena: Arena, seed: int) -> bool:
    """Every Round of one seed's lineage, from the baseline Context; whether the Run may go on."""
    # The induced-failure stream is reseeded here rather than once for the whole Run, so a seed's failures are its own: a Run of seeds 0
    # and 1 must give seed 1 the very calls a Run of seed 1 alone would have failed, or A3's arms cannot be read seed by seed. The rate
    # stays in the key so that fail-open and fail-closed, at one rate and one seed, fail on exactly the same calls.
    arena.failures.seed(f"{arena.config.threats.failure_rate}:{seed}:failures")
    state = SeedState(
        seed=seed,
        context=baseline_context(),
        attacker=build_attacker(arena.config, arena.donors, seed),
        curator=build_curator(arena, seed),
        rng=random.Random(f"{seed}:analyst"),  # noqa: S311  # seeded, not secret
    )
    append_context(arena.run_dir, state.context, seed=seed, round_index=0, accepted=True)
    # `all` short-circuits, and that is the point: a Round that says the Run may not go on stops the seed where it stands. The Round it
    # happened in is already written, and no further Round is begun with nothing left to spend on it.
    return all(play_round(arena, state, round_index) for round_index in range(1, arena.config.arena.rounds + 1))


def prepare(config: ArenaConfig) -> Arena:
    """Everything a Run needs, loaded once: the Dataset, the prompts, the attacker, the caps and the Run directory.

    The order is the discipline: the projection is computed and refused before anything is loaded that costs a call, and `config.json` is
    written before the first call is made. A Run that cannot finish therefore leaves no directory at all, and a Run that starts has
    already said on disk what it intends to spend.

    Raises:
        BudgetExhausted: the Run cannot finish under its own caps.
    """
    card = dataset.load_config(config.arena.dataset)
    learn_path = card["dir"] / "splits" / f"{config.arena.learn_split}.csv"
    gate_path = card["dir"] / "splits" / f"{config.arena.gate_split}.csv"
    learn = dataset.load_split(learn_path, card)
    held_out = dataset.load_split(gate_path, card)
    projection = project(config, len(learn), len(held_out))
    refuse_if_short(projection)
    pool = dataset.load_split(card["dir"] / "pool.csv", card)
    prompt = run.load_prompt(ROOT / "prompts" / card["name"] / "jev.json")
    curator_prompt = None if config.curator.kind == "heuristic" else run.load_prompt(ROOT / "prompts" / "arena" / "curator.md")
    state: dict[str, Any] = json.loads(prompt["text"]).get("state", {})
    budget = Budget(config.budget.max_detector_calls, config.budget.max_curator_calls)
    mutations = card["dir"] / "mutations.json"
    inputs = Inputs(
        dataset=card["sha256"],
        learn_split=sha256(learn_path),
        gate_split=sha256(gate_path),
        prompt=prompt["sha256"],
        curator_prompt=None if curator_prompt is None else curator_prompt["sha256"],
        mutations=sha256(mutations),
    )
    run_dir = start_run(config, inputs, projection.to_dict(), budget)
    by_category: dict[str, list[Flow]] = {name: [] for name in card["categories"]}
    for flow in pool:
        by_category.setdefault(flow.category, []).append(flow)
    return Arena(
        config=config,
        card=card,
        pool=tuple(pool),
        by_row_id={flow.row_id: flow for flow in pool},
        by_category={name: tuple(flows) for name, flows in by_category.items()},
        donors=load_donors(card, pool),
        learn=tuple(learn),
        held_out=tuple(held_out),
        template=prompt["text"],
        columns=state.get("columns", ",".join(card["features"])),
        categories=state.get("categories", {name: "" for name in card["categories"]}),
        vocabulary=vocabulary(pool, card) if config.detector.name == "offline" else {},
        curator_prompt=curator_prompt,
        apply=cast(Mutate, attacker_module().apply),
        analyst_params=AnalystParams(
            categories=tuple(card["categories"]),
            alert_budget=config.analyst.alert_budget,
            sample_rate=config.analyst.sample_rate,
            label_noise=config.analyst.label_noise,
        ),
        policy=GatePolicy(
            mode=config.gate.mode,
            recall_slack=config.gate.recall_slack,
            false_alarm_slack=config.gate.false_alarm_slack,
            min_attack_flows=config.gate.min_attack_flows,
            max_error_rate=config.gate.max_error_rate,
        ),
        budget=budget,
        failures=random.Random(f"{config.threats.failure_rate}:failures"),  # noqa: S311  # seeded, not secret
        run_dir=run_dir,
        run_id=run_dir.name,
    )


def run_arena(config: ArenaConfig) -> Path:
    """One whole Run of the Arena: every seed, every Round; the Run directory.

    The seeds are played one after another and share one Budget, because the cap is the Run's; a seed that exhausts it ends the Run, with
    the Round it was in already written.
    """
    arena = prepare(config)
    for seed in config.arena.seeds:
        if not play_seed(arena, seed):
            break
    print(f"done: {arena.run_dir}")
    return arena.run_dir
