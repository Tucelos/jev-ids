"""The final measurement: four Contexts, the same Flows, the untouched evaluation Split.

In reading order:

- `ARMS`, `BASELINE_ARM`, `PLACEBO_VERSION`, `EXAMPLES_ONLY_VERSION`, `PLACEBO_NOTE`, `EXAMPLES_ONLY_NOTE`, `PLACEBO_SENTENCES`,
  `EVAL_SET_HOW`, `MUTATION_KEY`, `EVAL_RESULTS`, `NO_CURATOR_CALLS`: the four arms, the placebo's catalogue, and the sentences the Run
  record explains itself with.
- `Projection`, `project`, `refuse_if_short`: what the measurement would spend, counted before it spends anything.
- `Source`, `config_of`, `eval_split`, `last_rounds`, `strategies_of`, `final_context`, `read_source`: a finished Arena Run, as this
  module reads it.
- `nearest`, `rule_chars`, `placebo_rules`, `placebo_context`, `examples_context`, `Arm`, `arms_of`: the two controls, and one seed's
  four arms.
- `Eval`, `census`, `eval_run_id`, `write_eval_config`, `prepare`: everything one measurement holds fixed, and the Run directory it
  writes before the first call.
- `Judged`, `evaluation_set`, `record_strategies`: the Flows every arm of one seed judges, which of them the attacker moved, and what it
  takes to rebuild them.
- `build_detector`, `examples_for`, `cell_fields`, `judge_arm`, `judge_seed`: the measurement itself, arm by arm.
- `preflight` and `run_final`: the two entry points, the projection a `--dry-run` prints and the measurement.
- `Cell`, `eval_row`, `summarize_eval`: the table.

**Why this module exists.** The Arena plays its Rounds on the learn Split and gates on the held-out one, and neither produces a number
anybody should quote. Across a Run, version 0 and the final Context were in force in DIFFERENT Rounds against DIFFERENT mutations, so two
of their Predictions share a `row_id` and not the traffic behind it; `arena.report.seed_row` says as much in its own `paired_same_round`
column. Here every Context judges the SAME Flows of the untouched evaluation Split, one seed at a time, so the comparison is genuinely
paired and stays comparable with the upstream numbers in `results/paper/`.

**Four arms, because a curated Context changes three things at once**: which Examples the Detector is shown, how long its prompt is, and
what the playbook actually says. Each arm holds one more of them fixed, so the four rows read as three steps:

- `baseline -> examples_only`: what CHOOSING THE EXAMPLES bought. Version 0's empty playbook carrying the final Context's `example_ids`,
  so the prompt is the committed template either way and only the Examples move.
- `examples_only -> placebo`: what the extra prompt LENGTH bought, the Examples held constant. A playbook rides on every Detector call
  and a longer prompt moves a model's answers on its own, so without this step "the playbook helped" cannot be told from "more text
  helped" (`dev-docs/arena-loop-design.md`, "Baselines the result is meaningless without").
- `placebo -> final`: what the Rules' CONTENT bought, length and Examples both held constant. This is the number the whole project
  exists to produce, and it cannot be read without the other three arms.

The placebo is generated from the final Context's shape by `placebo_rules` and never by a curator: this module makes no curator call at
all, and its Budget is created with none to spend.

**The whole Split, and not only the attacked Categories.** A curator that raises recall on the Categories under attack by teaching the
Detector to suspect quiet sessions moves every other Category too, and a measurement restricted to the attacked ones would never show
it. So every Flow of the Split is judged: the benign ones unchanged, the attack Flows of the attacked Categories mutated, and the attack
Flows of every other Category exactly as the Split has them. `recall_<category>` is where a regression outside the attacked Categories
appears, `recall_mutated` and `recall_unmutated` are where it is summarised, and every Prediction carries a `mutated` field saying which
side of that line its Flow was on.

**What this measurement still cannot tell you.** Five things, and they come before any number:

- **Selection, which is the largest remaining threat to the headline.** The `final` Context is the argmax of up to
  `rounds x proposals_per_round` gate decisions, every one of them taken on recall, while `baseline` is a single fixed point that was
  never selected for anything. Nothing here corrects for that multiplicity, so a `placebo -> final` difference of the size a lucky argmax
  produces cannot be told from one the Rules produced.
- **The mutations are adapted to one arm.** The Strategies replayed were searched against the FINAL Context, so the mutated traffic is
  the traffic that beat it, and no search was ever run against version 0. That runs AGAINST the final arm rather than for it, which makes
  this measurement conservative on that axis rather than flattering.
- **The placebo matches length and tokens, not salience.** Its sentences are true and inert; a real Rule names features the model is
  already attending to. If naming a feature at all moves an answer whatever the advice says, this arm does not control for it, and a
  shuffled or negated copy of the real playbook would be the stronger control.
- **One repetition per Flow.** Every arm judges every Flow once, so there is no measure of the Detector's own run-to-run variance beneath
  the McNemar p, and a difference of a few Flows may be noise that this table will happily attribute to the playbook.
- **The offline Detector cannot read a playbook AT ALL.** A forest ignores the real Rules and the placebo's alike, so with
  `[detector] name = "offline"` the `examples_only`, `placebo` and `final` arms are identical by construction and their p is 1 by
  arithmetic and not by evidence. Somebody will run it offline first: nothing in that table is a result.
"""

import random
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from jev_ids import ROOT, dataset, metrics, run
from jev_ids.arena import loop, report
from jev_ids.arena.budget import Budget, BudgetExhausted
from jev_ids.arena.config import ArenaConfig, ArenaSettings, AttackerSettings, BudgetSettings, DetectorSettings, ThreatSettings, section
from jev_ids.arena.context import Context, Rule, baseline_context, context_from_dict
from jev_ids.arena.loop import Donors, Mutate, Strategy
from jev_ids.arena.records import append_line, code_commit, read_rounds, sha256
from jev_ids.dataset import Config, Flow
from jev_ids.detectors.jev import JevDetector
from jev_ids.detectors.offline import OfflineDetector
from jev_ids.detectors.random_forest import Vocabulary, vocabulary
from jev_ids.records import Prediction, append_prediction, read_predictions, write_config

# The four Contexts every seed is measured with, in the order they are judged, which is also the order the three steps of the
# decomposition read in: version 0, then its Examples, then its length, then what the Rules actually say.
ARMS = ("baseline", "examples_only", "placebo", "final")
BASELINE_ARM = ARMS[0]

# The versions the two constructed arms carry. Negative on purpose: 0 is the baseline and the Arena numbers the curator's proposals from
# 1, so no lineage can ever reach these numbers and a reader who cuts `predictions.jsonl` by `context_version` alone cannot mistake
# either control for the Context it was cut from. Both carry the final version as their `parent`.
PLACEBO_VERSION = -1
EXAMPLES_ONLY_VERSION = -2
PLACEBO_NOTE = (
    "placebo: as many Rules as the final Context and of closely matching length, each true about network traffic and useless for this "
    "decision; generated from the final Context's shape by jev_ids.arena.final and never by a curator"
)
EXAMPLES_ONLY_NOTE = (
    "examples only: the final Context's chosen Examples under version 0's empty playbook, so the step from the baseline is the Examples "
    "and nothing else; generated by jev_ids.arena.final and never by a curator"
)

# The placebo's catalogue, kept here so a reader can audit every sentence the arm ever shows a Detector. Each one is true, none names a
# Category or a feature of the Card, and none of them helps decide anything: they are facts about cabling, addressing, standards bodies
# and the people who run a network. The lengths form a ladder from 30 to 203 characters, which is what makes the length match possible;
# `placebo_rules` explains how a Rule is matched to one of them.
PLACEBO_SENTENCES: tuple[str, ...] = (
    "A MAC address is 48 bits wide.",
    "An IPv6 address is 128 bits wide.",
    "Ethernet is standardised as IEEE 802.3.",
    "Cat 6 cabling is rated for one hundred metres.",
    "The OSI reference model is drawn in seven layers.",
    "A rack unit is 44.45 millimetres of vertical space.",
    "Wi-Fi equipment works in the 2.4 and 5 gigahertz bands.",
    "Glass fibre carries light, and copper cabling carries electricity.",
    "The metre of cabling that nobody labelled is the one that gets pulled.",
    "Light inside a glass fibre travels at two thirds of its speed in a vacuum.",
    "A switch builds its forwarding table by noting which interface an address appears on.",
    "Private address ranges were set aside by RFC 1918 and are not routed on the public Internet.",
    "Power over Ethernet carries the electrical supply along the very cabling that carries the data.",
    "A subnet mask separates the network part of an address from the part that names one interface on it.",
    "Network equipment keeps its own clock, and two clocks in the same rack rarely agree to the millisecond.",
    "The Domain Name System is hierarchical, and a resolver given no answer by one server simply asks another.",
    "The Internet Assigned Numbers Authority keeps the registries that make a number mean the same thing everywhere.",
    "Glass fibre is unaffected by the electromagnetic noise of a busy rack, because what it carries is light and not current.",
    "A wireless band is one shared medium, so two radios that transmit at the same moment garble each other and must both send again.",
    "Copper cabling loses signal with distance and with heat, which is one reason a data centre spends as much on cooling as on "
    "anything else.",
    "Numbering plans on the public Internet are registered rather than invented, and a number nobody registered means nothing outside the "
    "place that chose it.",
    "Network documentation is written by the people who operate the network, so it is accurate only up to the last change somebody "
    "remembered to write down.",
    "The physical layer of any network was installed by people, runs through walls and ceilings that somebody chose, and can be unplugged "
    "by anybody who reaches the far end of it.",
    "Every interface is given a name by the operating system that owns it, and those names follow different conventions on different "
    "systems, so one adapter is called two things on two machines.",
    "A cable that has been coiled, crushed, painted over or run beside a lift motor will keep passing inspection on paper long after the "
    "people who depend on it have started to notice that something is wrong.",
)

# How the evaluation set is built, written into the Run record because it is the whole claim this measurement makes.
EVAL_SET_HOW = (
    "every Flow of the evaluation Split: the benign ones unchanged, the attack Flows of the Run's [attacker] categories each put through "
    "attacker.apply with a Strategy drawn from the ones that evaded in that seed's last Round, and the attack Flows of every other "
    "Category exactly as the Split has them, since no Strategy was ever searched for those. Nothing is left out, so a playbook that "
    "bought recall on the attacked Categories by wrecking another shows up in the table's own recall_<category> column; every arm of a "
    "seed judges the identical Flows, so the comparison is paired on row_id"
)
# The seeded stream that draws a Strategy per attack Flow, keyed by the seed alone so the set rebuilds from the source Run and nothing else.
MUTATION_KEY = "final"

# Where the headline measurement is written; the Run directories sit beside the Arena's own, never inside them.
EVAL_RESULTS = ROOT / "results" / "arena-eval"
# The curator calls this measurement may make. Zero, and it is a cap and not a comment: the placebo must never be produced by a curator,
# and a Budget with nothing to spend on one makes that a property of the Run rather than a promise in a docstring.
NO_CURATOR_CALLS = 0


@dataclass(frozen=True)
class Projection:
    """The Detector calls the whole measurement would make, counted from the Split's size alone.

    Attributes:
        flows: the evaluation Split's Flows. Every one of them is judged, so this is the exact count and not a worst case.
        arms: the Contexts each seed is measured with, `len(ARMS)`.
        seeds: the seeds the source Run actually played.
        detector_calls: `flows x arms x seeds`.
        max_detector_calls: the cap they are held to, the source Run's own `[budget] max_detector_calls`.
    """

    flows: int
    arms: int
    seeds: int
    detector_calls: int
    max_detector_calls: int

    @property
    def shortfall(self) -> str | None:
        """Why this measurement cannot finish, naming the number and the cap, or None when it fits.

        A measurement that dies halfway leaves one arm judged over more Flows than another, and the paired test then silently runs over
        whatever the two happen to share. Refusing before the first call is cheaper than reading that table.
        """
        if self.detector_calls <= self.max_detector_calls:
            return None
        return (
            f"this measurement cannot finish: detector_calls: {self.detector_calls:,} projected against a cap of "
            f"{self.max_detector_calls:,}. {self.flows:,} Flows x {self.arms} arms x {self.seeds} seed(s) "
            f"= {self.detector_calls:,}. Raise max_detector_calls in [budget] deliberately, or measure fewer seeds."
        )

    def to_dict(self) -> dict[str, Any]:
        """The projection as `config.json` keeps it, with the line that says whether the measurement was allowed to start."""
        return {
            "flows": self.flows,
            "arms": self.arms,
            "seeds": self.seeds,
            "detector_calls": self.detector_calls,
            "max_detector_calls": self.max_detector_calls,
            "fits": self.shortfall is None,
        }


def project(config: ArenaConfig, seeds: Sequence[int], flows: int) -> Projection:
    """The worst case of measuring `seeds` over a Split of `flows` Flows with every arm."""
    return Projection(
        flows=flows,
        arms=len(ARMS),
        seeds=len(seeds),
        detector_calls=flows * len(ARMS) * len(seeds),
        max_detector_calls=config.budget.max_detector_calls,
    )


def refuse_if_short(projection: Projection) -> None:
    """Raise before the first call when the measurement cannot finish under the cap.

    Raises:
        BudgetExhausted: the projection is over the cap; the message names both numbers.
    """
    short = projection.shortfall
    if short is not None:
        raise BudgetExhausted(short)


@dataclass(frozen=True)
class Source:
    """The finished Arena Run this measurement is about, reduced to what it needs of it.

    Attributes:
        run_dir: the Run directory, `results/arena/<run_id>`.
        stored: its whole `config.json`, kept so the measurement records what it measured rather than describing it.
        config: the five sections of its knobs the measurement itself reads.
        seeds: the seeds it actually played a Round for, in the order its config named them.
        contexts: per seed, the Context it ended under.
        rounds: per seed, the index of its last Round, the one the Strategies come from.
        strategies: per seed, the Strategies of that Round that evaded; empty when nothing did.
    """

    run_dir: Path
    stored: Mapping[str, Any]
    config: ArenaConfig
    seeds: tuple[int, ...]
    contexts: Mapping[int, Context]
    rounds: Mapping[int, int]
    strategies: Mapping[int, tuple[Strategy, ...]]


def config_of(stored: Mapping[str, Any]) -> ArenaConfig:
    """The five sections of the Run's knobs this measurement reads, back from the `config` block of its `config.json`.

    Five and not eight: the curator, the analyst and the gate decided what the Run's final Context became and have no say in how it is
    measured, so they are left at their defaults here and the Run's own `config.json` is recorded whole under `measures` instead. An
    unknown key still raises, through `config.section`, because a config that drifted from the code is exactly what a silent default
    would hide.
    """
    document: Mapping[str, Any] = stored.get("config", {})
    return ArenaConfig(
        arena=section(ArenaSettings, document, "arena"),
        detector=section(DetectorSettings, document, "detector"),
        attacker=section(AttackerSettings, document, "attacker"),
        budget=section(BudgetSettings, document, "budget"),
        threats=section(ThreatSettings, document, "threats"),
    )


def eval_split(config: ArenaConfig) -> tuple[Config, Path, list[Flow]]:
    """The Card, the evaluation Split's file and its Flows: what the projection and the measurement both start from."""
    card = dataset.load_config(config.arena.dataset)
    path = card["dir"] / "splits" / f"{config.arena.eval_split}.csv"
    return card, path, dataset.load_split(path, card)


def last_rounds(records: Sequence[Mapping[str, Any]]) -> dict[int, Mapping[str, Any]]:
    """The last Round each seed played, keyed by the seed; a record naming no seed is not a seed's Round and is dropped."""
    latest: dict[int, Mapping[str, Any]] = {}
    for record in sorted(records, key=report.round_key):
        seed = record.get("seed")
        if seed is not None:
            latest[int(seed)] = record
    return latest


def strategies_of(record: Mapping[str, Any], module: Any) -> tuple[Strategy, ...]:
    """The Strategies of one Round that evaded, as the attacker's own frozen dataclass.

    Only the entries with `evaded: true` are taken: a knob setting the Detector still alerted on is not a technique, and replaying it on
    the evaluation Split would mutate Flows toward nothing. A Round in which nothing evaded yields none, and then nothing is mutated at
    all -- the honest outcome, and the Run record's evasion rate of 0.0 is what says so.
    """
    found: Sequence[Mapping[str, Any]] = record.get("attack", {}).get("strategies", [])
    return tuple(
        cast(
            Strategy,
            module.Strategy(
                bucket=str(item["bucket"]), padding_bytes=int(item["padding_bytes"] or 0), added_seconds=int(item["added_seconds"] or 0)
            ),
        )
        for item in found
        if item.get("evaded") and item.get("bucket") is not None
    )


def final_context(lines: Sequence[Mapping[str, Any]], seed: int, version: Any) -> Context:
    """The Context one seed ended under: the accepted line of the version in force, else the last accepted line, else version 0.

    `version` is the last Round's `accepted_version`, which is the version in force when the Round closed -- the incumbent's own when the
    gate accepted nothing, so a Run whose last Round accepted nothing still names a `final` arm and it is the Context that was standing.
    The version is looked up rather than the last accepted line taken, because one Round may accept several proposals and only the best
    of them stays in force.
    """
    accepted = [line for line in lines if line.get("seed") == seed and line.get("accepted") and "version" in line]
    if version is not None:
        matching = [line for line in accepted if int(line["version"]) == int(version)]
        if matching:
            return context_from_dict(matching[-1])
    return context_from_dict(accepted[-1]) if accepted else baseline_context()


def read_source(run_dir: Path) -> Source:
    """A finished Arena Run read once: its config, and per seed the Context it ended under and the Strategies it ended with.

    Args:
        run_dir: the Run directory, holding `config.json`, `rounds.jsonl` and `contexts.jsonl`.

    Returns:
        The Source, carrying only the seeds that actually played a Round.

    Raises:
        ValueError: the Run played no Round for any of the seeds its config names, so there is nothing to measure. A seed without a Round
            has no final Context but would still produce a `final` arm, silently equal to the baseline, and a table that says the curator
            changed nothing is worse than a refusal.
    """
    stored = report.read_config(run_dir)
    config = config_of(stored)
    lines = report.read_jsonl(run_dir / "contexts.jsonl")
    latest = last_rounds(read_rounds(run_dir))
    module = loop.attacker_module()
    seeds = tuple(seed for seed in config.arena.seeds if seed in latest)
    if not seeds:
        raise ValueError(f"{run_dir.name} recorded no Round for any of the seeds {list(config.arena.seeds)}: there is nothing to measure")
    return Source(
        run_dir=run_dir,
        stored=stored,
        config=config,
        seeds=seeds,
        contexts={seed: final_context(lines, seed, latest[seed].get("accepted_version")) for seed in seeds},
        rounds={seed: int(latest[seed].get("round", 0)) for seed in seeds},
        strategies={seed: strategies_of(latest[seed], module) for seed in seeds},
    )


def nearest(sentences: Sequence[str], target: int) -> str:
    """The catalogue sentence whose length is closest to `target`, the earliest one in the catalogue on a tie."""
    return min(sentences, key=lambda sentence: (abs(len(sentence) - target), PLACEBO_SENTENCES.index(sentence)))


def rule_chars(context: Context) -> int:
    """The characters of one Context's playbook, the number a placebo is built to match."""
    return sum(len(rule.text) for rule in context.rules)


def placebo_rules(rules: Sequence[Rule]) -> tuple[Rule, ...]:
    """One placebo Rule per Rule given, of closely matching length, in the Rules' own order.

    **How the length is matched.** Each Rule takes the catalogue sentence whose character count is nearest to its own, ties going to the
    earliest entry of `PLACEBO_SENTENCES`; a sentence already taken is not offered again while the catalogue lasts, so the arm shows a
    Detector as many distinct sentences as the playbook has Rules. The catalogue is a ladder of 25 distinct lengths from 30 to 203
    characters, so against a fresh catalogue the nearest match is never more than 10 characters out anywhere in that range and is within
    5 across the 45 to 140 band a curator's Rules actually fall in. Taking a sentence out widens the next Rule's match, and a playbook of
    fifteen Rules of one length widens it a lot; a playbook longer than the whole catalogue starts it again rather than failing. That is
    why `rule_chars` of both Contexts goes into the table: how close the match came is read there and is not claimed here.

    The id and the Round are copied from the Rule being matched, so the two playbooks line up entry by entry in the record. Neither
    reaches a Detector: `Context.to_prompt` renders the text alone.
    """
    available = list(PLACEBO_SENTENCES)
    made: list[Rule] = []
    for rule in rules:
        if not available:
            available = list(PLACEBO_SENTENCES)
        text = nearest(available, len(rule.text))
        available.remove(text)
        made.append(Rule(id=rule.id, text=text, added_round=rule.added_round))
    return tuple(made)


def placebo_context(final: Context) -> Context:
    """The confound control: the final Context's shape with its playbook's meaning taken out.

    Deterministic in the strict sense -- the same final Context gives an equal Context every time, since `placebo_rules` reads nothing
    but the Rules' lengths and the catalogue's fixed order. The chosen Examples travel unchanged, so this arm differs from `final` in the
    Rules' wording and in nothing else and the step between the two is the playbook's meaning alone; a final Context with no Rules at all
    yields a placebo with none, which renders the same prompt as `examples_only` and says so in the table.
    """
    return Context(
        version=PLACEBO_VERSION,
        rules=placebo_rules(final.rules),
        example_ids=final.example_ids,
        parent=final.version,
        note=PLACEBO_NOTE,
    )


def examples_context(final: Context) -> Context:
    """The other control: the final Context's chosen Examples under version 0's empty playbook.

    The step that isolates the Examples. Chosen Examples travel as `predict`'s own argument and never through the template, so this arm
    renders the committed template byte for byte exactly as the baseline does, and the two differ in the Examples shown and in nothing
    whatever else. A final Context that chose none makes this arm equal to the baseline, and the table then carries two rows that agree,
    which is the honest way of saying the curator chose no Examples.
    """
    return Context(version=EXAMPLES_ONLY_VERSION, example_ids=final.example_ids, parent=final.version, note=EXAMPLES_ONLY_NOTE)


@dataclass(frozen=True)
class Arm:
    """One Context judging one seed's evaluation set.

    Attributes:
        name: one of `ARMS`, the column every Prediction of this arm carries.
        seed: the seed whose evaluation set it judges.
        context: the Context itself.
    """

    name: str
    seed: int
    context: Context


def arms_of(seed: int, final: Context) -> tuple[Arm, ...]:
    """The four Contexts one seed is measured with, in `ARMS` order, which is the order the decomposition reads in.

    Arm by arm and not Flow by Flow: the prompt prefix then stays constant for a whole arm, which is what gives a provider's prefix cache
    its chance, exactly as `run.execute` orders its own loop. The price is that a measurement cut short loses the tail of one arm rather
    than a Flow of each, which is why the projection refuses a measurement that cannot finish.
    """
    return (
        Arm(name=ARMS[0], seed=seed, context=baseline_context()),
        Arm(name=ARMS[1], seed=seed, context=examples_context(final)),
        Arm(name=ARMS[2], seed=seed, context=placebo_context(final)),
        Arm(name=ARMS[3], seed=seed, context=final),
    )


@dataclass(frozen=True)
class Eval:
    """Everything one final measurement holds fixed: its inputs, its cap and where it writes.

    Attributes:
        source: the finished Run being measured.
        card: the Dataset's Card.
        pool: the Pool, where Examples are drawn from when a Context chooses none.
        by_row_id: the Pool keyed by row_id, for a Context that chose its own.
        donors: the benign Pool Flows the attacker copies derived blocks from, as `attacker.Donors`.
        judged: the whole evaluation Split before mutation, in its own order.
        census: what that set is made of, mutated and unmutated, as the Run record keeps it.
        template: the Detector's request template, before any Context is rendered onto it.
        vocabulary: the one-hot vocabulary of the Pool; empty unless the offline Detector needs it.
        apply: `attacker.apply`, how a Strategy is applied to a Flow.
        budget: the measurement's own counters, with no curator call to spend.
        run_dir: the Run directory under `results/arena-eval/`.
        run_id: its name, stamped on every row.
    """

    source: Source
    card: Config
    pool: tuple[Flow, ...]
    by_row_id: Mapping[int, Flow]
    donors: Donors
    judged: tuple[Flow, ...]
    census: Mapping[str, Any]
    template: str
    vocabulary: Vocabulary
    apply: Mutate
    budget: Budget
    run_dir: Path
    run_id: str


def census(flows: Sequence[Flow], categories: Sequence[str]) -> dict[str, Any]:
    """What the evaluation set is made of, for the Run record: nothing is left out, and two kinds of attack Flow are in it.

    The Flows of the attacked Categories carry a Strategy and the rest are the Split's own. Both counts are written down with their
    Categories named, because the difference between them is what the table's `recall_mutated` and `recall_unmutated` columns mean, and a
    reader who cannot see which Categories were moved cannot read either.
    """
    attacks = [flow for flow in flows if flow.is_attack]
    moved = [flow for flow in attacks if flow.category in categories]
    untouched = [flow for flow in attacks if flow.category not in categories]
    return {
        "flows": len(flows),
        "benign": len(flows) - len(attacks),
        "attacks": len(attacks),
        "mutated_attacks": len(moved),
        "mutated_categories": sorted({flow.category for flow in moved}),
        "unmutated_attacks": len(untouched),
        "unmutated_categories": sorted({flow.category for flow in untouched}),
        "how": EVAL_SET_HOW,
    }


def eval_run_id(started: datetime, card: Config, detector: str) -> str:
    """`<UTC timestamp>-<dataset>-<detector>-eval`, the name of the measurement's directory.

    The timestamp keeps its microseconds, as `run.execute`'s and `arena.records.run_id`'s do, so two measurements launched together never
    share a directory; the `-eval` suffix is what tells a reader at a glance that the directory holds the headline number and not a Run of
    the loop.
    """
    return f"{started:%Y%m%dT%H%M%S.%fZ}-{card['name']}-{detector}-eval"


def write_eval_config(ev: Eval, projection: Projection, inputs: Mapping[str, Any], started: datetime) -> None:
    """Create the Run directory and write `config.json`, before a single Detector call is made.

    `run.execute`'s discipline and `arena.records.start_run`'s: what the measurement intends to spend is on disk before it spends any of
    it, so a measurement killed by a quota error or a laptop lid is still readable as the thing it set out to be. The source Run's own
    `config.json` is copied in whole under `measures`, because the arms are only comparable with each other and the numbers are only
    comparable with `results/paper/` if a reader can see which Run, which Card and which Splits they came from.
    """
    write_config(
        ev.run_dir,
        {
            "run_id": ev.run_id,
            "measures": {
                "run_dir": str(ev.source.run_dir),
                "run_id": ev.source.stored.get("run_id"),
                "config": dict(ev.source.stored),
                "seeds": list(ev.source.seeds),
                "final_versions": {str(seed): ev.source.contexts[seed].version for seed in ev.source.seeds},
                "final_rounds": {str(seed): ev.source.rounds[seed] for seed in ev.source.seeds},
                "strategies": {str(seed): len(ev.source.strategies[seed]) for seed in ev.source.seeds},
            },
            "config": {
                "arena": asdict(ev.source.config.arena),
                "detector": asdict(ev.source.config.detector),
                "attacker": asdict(ev.source.config.attacker),
                "budget": asdict(ev.source.config.budget),
                "threats": asdict(ev.source.config.threats),
            },
            "arms": list(ARMS),
            "eval_split": ev.source.config.arena.eval_split,
            "eval_set": dict(ev.census),
            "inputs": dict(inputs),
            "projection": projection.to_dict(),
            "budget": ev.budget.snapshot(),
            "code_commit": code_commit(),
            "started_at": started.isoformat(timespec="seconds"),
        },
    )


def prepare(source: Source, results_dir: Path) -> Eval:
    """Everything the measurement needs, loaded once, with the projection refused before any of it costs a call.

    The order is the discipline of `loop.prepare`: the Split is read and the projection refused first, so a measurement that cannot
    finish leaves no directory at all; then the Pool, the donors and the template are loaded; then `config.json` is written, before the
    first Detector call.

    Raises:
        BudgetExhausted: the measurement cannot finish under the source Run's own cap.
    """
    config = source.config
    card, split_path, flows = eval_split(config)
    projection = project(config, source.seeds, len(flows))
    refuse_if_short(projection)
    pool = dataset.load_split(card["dir"] / "pool.csv", card)
    prompt = run.load_prompt(ROOT / "prompts" / card["name"] / "jev.json")
    started = datetime.now(UTC)
    identifier = eval_run_id(started, card, config.detector.name)
    measurement = Eval(
        source=source,
        card=card,
        pool=tuple(pool),
        by_row_id={flow.row_id: flow for flow in pool},
        donors=loop.load_donors(card, pool),
        judged=tuple(flows),
        census=census(flows, config.attacker.categories),
        template=prompt["text"],
        vocabulary=vocabulary(pool, card) if config.detector.name == "offline" else {},
        apply=cast(Mutate, loop.attacker_module().apply),
        budget=Budget(projection.max_detector_calls, NO_CURATOR_CALLS),
        run_dir=results_dir / identifier,
        run_id=identifier,
    )
    inputs = {
        "dataset": card["sha256"],
        "eval_split": sha256(split_path),
        "prompt": prompt["sha256"],
        "mutations": sha256(card["dir"] / "mutations.json"),
        "source_config": sha256(source.run_dir / "config.json"),
        "source_rounds": sha256(source.run_dir / "rounds.jsonl"),
        "source_contexts": sha256(source.run_dir / "contexts.jsonl"),
    }
    write_eval_config(measurement, projection, inputs, started)
    return measurement


@dataclass(frozen=True)
class Judged:
    """One seed's evaluation set: the Flows every arm of that seed judges, and which of them the attacker moved.

    Attributes:
        flows: the whole evaluation Split, the attacked Categories mutated and everything else as the Split has it.
        strategies: the Strategy each mutated Flow was given, by row_id; empty when nothing evaded, and then nothing was mutated.
    """

    flows: tuple[Flow, ...]
    strategies: Mapping[int, Strategy]


def evaluation_set(ev: Eval, seed: int) -> Judged:
    """The Flows every arm of one seed judges, and the Strategy each mutated Flow was given.

    Built once per seed and handed to all four arms, which is the whole point of this module: the four Contexts judge the identical
    Flows, so a pair of their Predictions shares a `row_id` AND the traffic behind it, and `metrics.mcnemar_exact` means what its name
    says. A mutated Flow keeps its parent's row_id, by `attacker.apply`'s own rule.

    An attack Flow of a Category the Run never attacked passes through untouched rather than being dropped: there is no Strategy to
    replay on it, and judging it anyway is the only way a playbook that bought its recall at that Category's expense can be seen at all.

    The draw is seeded by the seed alone, so the set rebuilds from the source Run and this function and nothing else; `record_strategies`
    writes down which Strategy each Flow got, so it can be rebuilt without rerunning the draw at all.
    """
    strategies = ev.source.strategies[seed]
    attacked = ev.source.config.attacker.categories
    if not strategies:
        return Judged(flows=ev.judged, strategies={})
    stream = random.Random(f"{seed}:{MUTATION_KEY}")  # noqa: S311  # seeded, not secret
    chosen: dict[int, Strategy] = {}
    flows: list[Flow] = []
    for flow in ev.judged:
        if not (flow.is_attack and flow.category in attacked):
            flows.append(flow)
            continue
        strategy = stream.choice(strategies)  # noqa: S311  # seeded, not secret
        chosen[flow.row_id] = strategy
        flows.append(ev.apply(flow, strategy, ev.donors, stream))
    return Judged(flows=tuple(flows), strategies=chosen)


def record_strategies(ev: Eval, seed: int, chosen: Mapping[int, Strategy]) -> None:
    """Append one line per mutated Flow to `strategies.jsonl`, before the arms judge any of them.

    Written first for the same reason `config.json` is: the evaluation set is the claim, and a measurement that died in its second arm
    should still say exactly which traffic its first arm was judged on. The Flows absent from this file are the ones no Strategy touched,
    and every Prediction says which it was in its own `mutated` field.
    """
    for row_id, strategy in chosen.items():
        append_line(
            ev.run_dir / "strategies.jsonl",
            {
                "seed": seed,
                "row_id": row_id,
                "bucket": strategy.bucket,
                "padding_bytes": strategy.padding_bytes,
                "added_seconds": strategy.added_seconds,
                "from_round": ev.source.rounds[seed],
            },
        )


def build_detector(ev: Eval, context: Context) -> run.Detector:
    """The Detector reading one Context: Jev, or the offline stand-in when the measurement has no API key to spend.

    The offline Detector cannot read a playbook at all, so every arm that differs from another only in its Rules gives it exactly the
    same answers; it is here to exercise the measurement, never to produce one.
    """
    prompt = context.to_prompt(ev.template)
    if ev.source.config.detector.name == "jev":
        return JevDetector(prompt)
    return OfflineDetector(prompt, ev.vocabulary, ev.card["benign"])


def examples_for(ev: Eval, context: Context, seed: int) -> tuple[Flow, ...]:
    """The Examples a Context shows: the Pool Flows it chose, or `run.sample_examples` at the Run's own k when it chose none.

    The fallback is upstream's draw and not one of this module's, so the baseline arm is exactly the published Run at that k and the
    headline number stays comparable with `results/paper/`.
    """
    if context.example_ids:
        return tuple(ev.by_row_id[row_id] for row_id in context.example_ids if row_id in ev.by_row_id)
    return tuple(run.sample_examples(ev.pool, ev.source.config.detector.k, seed, ev.card["categories"]))


def cell_fields(ev: Eval, arm: Arm, detector: run.Detector, n_examples: int) -> dict[str, Any]:
    """The fields every Prediction of one arm shares: the ordinary shape of `jev_ids.records`, plus `arm` and `context_version`.

    Ordinary on purpose, so `jev_ids.metrics` reads this directory with no special case and the rows sit beside the published ones. `seed`
    is already part of that shape, so the three fields the measurement needs are two new ones and one it inherits. The fourth field a row
    carries, `mutated`, is not here: it belongs to the Flow and not to the arm, so `judge_arm` adds it per row.
    """
    return {
        "run_id": ev.run_id,
        "dataset": ev.card["name"],
        "detector": detector.name,
        "model": detector.model,
        "split": ev.source.config.arena.eval_split,
        "prompt_hash": detector.prompt_hash,
        "k": ev.source.config.detector.k,
        "seed": arm.seed,
        "repetition": 0,
        "n_examples": n_examples,
        "arm": arm.name,
        "context_version": arm.context.version,
    }


def judge_arm(ev: Eval, arm: Arm, judged: Judged) -> None:
    """One arm over one seed's evaluation set: one call and one appended row per Flow.

    Appended as they come, so a crash loses at most one Flow. Every row says in `mutated` whether the attacker's Strategies moved its
    Flow, which is what lets the table split recall into the Categories that were attacked and the ones that were only along for the
    ride. `loop.as_row` applies the source Run's `[threats] on_failure`, so a fail-closed Run's final measurement scores a failed call the
    way that Run did; no failure is INDUCED here whatever `[threats] failure_rate` says, because the induced ones would land on different
    Flows in different arms and the arms would stop being a comparison.

    Raises:
        BudgetExhausted: the measurement has spent its Detector calls.
    """
    detector = build_detector(ev, arm.context)
    examples = examples_for(ev, arm.context, arm.seed)
    cell = cell_fields(ev, arm, detector, len(examples))
    on_failure = ev.source.config.threats.on_failure
    for flow in judged.flows:
        ev.budget.spend_detector()
        measured = detector.predict(flow, examples)
        fields = {**cell, "mutated": flow.row_id in judged.strategies}
        append_prediction(ev.run_dir, loop.as_row(measured, flow, fields, on_failure))
    spent = ev.budget.spent["detector_calls"]
    print(f"seed={arm.seed} arm={arm.name} context=v{arm.context.version} flows={len(judged.flows)} calls={spent}")


def judge_seed(ev: Eval, seed: int) -> None:
    """One seed: its evaluation set built once, written down, then judged by each of the four arms in turn."""
    arms = arms_of(seed, ev.source.contexts[seed])
    judged = evaluation_set(ev, seed)
    record_strategies(ev, seed, judged.strategies)
    for arm in arms:
        append_line(
            ev.run_dir / "contexts.jsonl",
            {"seed": seed, "arm": arm.name, "rule_chars": rule_chars(arm.context), **arm.context.to_dict()},
        )
    for arm in arms:
        judge_arm(ev, arm, judged)


def preflight(run_dir: Path) -> Projection:
    """What measuring one finished Run would spend, from its config and the evaluation Split alone; no Detector is called.

    Args:
        run_dir: the finished Arena Run directory.

    Returns:
        The projection, whose `fits` is what `--dry-run` prints.
    """
    source = read_source(run_dir)
    _card, _path, flows = eval_split(source.config)
    return project(source.config, source.seeds, len(flows))


def run_final(run_dir: Path, *, results_dir: Path = EVAL_RESULTS) -> Path:
    """The final measurement of one finished Arena Run: every seed, every arm, over the same Flows; the Run directory.

    Args:
        run_dir: the finished Arena Run to measure, `results/arena/<run_id>`.
        results_dir: where the measurement's own directory is created; `results/arena-eval/` by default.

    Returns:
        `results/arena-eval/<UTC timestamp>-<dataset>-<detector>-eval/`, holding `config.json`, `contexts.jsonl`, `strategies.jsonl` and
        `predictions.jsonl`.

    Raises:
        BudgetExhausted: the measurement cannot finish under the source Run's cap; nothing is written.
        ValueError: the source Run played no Round, so it has no final Context to measure.
    """
    measurement = prepare(read_source(run_dir), results_dir)
    try:
        for seed in measurement.source.seeds:
            judge_seed(measurement, seed)
    except BudgetExhausted as exhausted:
        # The cap was checked before the first call, so reaching it here means the Split or the arms grew under the measurement's feet.
        # What was judged is already on disk, and the row counts per arm in the table are what say the measurement is incomplete.
        print(f"stopped: {exhausted}")
    print(f"done: {measurement.run_dir}")
    return measurement.run_dir


@dataclass(frozen=True)
class Cell:
    """One (seed, arm) of the table, and everything the row is computed from.

    Attributes:
        seed: the seed.
        arm: one of `ARMS`.
        rows: this arm's Predictions for that seed.
        baseline: the same seed's baseline arm, keyed by row_id, the side every arm is paired against.
        context: the Context this arm judged with, as `contexts.jsonl` holds it.
        priced: the list prices `metrics.cost_usd_per_1m` bills the tokens at.
    """

    seed: Any
    arm: str
    rows: Sequence[Prediction]
    baseline: Mapping[Any, Prediction]
    context: Mapping[str, Any]
    priced: dict[str, Any]


def eval_row(cell: Cell) -> dict[str, Any]:
    """One arm of one seed as one row: what it caught, where it caught it, what its prompt cost, and how it split from the baseline.

    Recall, the false-alarm rate, F1 and the mean `input_tokens` come from `arena.report.detection`, the very function the Rounds table
    uses, so the headline number cannot drift from the loop's own. `recall_mutated` and `recall_unmutated` cut the same attack Flows by
    whether the attacker moved them, and `metrics.recall_by_category` gives one column per Category: a playbook that bought the attacked
    Categories by losing another is visible in exactly those columns and nowhere else. The paired test is `metrics.compare_cell`, which
    counts the discordant pairs and runs `metrics.mcnemar_exact` over them; the baseline arm is paired with itself and therefore reports
    no discordant pair and p = 1, which is also the check that the pairing is complete.
    """
    spend = metrics.usage(cell.rows, cell.priced)
    paired = metrics.compare_cell(report.paired_rows(report.latest_by_flow(cell.rows), cell.baseline))
    attacks = [row for row in cell.rows if row["is_attack"] == 1]
    return {
        "run_id": cell.rows[0].get("run_id") if cell.rows else None,
        "seed": cell.seed,
        "arm": cell.arm,
        "context_version": cell.context.get("version"),
        "rules": len(cell.context.get("rules", [])),
        "rule_chars": cell.context.get("rule_chars"),
        "examples": len(cell.context.get("example_ids", [])),
        **report.detection(cell.rows),
        "mutated_flows": sum(bool(row.get("mutated")) for row in cell.rows),
        "recall_mutated": metrics.rate([row for row in attacks if row.get("mutated")]),
        "recall_unmutated": metrics.rate([row for row in attacks if not row.get("mutated")]),
        **metrics.recall_by_category(attacks),
        "cost_usd_per_1m": spend.get("cost_usd_per_1m"),
        "vs_baseline_flows": paired["pairs"],
        "vs_baseline_discordant": paired["discordant"],
        "arm_correct": paired["a_correct"],
        "baseline_correct": paired["b_correct"],
        "mcnemar_p": paired["mcnemar_p"],
    }


def summarize_eval(run_dir: Path) -> list[dict[str, Any]]:
    """One row per (seed, arm) of one measurement: the number that can be quoted, and the confounds beside it.

    Four rows per seed, in `ARMS` order, which is the order the three steps are read down: `baseline` to `examples_only` is the Examples,
    `examples_only` to `placebo` is the prompt's length, `placebo` to `final` is what the Rules say. Every row carries the mean
    `input_tokens` and the list cost of a million Flows next to the recall, because a playbook rides on every Detector call and an arm
    that gained recall while its prompt grew is two hypotheses at once; `rules` and `rule_chars` are there so a reader can check that the
    placebo really did match the final Context's shape instead of taking this module's word for it.

    `recall_<category>` is the column a regression outside the attacked Categories appears in, and `recall_mutated` against
    `recall_unmutated` is the same story in two numbers.

    The pairing is per seed and never across seeds, as `metrics.compare_cell` needs each Flow once per side.

    Args:
        run_dir: `results/arena-eval/<run_id>`, holding `contexts.jsonl` and `predictions.jsonl`.

    Returns:
        One dict per (seed, arm) in `ARMS` order within ascending seed, ready for `cli.print_csv`; a directory with no Prediction gives
        no rows.
    """
    predictions = read_predictions(run_dir)
    contexts = {(line.get("seed"), line.get("arm")): line for line in report.read_jsonl(run_dir / "contexts.jsonl")}
    priced = report.prices()
    groups = metrics.group_by_fields(predictions, ("seed", "arm"))
    rows: list[dict[str, Any]] = []
    for seed in sorted({key[0] for key in groups}, key=lambda value: metrics.none_last_key((value,))):
        baseline = report.latest_by_flow(groups.get((seed, BASELINE_ARM), []))
        for name in ARMS:
            members = groups.get((seed, name), [])
            if members:
                rows.append(eval_row(Cell(seed, name, members, baseline, contexts.get((seed, name), {}), priced)))
    return rows
