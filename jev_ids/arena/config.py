"""Every knob of an Arena, in one TOML file the user edits by hand.

In reading order:

- `ArenaSettings` ... `ThreatSettings`: one frozen dataclass per section of the file, each field a knob with its default.
- `ArenaConfig`: the eight sections together, what one Arena is configured by.
- `section` and `convert`: one section of the parsed document as its dataclass, with the TOML scalars turned into the field's type.
- `check_ranges` and `check_choices`: the numbers that must be fractions or counts, and the fields that name one of a fixed set.
- `load_arena_config`: the file as an `ArenaConfig`.

`configs/arena.toml` states every default, so the file itself is the documentation of what can be changed; nothing here reads an
environment variable and nothing outside this module hard-codes a number. Rounds, sizes and budget move without touching code.
"""

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, get_origin, get_type_hints

from jev_ids import ROOT

# Where the committed file lives; the CLI defaults to it and the tests write their own elsewhere.
ARENA_CONFIG = ROOT / "configs" / "arena.toml"


@dataclass(frozen=True)
class ArenaSettings:
    """`[arena]`: which Dataset and Splits the loop runs on, and how long it runs.

    Attributes:
        dataset: the card of the Dataset, `data/<name>/dataset.json`.
        learn_split: the Split the attacker and the curator work on.
        gate_split: the held-out Split a proposed Context is scored on, disjoint from both the others; the gate must never judge a
            Context on the very Flows the curator learned from.
        eval_split: the Split a kept Context is finally measured on, never learned from.
        rounds: how many Rounds one Run of the Arena plays.
        seeds: the seeds of the Example draws and of the attacker's mutations.
        results_dir: where the Round records are written.
    """

    dataset: Path = Path("data/nsl-kdd/dataset.json")
    learn_split: str = "arena"
    gate_split: str = "arena-val"
    eval_split: str = "paper"
    rounds: int = 10
    seeds: tuple[int, ...] = (0,)
    results_dir: Path = Path("results/arena")


@dataclass(frozen=True)
class DetectorSettings:
    """`[detector]`: the Detector under attack.

    Attributes:
        name: `jev` for the real thing, `offline` for the free stand-in that proves the loop runs.
        k: Examples per Category to draw when the Context chooses none of its own.
    """

    name: str = "jev"
    k: int = 1


@dataclass(frozen=True)
class AttackerSettings:
    """`[attacker]`: who mutates the attack Flows, and how hard.

    Attributes:
        kind: `mimicry` moves a Flow toward benign traffic, `llm` asks a model for the next mutation.
        flows_per_round: attack Flows attacked in one Round.
        max_queries_per_flow: Detector calls the attacker may spend on one Flow before giving up on it.
        observes: what the attacker is told back, the Verdict alone or the whole p_attack.
        categories: the Categories whose Flows are attacked.
    """

    kind: str = "mimicry"
    flows_per_round: int = 20
    max_queries_per_flow: int = 30
    observes: str = "verdict"
    categories: tuple[str, ...] = ("r2l",)


@dataclass(frozen=True)
class CuratorSettings:
    """`[curator]`: who rewrites the Context between Rounds.

    Attributes:
        kind: `llm` asks a model for a new Context, `heuristic` builds one from the labels alone.
        provider: the provider of the curator's model, as `detectors.llm` names them.
        model: the provider's model id; empty means the provider default.
        max_rules: how long the playbook may grow.
        max_examples: how many Pool Flows a Context may choose as Examples.
        proposals_per_round: how many Contexts the curator proposes per Round, for the gate to choose between.
    """

    kind: str = "llm"
    provider: str = "deepseek"
    model: str = ""
    max_rules: int = 15
    max_examples: int = 10
    proposals_per_round: int = 2


@dataclass(frozen=True)
class AnalystSettings:
    """`[analyst]`: the simulated human whose labels the curator learns from.

    Attributes:
        alert_budget: alerts one Round's analyst can look at.
        sample_rate: the share of the Flows that raised no alert that get looked at anyway.
        delay_rounds: how many Rounds a label lags behind the Round that produced it.
        label_noise: the share of labels the analyst gets wrong.
    """

    alert_budget: int = 50
    sample_rate: float = 0.1
    delay_rounds: int = 1
    label_noise: float = 0.0


@dataclass(frozen=True)
class GateSettings:
    """`[gate]`: whether a proposed Context is kept.

    Field for field the counterpart of `arena.gate.GatePolicy`, which the round loop builds from this; the names and the defaults are
    kept in step with it by hand rather than by an import, so a config stays plain data and reads nothing of the gate's logic.

    Attributes:
        mode: `guarded` applies the rule below, `none` keeps every proposal that is not broken.
        recall_slack: how much recall a proposal may give up, as an absolute difference of rates.
        false_alarm_slack: how far the false alarm rate may rise, as an absolute difference of rates.
        min_attack_flows: the attack Flows the gate needs before it will decide anything at all.
        max_error_rate: the share of failed calls a proposal may have; checked in both modes.
    """

    mode: str = "guarded"
    recall_slack: float = 0.0
    false_alarm_slack: float = 0.02
    min_attack_flows: int = 30
    max_error_rate: float = 0.05


@dataclass(frozen=True)
class BudgetSettings:
    """`[budget]`: the caps `arena.budget.Budget` enforces.

    Attributes:
        max_detector_calls: Detector calls one Run of the Arena may make, attacker and evaluation together.
        max_curator_calls: curator calls one Run of the Arena may make.
    """

    max_detector_calls: int = 20000
    max_curator_calls: int = 200


@dataclass(frozen=True)
class ThreatSettings:
    """`[threats]`: the two ways the loop is asked to misbehave on purpose.

    Attributes:
        poisoning: whether the attacker also feeds the analyst mislabeled Flows.
        poisoned_fraction: the share of the attacker's Flows that are poison when it does.
        on_failure: what a failed Detector call counts as, `open` for `normal` or `closed` for an alert. Upstream always failed open
            (`records.complete_prediction` leaves no Verdict and `metrics.verdict` reads that as normal), so `open` is what the
            published rows mean; `closed` is the other horn of the dilemma, and under a flood of failures the two separate a system
            that misses attacks from one that drowns its analyst in false alarms.
        failure_rate: the share of Detector calls made to fail, to exercise that path.
    """

    poisoning: bool = False
    poisoned_fraction: float = 0.1
    on_failure: str = "open"
    failure_rate: float = 0.0


@dataclass(frozen=True)
class ArenaConfig:
    """The eight sections of `configs/arena.toml`, what one Arena is configured by.

    The field names are the section names, so the loader needs no second list of them.

    Attributes:
        arena: `[arena]`, the Dataset, the Splits and the number of Rounds.
        detector: `[detector]`, the Detector under attack.
        attacker: `[attacker]`, who mutates the Flows.
        curator: `[curator]`, who rewrites the Context.
        analyst: `[analyst]`, the simulated human behind the labels.
        gate: `[gate]`, whether a proposal is kept.
        budget: `[budget]`, the hard caps.
        threats: `[threats]`, poisoning and induced failures.
    """

    arena: ArenaSettings = ArenaSettings()
    detector: DetectorSettings = DetectorSettings()
    attacker: AttackerSettings = AttackerSettings()
    curator: CuratorSettings = CuratorSettings()
    analyst: AnalystSettings = AnalystSettings()
    gate: GateSettings = GateSettings()
    budget: BudgetSettings = BudgetSettings()
    threats: ThreatSettings = ThreatSettings()


def convert(value: Any, annotation: Any) -> Any:
    """One TOML value as the field's type: TOML has no path and no tuple, everything else it already has."""
    if annotation is Path:
        return Path(value)
    if get_origin(annotation) is tuple:
        return tuple(value)
    return value


def section[T](kind: type[T], document: Mapping[str, Any], name: str) -> T:
    """The `[name]` table of the document as a `kind`; an absent table means every default.

    An unknown key raises instead of being ignored. This is a file the user edits by hand between Runs, and a silent typo there is the
    worst failure mode the Arena has: the Run would finish, look healthy and answer a question nobody asked.
    """
    table: Mapping[str, Any] = document.get(name, {})
    types = get_type_hints(kind)
    unknown = sorted(set(table) - set(types))
    if unknown:
        raise ValueError(f"[{name}] has no key {', '.join(unknown)}; it takes {', '.join(sorted(types))}")
    return kind(**{key: convert(value, types[key]) for key, value in table.items()})


def check_ranges(config: ArenaConfig) -> None:
    """Refuse a number that cannot mean anything: a share outside [0, 1], a count below one, a size below zero."""
    fractions = {
        "analyst.sample_rate": config.analyst.sample_rate,
        "analyst.label_noise": config.analyst.label_noise,
        "gate.recall_slack": config.gate.recall_slack,
        "gate.false_alarm_slack": config.gate.false_alarm_slack,
        "gate.max_error_rate": config.gate.max_error_rate,
        "threats.poisoned_fraction": config.threats.poisoned_fraction,
        "threats.failure_rate": config.threats.failure_rate,
    }
    counts = {
        "arena.rounds": config.arena.rounds,
        "attacker.flows_per_round": config.attacker.flows_per_round,
        "attacker.max_queries_per_flow": config.attacker.max_queries_per_flow,
        "curator.proposals_per_round": config.curator.proposals_per_round,
        "gate.min_attack_flows": config.gate.min_attack_flows,
        "budget.max_detector_calls": config.budget.max_detector_calls,
        "budget.max_curator_calls": config.budget.max_curator_calls,
    }
    # Zero is a meaning of its own here: k = 0 is zero-shot, an empty playbook, an analyst who looks at nothing, a label that never lags.
    sizes = {
        "detector.k": config.detector.k,
        "curator.max_rules": config.curator.max_rules,
        "curator.max_examples": config.curator.max_examples,
        "analyst.alert_budget": config.analyst.alert_budget,
        "analyst.delay_rounds": config.analyst.delay_rounds,
    }
    for label, fraction in fractions.items():
        if not 0.0 <= fraction <= 1.0:
            raise ValueError(f"{label} = {fraction}: a share lives in [0, 1]")
    for label, count in counts.items():
        if count < 1:
            raise ValueError(f"{label} = {count}: a count is one or more")
    for label, size in sizes.items():
        if size < 0:
            raise ValueError(f"{label} = {size}: a size is zero or more")


def check_choices(config: ArenaConfig) -> None:
    """Refuse a field that names something the Arena cannot build; a misspelled kind is a typo like any other."""
    choices = {
        "detector.name": (config.detector.name, ("jev", "offline")),
        "attacker.kind": (config.attacker.kind, ("llm", "mimicry")),
        "attacker.observes": (config.attacker.observes, ("p_attack", "verdict")),
        "curator.kind": (config.curator.kind, ("heuristic", "llm")),
        "gate.mode": (config.gate.mode, ("guarded", "none")),
        "threats.on_failure": (config.threats.on_failure, ("closed", "open")),
    }
    for label, (named, allowed) in choices.items():
        if named not in allowed:
            raise ValueError(f"{label} = {named!r}: one of {', '.join(allowed)}")


def load_arena_config(path: Path) -> ArenaConfig:
    """Every knob of one Arena, read from its TOML file and checked.

    Args:
        path: the file, `configs/arena.toml` or a copy of it.

    Returns:
        The eight sections, each field either the file's value or the dataclass default.

    Raises:
        ValueError: the file names a section or a key the Arena does not have, or a number or a kind it cannot use.
    """
    with path.open("rb") as handle:
        document: dict[str, Any] = tomllib.load(handle)
    unknown = sorted(set(document) - set(get_type_hints(ArenaConfig)))
    if unknown:
        raise ValueError(f"{path}: no such section: {', '.join(unknown)}")
    config = ArenaConfig(
        arena=section(ArenaSettings, document, "arena"),
        detector=section(DetectorSettings, document, "detector"),
        attacker=section(AttackerSettings, document, "attacker"),
        curator=section(CuratorSettings, document, "curator"),
        analyst=section(AnalystSettings, document, "analyst"),
        gate=section(GateSettings, document, "gate"),
        budget=section(BudgetSettings, document, "budget"),
        threats=section(ThreatSettings, document, "threats"),
    )
    check_ranges(config)
    check_choices(config)
    return config
