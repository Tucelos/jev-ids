"""The Arena config: the committed file, the overrides, and everything a hand edit can get wrong."""

from pathlib import Path

import pytest

from jev_ids import ROOT, dataset
from jev_ids.arena.config import ARENA_CONFIG, ArenaConfig, load_arena_config
from jev_ids.arena.gate import GatePolicy


def written(tmp_path: Path, text: str) -> Path:
    """A TOML file with `text` in it."""
    path = tmp_path / "arena.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_the_committed_file_states_every_default() -> None:
    # The point of the file: a reader who wants to know what a knob is set to reads the TOML, not the dataclasses.
    assert load_arena_config(ARENA_CONFIG) == ArenaConfig()


def test_the_gate_section_matches_the_policy_it_builds() -> None:
    # `[gate]` is `GatePolicy` in TOML. The two are kept in step by hand, so a field added to one and not the other stops here rather
    # than at the round loop, where a missing knob would silently gate on a default nobody chose.
    gate, policy = ArenaConfig().gate, GatePolicy()
    assert vars(gate) == vars(policy)


def test_the_gate_scores_on_a_split_of_its_own() -> None:
    arena = load_arena_config(ARENA_CONFIG).arena
    # The curator learns on one Split and the gate decides on another, or a Context would be scored on the very Flows it was written
    # from and every proposal would look like an improvement.
    assert arena.gate_split == "arena-val"
    assert len({arena.learn_split, arena.gate_split, arena.eval_split}) == 3


def test_the_default_budget_covers_a_default_run() -> None:
    config = load_arena_config(ARENA_CONFIG)
    card = dataset.load_config(ROOT / config.arena.dataset)
    gate_flows = len(dataset.load_split(card["dir"] / "splits" / f"{config.arena.gate_split}.csv", card))
    per_round = config.attacker.flows_per_round * config.attacker.max_queries_per_flow + gate_flows * config.curator.proposals_per_round
    worst_case = per_round * config.arena.rounds * len(config.arena.seeds)

    # The arithmetic the [budget] comment states, checked against the Split on disk. A default Run that could hit the cap would die
    # mid-Round and lose the experiment, which is the one failure the Budget exists to prevent.
    assert (gate_flows, per_round, worst_case) == (250, 1100, 11000)
    assert worst_case < config.budget.max_detector_calls


def test_an_empty_file_is_every_default(tmp_path: Path) -> None:
    assert load_arena_config(written(tmp_path, "")) == ArenaConfig()


def test_the_file_wins_and_its_scalars_become_the_field_types(tmp_path: Path) -> None:
    path = written(
        tmp_path,
        '[arena]\ndataset = "data/nf-uq-nids-v2/dataset.json"\nrounds = 3\nseeds = [7]\nresults_dir = "out"\n'
        '[detector]\nname = "offline"\nk = 0\n'
        '[attacker]\ncategories = ["r2l", "u2r"]\nobserves = "p_attack"\n'
        "[gate]\nmin_attack_flows = 10\nmax_error_rate = 0.2\n"
        '[threats]\npoisoning = true\non_failure = "closed"\n',
    )
    config = load_arena_config(path)
    assert config.arena.dataset == Path("data/nf-uq-nids-v2/dataset.json")
    assert config.arena.results_dir == Path("out")
    assert (config.arena.rounds, config.arena.seeds) == (3, (7,))
    assert (config.detector.name, config.detector.k) == ("offline", 0)
    assert config.attacker.categories == ("r2l", "u2r")
    assert (config.gate.min_attack_flows, config.gate.max_error_rate) == (10, 0.2)
    assert (config.threats.poisoning, config.threats.on_failure) == (True, "closed")
    # A section the file leaves out keeps every default, and so does a key inside a section it does touch.
    assert config.curator == ArenaConfig().curator
    assert (config.arena.learn_split, config.arena.gate_split) == ("arena", "arena-val")
    assert config.attacker.flows_per_round == 20
    assert config.gate.recall_slack == 0.0


def test_an_unknown_section_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no such section: defender"):
        load_arena_config(written(tmp_path, "[defender]\nname = 'jev'\n"))


def test_an_unknown_key_raises_and_names_what_the_section_takes(tmp_path: Path) -> None:
    # The whole reason the loader is strict: `round` instead of `rounds` would otherwise run ten Rounds and say nothing.
    with pytest.raises(ValueError, match=r"\[arena\] has no key round"):
        load_arena_config(written(tmp_path, "[arena]\nround = 3\n"))


@pytest.mark.parametrize(
    ("table", "message"),
    [
        ("[analyst]\nsample_rate = 1.5\n", r"analyst.sample_rate = 1.5: a share lives in \[0, 1\]"),
        ("[threats]\nfailure_rate = -0.1\n", r"threats.failure_rate = -0.1: a share lives in \[0, 1\]"),
        ("[gate]\nfalse_alarm_slack = 2.0\n", r"gate.false_alarm_slack = 2.0: a share lives in \[0, 1\]"),
        ("[gate]\nmax_error_rate = 1.5\n", r"gate.max_error_rate = 1.5: a share lives in \[0, 1\]"),
        ("[gate]\nrecall_slack = -0.5\n", r"gate.recall_slack = -0.5: a share lives in \[0, 1\]"),
        ("[gate]\nmin_attack_flows = 0\n", "gate.min_attack_flows = 0: a count is one or more"),
        ("[arena]\nrounds = 0\n", "arena.rounds = 0: a count is one or more"),
        ("[budget]\nmax_curator_calls = -1\n", "budget.max_curator_calls = -1: a count is one or more"),
        ("[curator]\nmax_rules = -2\n", "curator.max_rules = -2: a size is zero or more"),
    ],
)
def test_a_number_that_cannot_mean_anything_raises(tmp_path: Path, table: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        load_arena_config(written(tmp_path, table))


@pytest.mark.parametrize(
    ("table", "message"),
    [
        ("[detector]\nname = 'random_forest'\n", "detector.name = 'random_forest': one of jev, offline"),
        ("[attacker]\nkind = 'gradient'\n", "attacker.kind = 'gradient': one of llm, mimicry"),
        ("[attacker]\nobserves = 'category'\n", "attacker.observes = 'category': one of p_attack, verdict"),
        ("[curator]\nkind = 'human'\n", "curator.kind = 'human': one of heuristic, llm"),
        ("[gate]\nmode = 'open'\n", "gate.mode = 'open': one of guarded, none"),
        ("[threats]\non_failure = 'fail_open'\n", "threats.on_failure = 'fail_open': one of closed, open"),
    ],
)
def test_a_kind_the_arena_cannot_build_raises(tmp_path: Path, table: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        load_arena_config(written(tmp_path, table))


def test_zero_is_allowed_where_it_means_something(tmp_path: Path) -> None:
    # k = 0 is zero-shot, an analyst with no budget looks at nothing, and a label that lags no Round arrives at once.
    path = written(tmp_path, "[detector]\nk = 0\n[analyst]\nalert_budget = 0\ndelay_rounds = 0\nlabel_noise = 0.0\n")
    config = load_arena_config(path)
    assert (config.detector.k, config.analyst.alert_budget, config.analyst.delay_rounds) == (0, 0, 0)
