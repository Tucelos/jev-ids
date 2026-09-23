"""The round loop: the pre-flight projection, one Round end to end, the gate's seeds, the threat arms and the Budget's last word."""

import inspect
import json
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

from jev_ids import cli, metrics
from jev_ids.arena import gate, loop
from jev_ids.arena.budget import BudgetExhausted
from jev_ids.arena.config import (
    ARENA_CONFIG,
    AnalystSettings,
    ArenaConfig,
    ArenaSettings,
    AttackerSettings,
    BudgetSettings,
    CuratorSettings,
    DetectorSettings,
    GateSettings,
    ThreatSettings,
    load_arena_config,
)
from jev_ids.arena.context import Context, Rule
from jev_ids.arena.curator import Evidence, Proposal
from jev_ids.arena.records import STAGES, read_rounds
from jev_ids.dataset import Flow
from jev_ids.records import Prediction, read_predictions
from tests.helpers import CONFIG, JEV_PROMPT, make_flow, write_dataset

# The synthetic Dataset: a Pool of ten Flows per Category whose three attribute values are its Category's index, so the offline forest
# separates them perfectly and every Verdict below is a consequence of the loop and not of a coin toss.
CATEGORIES = ("normal", "dos", "probe")
BENIGN_VALUES = "0,0,0"


@dataclass(frozen=True)
class FakeStrategy:
    """A knob setting in the attacker's shape."""

    bucket: str = "slow-narrow"
    padding_bytes: int = 0
    added_seconds: int = 0


@dataclass(frozen=True)
class FakeEvasion:
    """One attacked Flow in the attacker's shape."""

    row_id: int
    evaded: bool
    strategy: FakeStrategy | None
    queries: int
    start_p_attack: float | None
    final_p_attack: float | None


class FakeAttacker:
    """An attacker in the contract's shape: it probes `queries` times and reports the Strategy it was told to report."""

    name = "fake"

    def __init__(self, *, queries: int = 2, evades: bool = True) -> None:
        self.queries = queries
        self.evades = evades

    def evade(self, flow: Flow, judge: Any, max_queries: int) -> FakeEvasion:
        """Spend `queries` probes on the Flow, bounded by `max_queries` as the contract asks."""
        rows: list[Prediction] = [judge(flow) for _ in range(min(self.queries, max_queries))]
        return FakeEvasion(
            row_id=flow.row_id,
            evaded=self.evades,
            strategy=FakeStrategy() if self.evades else None,
            queries=len(rows),
            start_p_attack=rows[0].get("p_attack"),
            final_p_attack=rows[-1].get("p_attack"),
        )


class GreedyAttacker:
    """An attacker that ignores `max_queries`: the case the Budget exists for, and the only way to make it fire."""

    name = "greedy"

    def __init__(self, *, queries: int) -> None:
        self.queries = queries

    def evade(self, flow: Flow, judge: Any, max_queries: int) -> FakeEvasion:
        """Spend far more than the loop asked for; the Budget is what stops it."""
        for _ in range(self.queries):
            judge(flow)
        return FakeEvasion(row_id=flow.row_id, evaded=False, strategy=None, queries=self.queries, start_p_attack=None, final_p_attack=None)


class FakeCurator:
    """A curator that answers with the Proposals it was built with and keeps every Evidence it was shown."""

    name = "fake"
    model = "fake-1"

    def __init__(self, proposals: Sequence[Proposal]) -> None:
        self.proposals = list(proposals)
        self.seen: list[Evidence] = []

    def propose(self, context: Context, evidence: Evidence, count: int) -> list[Proposal]:
        """Keep the Evidence and hand back the fixed Proposals."""
        self.seen.append(evidence)
        return self.proposals[:count]


def fake_apply(flow: Flow, strategy: FakeStrategy, donors: Sequence[Flow], rng: Any) -> Flow:
    """Perfect mimicry: the attack Flow takes a benign Flow's values and keeps its row_id, as the pairing requires."""
    assert donors and strategy.bucket
    return replace(flow, attributes_csv=BENIGN_VALUES)


class FakeModule:
    """`jev_ids.arena.attacker` as the loop needs it: the donors, one class per kind and the `apply` function."""

    def __init__(self, attacker: Any = None) -> None:
        self.attacker = attacker or FakeAttacker()
        self.built: list[tuple[str, int]] = []

    def donors_from_pool(self, flows: Sequence[Flow], config: Any) -> list[Flow]:
        """The donors, which for a fake are the benign Pool Flows themselves."""
        return [flow for flow in flows if not flow.is_attack]

    def MimicryAttacker(self, donors: Any, *, observes: str, seed: int) -> Any:
        """The attacker the loop builds per seed; the arguments are kept so a test can see which seeds were used."""
        self.built.append((observes, seed))
        return self.attacker

    apply = staticmethod(fake_apply)


def make_dataset(tmp_path: Path) -> Path:
    """A Pool, a learn Split and a held-out Split under `tmp_path`; the Card."""
    pool = [make_flow(index, CATEGORIES[index % 3], value=str(index % 3)) for index in range(30)]
    learn = [make_flow(100 + index, "normal" if index < 12 else "dos", value="0" if index < 12 else "1") for index in range(20)]
    held = [make_flow(200 + index, "normal" if index < 10 else "dos", value="0" if index < 10 else "1") for index in range(20)]
    return write_dataset(tmp_path / "data", CONFIG, {"pool": pool, "arena": learn, "arena-val": held})


def make_config(card: Path, tmp_path: Path) -> ArenaConfig:
    """The Arena the tests play: four attacked Flows, one proposal, an analyst who looks at everything and no delay."""
    return ArenaConfig(
        arena=ArenaSettings(dataset=card, learn_split="arena", gate_split="arena-val", rounds=1, seeds=(0,), results_dir=tmp_path / "out"),
        detector=DetectorSettings(name="offline", k=1),
        attacker=AttackerSettings(kind="mimicry", flows_per_round=4, max_queries_per_flow=3, categories=("dos",)),
        curator=CuratorSettings(kind="heuristic", proposals_per_round=1, max_rules=5, max_examples=5),
        analyst=AnalystSettings(alert_budget=50, sample_rate=1.0, delay_rounds=0, label_noise=0.0),
        gate=GateSettings(mode="guarded", min_attack_flows=1),
        budget=BudgetSettings(max_detector_calls=10000, max_curator_calls=100),
        threats=ThreatSettings(),
    )


def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, attacker: Any = None, **sections: Any) -> ArenaConfig:
    """A synthetic Arena with the attacker module faked out; the config, with any section replaced."""
    card = make_dataset(tmp_path)
    prompts = tmp_path / "prompts" / CONFIG["name"]
    prompts.mkdir(parents=True)
    (prompts / "jev.json").write_text(JEV_PROMPT["text"], encoding="utf-8")
    module = FakeModule(attacker)

    def imported() -> FakeModule:
        return module

    # `prompts/` hangs off ROOT, and the attacker is another package: both are reached through a module global, so both are patched, and
    # the one seam means a test never needs the constraint model or a donor bucket.
    monkeypatch.setattr(loop, "ROOT", tmp_path)
    monkeypatch.setattr(loop, "attacker_module", imported)
    return replace(make_config(card, tmp_path), **sections)


def install_curator(monkeypatch: pytest.MonkeyPatch, curator: FakeCurator) -> None:
    """Hand the loop this curator for every seed of the Run."""

    def build(arena: loop.Arena, seed: int) -> Any:
        return curator

    monkeypatch.setattr(loop, "build_curator", build)


def test_a_run_that_cannot_finish_is_refused_before_the_first_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = setup(tmp_path, monkeypatch, budget=BudgetSettings(max_detector_calls=50, max_curator_calls=100))
    projection = loop.preflight(config)
    # 4 x 3 attacker + 20 traffic + 20 x (1 proposal + the incumbent) gate, per seed per Round.
    assert (projection.attacker, projection.traffic, projection.gate) == (12, 20, 40)
    assert projection.detector_calls == 72
    assert projection.to_dict()["fits"] is False
    with pytest.raises(BudgetExhausted, match="detector_calls: 72 projected against a cap of 50"):
        loop.run_arena(config)
    # An experiment that dies in Round 7 is worth less than one never begun, so a refused Run leaves no directory behind either.
    assert not (tmp_path / "out").exists()


def test_the_curator_cap_is_projected_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = setup(tmp_path, monkeypatch, budget=BudgetSettings(max_detector_calls=10000, max_curator_calls=5))
    config = replace(config, arena=replace(config.arena, rounds=3, seeds=(0, 1)))
    projection = loop.preflight(config)
    assert (projection.curator_calls, projection.rounds, projection.seeds) == (6, 3, 2)
    assert "curator_calls: 6 projected against a cap of 5" in (projection.shortfall or "")


def test_the_committed_defaults_fit_their_own_cap() -> None:
    # The shipped configs/arena.toml must describe a Run that can finish, or the first thing a reader runs refuses to start.
    projection = loop.preflight(load_arena_config(ARENA_CONFIG))
    assert projection.shortfall is None
    assert projection.traffic == 550
    assert projection.detector_calls == (600 + 550 + 750) * 10


def test_one_round_runs_end_to_end_and_writes_the_four_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = loop.run_arena(setup(tmp_path, monkeypatch))

    stored = json.loads((run_dir / "config.json").read_text("utf-8"))
    assert stored["projection"]["fits"] is True
    assert stored["config"]["attacker"]["flows_per_round"] == 4
    assert len(stored["inputs"]["learn_split"]) == 64
    assert stored["inputs"]["curator_prompt"] is None  # the heuristic baseline reads no prompt

    rounds = read_rounds(run_dir)
    assert len(rounds) == 1
    record = rounds[0]
    assert (record["seed"], record["round"], record["context"]["version"]) == (0, 1, 0)
    assert len(record["prompt_hash"]) == 64
    assert (record["attack"]["flows"], record["attack"]["evaded"], record["attack"]["evasion_rate"]) == (4, 4, 1.0)
    assert record["attack"]["queries"] == 8
    assert record["attack"]["strategies"][0]["bucket"] == "slow-narrow"
    # Every Flow was mimicked into benign traffic, so nothing alerted and the analyst's whole pass is quiet Flows.
    assert record["analyst"] == {"reviewed": 20, "alerts_reviewed": 0, "quiet_reviewed": 20, "poisoned": 0}
    assert record["shortlist"]["size"] > 0
    assert "per missed record" in record["shortlist"]["how"]
    assert (record["curator"]["kind"], record["curator"]["model"], record["curator"]["proposals"]) == ("heuristic", "", 1)
    assert record["curator"]["error"] is None
    assert "8 of them reported as attacks" in record["curator"]["notes"][0]
    # The Examples the heuristic chose are all attacks, so the candidate alerts on everything: recall bought with every benign Flow.
    assert record["gate"][0]["accepted"] is False
    assert "false alarms rose" in record["gate"][0]["reason"]
    assert record["accepted_version"] == 0
    assert record["budget"] == {"detector_calls": 68, "max_detector_calls": 10000, "curator_calls": 1, "max_curator_calls": 100}

    rows = read_predictions(run_dir)
    # 20 traffic Flows plus 20 held-out Flows for the incumbent and 20 for the candidate; the attacker's 8 probes leave no row.
    assert len(rows) == 60
    assert {row["arena_stage"] for row in rows} == set(STAGES)
    assert {row["round"] for row in rows} == {1}
    assert {(row["arena_stage"], row["context_version"]) for row in rows} == {("traffic", 0), ("gate-incumbent", 0), ("gate-candidate", 1)}
    assert {row["split"] for row in rows if row["arena_stage"] == "traffic"} == {"arena"}
    assert {row["split"] for row in rows if row["arena_stage"] != "traffic"} == {"arena-val"}
    # The ordinary Prediction shape: jev_ids.metrics reads an Arena Run with no special case.
    summary = metrics.summarize(rows)
    assert [item["split"] for item in summary] == ["arena", "arena-val"]
    assert summary[0]["flows"] == 20

    contexts = [json.loads(line) for line in (run_dir / "contexts.jsonl").read_text("utf-8").splitlines()]
    assert [(item["version"], item["accepted"]) for item in contexts] == [(0, True), (1, False)]


def test_a_rejected_proposal_rolls_back_to_the_incumbent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = setup(tmp_path, monkeypatch)
    run_dir = loop.run_arena(replace(config, arena=replace(config.arena, rounds=2)))
    rounds = read_rounds(run_dir)
    assert [item["round"] for item in rounds] == [1, 2]
    # Round 2 is judged under version 0 again: the Context in force is the one the gate refused to replace.
    assert [item["context"]["version"] for item in rounds] == [0, 0]
    assert [item["accepted_version"] for item in rounds] == [0, 0]
    assert [item["gate"][0]["accepted"] for item in rounds] == [False, False]
    contexts = [json.loads(line) for line in (run_dir / "contexts.jsonl").read_text("utf-8").splitlines()]
    # The rejected proposals are kept anyway, and their versions never repeat.
    assert [(item["version"], item["accepted"], item["parent"]) for item in contexts] == [(0, True, None), (1, False, 0), (2, False, 0)]


def test_the_best_accepted_proposal_becomes_the_context_in_force(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Two proposals that change the playbook only: the offline Detector cannot read a rule, so both judge the held-out Flows exactly as
    # the incumbent does, both are accepted, and `best` breaks the tie on the lower version.
    curator = FakeCurator(
        [
            Proposal(rules=(Rule("r1", "first", 1),), example_ids=(), note="one"),
            Proposal(rules=(Rule("r1", "second", 1),), example_ids=(), note="two"),
        ]
    )
    config = setup(tmp_path, monkeypatch)
    config = replace(config, arena=replace(config.arena, rounds=2), curator=replace(config.curator, proposals_per_round=2))
    install_curator(monkeypatch, curator)
    run_dir = loop.run_arena(config)
    rounds = read_rounds(run_dir)
    assert [verdict["accepted"] for verdict in rounds[0]["gate"]] == [True, True]
    assert rounds[0]["accepted_version"] == 1
    # Round 2 is judged under the accepted Context, playbook and all, and its Rule travels in the record.
    assert rounds[1]["context"]["version"] == 1
    assert rounds[1]["context"]["rules"] == [{"id": "r1", "text": "first", "added_round": 1}]
    assert rounds[0]["prompt_hash"] != rounds[1]["prompt_hash"]
    assert [item.round_index for item in curator.seen] == [1, 2]


def test_the_gate_judges_one_seed_at_a_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[Sequence[Prediction], Sequence[Prediction]]] = []
    evaluate = gate.evaluate

    def spy(
        candidate: Sequence[Prediction], incumbent: Sequence[Prediction], *, policy: gate.GatePolicy = gate.DEFAULT_POLICY
    ) -> gate.GateVerdict:
        seen.append((candidate, incumbent))
        return evaluate(candidate, incumbent, policy=policy)

    config = setup(tmp_path, monkeypatch)
    monkeypatch.setattr(loop.gate, "evaluate", spy)
    loop.run_arena(replace(config, arena=replace(config.arena, seeds=(0, 1))))
    assert len(seen) == 2
    for candidate, incumbent in seen:
        # Predictions pooled across seeds would silently fall back to the unpaired rule and the McNemar test would be lost.
        assert {row["seed"] for row in candidate} == {row["seed"] for row in incumbent}
        assert len({row["seed"] for row in candidate}) == 1
        assert gate.pairing(candidate, incumbent) is not None
    assert {candidate[0]["seed"] for candidate, _ in seen} == {0, 1}


def test_poisoning_reaches_the_curator_only_through_the_projection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    curator = FakeCurator([])
    config = setup(tmp_path, monkeypatch, threats=ThreatSettings(poisoning=True, poisoned_fraction=1.0))
    install_curator(monkeypatch, curator)
    run_dir = loop.run_arena(config)
    evidence = curator.seen[0]
    attacks = [item for item in evidence.observations if item.row_id >= 112]
    assert len(attacks) == 8
    # Every attack Flow was relabeled benign: the curator is being taught a blind spot and cannot tell.
    assert {item.label for item in attacks} == {"normal"}
    # `for_curator` is the boundary: neither the truth nor the tampering has anywhere to travel.
    assert all(not hasattr(item, "true_category") and not hasattr(item, "poisoned") for item in evidence.observations)
    assert not hasattr(evidence, "true_category")
    assert read_rounds(run_dir)[0]["analyst"]["poisoned"] == 8
    # The shortlist is drawn from what the analyst reported, so a poisoned Round offers no missed Category at all.
    assert "per missed record" in read_rounds(run_dir)[0]["shortlist"]["how"]


def test_without_poisoning_the_same_round_reports_the_attacks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    curator = FakeCurator([])
    config = setup(tmp_path, monkeypatch)
    install_curator(monkeypatch, curator)
    run_dir = loop.run_arena(config)
    attacks = [item for item in curator.seen[0].observations if item.row_id >= 112]
    assert {item.label for item in attacks} == {"dos"}
    assert read_rounds(run_dir)[0]["analyst"]["poisoned"] == 0
    # Round-wide counts beside the analyst's own: the eight misses are what the Detector let through, reviewed or not.
    assert (curator.seen[0].misses, curator.seen[0].false_alarms) == (8, 0)


def test_a_failed_call_fails_open_as_upstream_does(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = setup(tmp_path, monkeypatch, threats=ThreatSettings(failure_rate=1.0, on_failure="open"))
    run_dir = loop.run_arena(config)
    rows = read_predictions(run_dir)
    assert all(row["error"] == loop.INDUCED_FAILURE for row in rows)
    # No Verdict at all, which `metrics.verdict` reads as normal: the fail-open the published rows mean.
    assert {row["classification_verdict"] for row in rows} == {None}
    assert {metrics.verdict(row) for row in rows} == {0}
    # A Context that answers nothing is not a working Context, whatever its false-alarm rate looks like.
    assert "of the candidate's calls failed" in read_rounds(run_dir)[0]["gate"][0]["reason"]


def test_a_failed_call_can_fail_closed_instead(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = setup(tmp_path, monkeypatch, threats=ThreatSettings(failure_rate=1.0, on_failure="closed"))
    run_dir = loop.run_arena(config)
    rows = read_predictions(run_dir)
    assert all(row["error"] == loop.INDUCED_FAILURE for row in rows)
    # The other horn: the same failures raise alerts, so the analyst drowns instead of the attacks getting through.
    assert {row["classification_verdict"] for row in rows} == {1}
    assert {metrics.verdict(row) for row in rows} == {1}
    assert read_rounds(run_dir)[0]["analyst"]["alerts_reviewed"] == 20


def test_an_exhausted_budget_ends_the_run_with_the_round_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # An attacker that spends 25 calls a Flow where the loop allowed 3: the projection is a worst case over a well-behaved attacker, so
    # this is the case the Budget itself exists for, and the only way to make it fire.
    config = setup(
        tmp_path,
        monkeypatch,
        attacker=GreedyAttacker(queries=25),
        budget=BudgetSettings(max_detector_calls=216, max_curator_calls=100),
    )
    run_dir = loop.run_arena(replace(config, arena=replace(config.arena, rounds=3)))
    rounds = read_rounds(run_dir)
    # Three Rounds were asked for; the Budget stopped the Run in the second, and the first is on disk untouched.
    assert len(rounds) == 2
    assert (rounds[0]["attack"]["flows"], rounds[0]["attack"]["queries"]) == (4, 100)
    assert rounds[0]["budget"]["detector_calls"] == 120
    # Nothing evaded, so nothing was mutated and the Detector caught the attacks: a Round with no miss teaches the curator nothing.
    assert rounds[0]["analyst"]["alerts_reviewed"] == 8
    assert rounds[0]["curator"]["proposals"] == 0
    # The Round that died wrote the three Flows the attacker did get through, and rolled nothing forward.
    assert (rounds[1]["attack"]["flows"], rounds[1]["attack"]["queries"]) == (3, 75)
    assert rounds[1]["budget"]["detector_calls"] == rounds[1]["budget"]["max_detector_calls"] == 216
    assert rounds[1]["accepted_version"] == 0
    assert rounds[1]["gate"] == []
    # The arm is named even in the Round that never reached its curator, so a reader aggregating by `kind` sees no empty column.
    assert rounds[1]["curator"] == {"kind": "heuristic", "model": "", "proposals": 0, "error": None, "notes": []}


def test_a_context_that_chose_examples_shows_them_and_the_baseline_takes_the_upstream_draw(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = setup(tmp_path, monkeypatch)
    arena = loop.prepare(config)
    baseline = loop.examples_for(arena, Context(version=0), seed=0)
    # Version 0 behaves exactly as an upstream run at that k: one Example per Category, from `run.sample_examples`.
    assert sorted(flow.category for flow in baseline) == sorted(CONFIG["categories"])
    chosen = loop.examples_for(arena, Context(version=1, example_ids=(3, 4)), seed=0)
    assert [flow.row_id for flow in chosen] == [3, 4]
    # An id the Pool does not hold is dropped rather than crashing the Round it was proposed in.
    assert loop.examples_for(arena, Context(version=2, example_ids=(9999,)), seed=0) == ()


def test_the_run_can_be_wired_to_jev_and_to_the_llm_curator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The two arms every Run above replaced with a free stand-in, built here and called nowhere: a typo in either branch would otherwise
    # be found only by a Run that costs money.
    config = setup(tmp_path, monkeypatch)
    arena = loop.prepare(config)
    context = Context(version=0)
    jev = loop.build_detector(replace(arena, config=replace(config, detector=replace(config.detector, name="jev"))), context)
    assert jev.name == "jev"
    # The Detector wears the Context's rendered prompt, so every row it writes can be traced to the version that produced it.
    assert jev.prompt_hash == context.to_prompt(arena.template)["sha256"]
    asking = replace(arena, config=replace(config, curator=replace(config.curator, kind="llm")), curator_prompt=JEV_PROMPT)
    assert loop.build_curator(asking, 0).name == "llm:deepseek"


def test_the_llm_curator_needs_its_prompt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = setup(tmp_path, monkeypatch)
    arena = loop.prepare(config)
    asking = replace(arena, config=replace(config, curator=replace(config.curator, kind="llm")), curator_prompt=None)
    with pytest.raises(ValueError, match="curator.md"):
        loop.build_curator(asking, 0)


def test_the_attacker_module_is_loaded_by_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = FakeModule()

    def imported(name: str) -> FakeModule:
        return module

    monkeypatch.setattr(loop, "import_module", imported)
    config = make_config(tmp_path / "card.json", tmp_path)
    assert loop.build_attacker(config, loop.load_donors(CONFIG, []), 2).name == "fake"
    assert module.built == [("verdict", 2)]
    # `[attacker] kind = "llm"` is a config the Arena accepts and the attacker package has no class for; it says so rather than guessing.
    with pytest.raises(NotImplementedError, match="LLMAttacker"):
        loop.build_attacker(replace(config, attacker=replace(config.attacker, kind="llm")), None, 0)


def test_the_real_attacker_satisfies_the_contract_the_loop_calls_it_through() -> None:
    # The loop is written to a contract and imports the attacker by name, so nothing else in it would notice that module changing shape.
    # This is the one test that would: it calls no Detector, reads no Dataset and needs no key.
    module = loop.attacker_module()
    assert list(inspect.signature(module.apply).parameters) == ["flow", "strategy", "donors", "rng"]
    assert list(inspect.signature(module.donors_from_pool).parameters) == ["flows", "config"]
    assert list(inspect.signature(module.MimicryAttacker).parameters) == ["donors", "observes", "seed"]
    assert list(inspect.signature(module.MimicryAttacker.evade).parameters) == ["self", "flow", "judge", "max_queries"]
    assert module.MimicryAttacker.name == "mimicry"
    assert {"row_id", "evaded", "strategy", "queries", "start_p_attack", "final_p_attack"} <= set(module.Evasion.__dataclass_fields__)
    assert {"bucket", "padding_bytes", "added_seconds"} <= set(module.Strategy.__dataclass_fields__)


def test_the_cli_dry_run_prints_the_projection_and_calls_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = setup(tmp_path, monkeypatch)
    toml = tmp_path / "arena.toml"
    toml.write_text(
        "[arena]\n"
        f'dataset = "{config.arena.dataset.as_posix()}"\n'
        'learn_split = "arena"\n'
        'gate_split = "arena-val"\n'
        "rounds = 1\n"
        "seeds = [0]\n"
        f'results_dir = "{(tmp_path / "out").as_posix()}"\n'
        '[detector]\nname = "offline"\n'
        '[attacker]\nflows_per_round = 4\nmax_queries_per_flow = 3\ncategories = ["dos"]\n'
        '[curator]\nkind = "heuristic"\nproposals_per_round = 1\n',
        encoding="utf-8",
    )

    def never(config: ArenaConfig) -> Path:
        return pytest.fail("a dry run must not start a Run")

    monkeypatch.setattr(loop, "run_arena", never)
    assert cli.main(["arena", "--config", str(toml), "--dry-run"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["detector_calls"] == 72
    assert printed["fits"] is True
    assert not (tmp_path / "out").exists()


def test_the_cli_flags_override_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[ArenaConfig] = []

    def capture(config: ArenaConfig) -> Path:
        seen.append(config)
        return tmp_path

    def load(path: Path) -> ArenaConfig:
        return make_config(tmp_path / "card.json", tmp_path)

    monkeypatch.setattr(cli.loop, "run_arena", capture)
    monkeypatch.setattr(cli, "load_arena_config", load)
    assert cli.main(["arena", "--config", "ignored.toml", "--rounds", "4", "--seeds", "0,2", "--detector", "offline"]) == 0
    assert (seen[0].arena.rounds, seen[0].arena.seeds, seen[0].detector.name) == (4, (0, 2), "offline")
    # A flag that was not given changes nothing, so the file stays the single statement of what a Run was.
    assert cli.main(["arena", "--config", "ignored.toml"]) == 0
    assert (seen[1].arena.rounds, seen[1].arena.seeds) == (1, (0,))
    # A misspelled flag is a typo like any other, and the config's own checks are what catch it.
    with pytest.raises(ValueError, match="detector.name"):
        cli.main(["arena", "--config", "ignored.toml", "--detector", "jevv"])
