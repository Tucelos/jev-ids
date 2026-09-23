"""The final measurement over a synthetic Run directory: the three arms, the placebo, the pre-flight refusal and the paired test."""

import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

import pytest

from jev_ids.arena import final, loop
from jev_ids.arena.budget import Budget, BudgetExhausted
from jev_ids.arena.config import (
    ARENA_CONFIG,
    ArenaConfig,
    ArenaSettings,
    AttackerSettings,
    BudgetSettings,
    CuratorSettings,
    DetectorSettings,
    ThreatSettings,
    load_arena_config,
)
from jev_ids.arena.context import Context, Rule, baseline_context
from jev_ids.dataset import Flow
from jev_ids.records import Prediction, read_predictions
from tests.helpers import CONFIG, JEV_PROMPT, make_flow, write_dataset

# The synthetic `paper` Split: ten benign Flows, six of the attacked Category and four of a Category nobody ever attacked. All twenty are
# judged; only the six carry a mutation.
BENIGN_IDS = tuple(range(200, 210))
DOS_IDS = tuple(range(210, 216))
PROBE_IDS = tuple(range(216, 220))
JUDGED_IDS = set(BENIGN_IDS) | set(DOS_IDS) | set(PROBE_IDS)

# A model priced in prices.json, so `cost_usd_per_1m` is a number; its output tokens are free, so the cost is the input alone.
MODEL = "jev-1.13.0"
INPUT_PRICE = 0.042
# What the recording Detector alerts on, per Context version. Version 0 catches the Category nobody attacked and none of the mutated
# Flows; the Examples buy two of the mutated ones, the placebo's extra text a third, and the final Context catches every mutated Flow --
# while raising one false alarm and losing the unattacked Category outright. Nothing here is a claim about Jev: it is the shape of the
# failure the whole-Split evaluation exists to make visible, arranged so the four arms split from each other.
ALERTS: dict[int, tuple[int, ...]] = {
    0: PROBE_IDS,
    final.EXAMPLES_ONLY_VERSION: PROBE_IDS + DOS_IDS[:2],
    final.PLACEBO_VERSION: PROBE_IDS + DOS_IDS[:3],
    1: DOS_IDS,
}

# The Card of NSL-KDD, spelled out here so the audit below is the test's own: a placebo that named one of these would be advice.
FEATURE_NAMES = (
    "duration protocol_type service flag src_bytes dst_bytes land wrong_fragment urgent hot num_failed_logins logged_in "
    "num_compromised root_shell su_attempted num_root num_file_creations num_shells num_access_files num_outbound_cmds "
    "is_host_login is_guest_login count srv_count serror_rate srv_serror_rate rerror_rate srv_rerror_rate same_srv_rate "
    "diff_srv_rate srv_diff_host_rate dst_host_count dst_host_srv_count dst_host_same_srv_rate dst_host_diff_srv_rate "
    "dst_host_same_src_port_rate dst_host_srv_diff_host_rate dst_host_serror_rate dst_host_srv_serror_rate dst_host_rerror_rate "
    "dst_host_srv_rerror_rate"
)
# The Categories, and the words a rule about this decision would be written in.
DECISION_WORDS = (
    "normal dos probe r2l u2r attack attacks benign malicious intrusion anomaly suspicious threat protocol port ports byte bytes "
    "host hosts login logins shell root error errors src dst srv packet payload scan scanning flow flows"
)

# The playbook the Run ended with: two Rules of different lengths, so the placebo has two lengths to match.
FINAL_RULES = (
    Rule("r1", "A Flow of the attacked Category almost always shows a very high connection window.", 1),
    Rule("r2", "Weigh the reported service against the bytes returned.", 2),
)
FINAL_EXAMPLES = (0, 3)


@dataclass(frozen=True)
class FakeStrategy:
    """A knob setting in the attacker's shape."""

    bucket: str
    padding_bytes: int
    added_seconds: int


def fake_apply(flow: Flow, strategy: FakeStrategy, donors: Sequence[Flow], rng: Any) -> Flow:
    """A mutation whose values say which Strategy produced them, so a test can see the traffic each arm was judged on."""
    assert donors, "the donors come from the Pool and travel to `apply`"
    return replace(flow, attributes_csv=f"0,{strategy.padding_bytes},{strategy.added_seconds}")


class FakeModule:
    """`jev_ids.arena.attacker` as this module needs it: the Strategy, the donors and `apply`."""

    Strategy = FakeStrategy
    apply = staticmethod(fake_apply)

    def donors_from_pool(self, flows: Sequence[Flow], config: Any) -> list[Flow]:
        """The donors, which for a fake are the benign Pool Flows themselves."""
        return [flow for flow in flows if not flow.is_attack]


class Recorder:
    """A Detector that writes down every Flow it was shown, and answers from the Context version alone."""

    name = "recorder"

    def __init__(self, context: Context, prompt: dict[str, Any], seen: list[tuple[int, int, str, int]]) -> None:
        self.version = context.version
        self.rules = len(context.rules)
        self.prompt_hash: str = prompt["sha256"]
        self.model = MODEL
        self.seen = seen

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One Flow judged, and the traffic behind it recorded; the prompt grows with the playbook, placebo or not."""
        self.seen.append((self.version, flow.row_id, flow.attributes_csv, len(examples)))
        alerted = flow.row_id in ALERTS.get(self.version, DOS_IDS) or (self.version == 1 and flow.row_id == BENIGN_IDS[0])
        return {
            "p_attack": 0.9 if alerted else 0.1,
            "category_pred": "dos" if alerted else "normal",
            "latency_ms": 1.0,
            "usage": {"input_tokens": 100 + 20 * self.rules, "output_tokens": 0},
            "retries": 0,
            "error": None,
        }


def make_dataset(tmp_path: Path) -> Path:
    """A Pool and a `paper` Split under `tmp_path`; the Card."""
    pool = [make_flow(index, ("normal", "dos", "probe")[index % 3], value=str(index % 3)) for index in range(30)]
    paper = (
        [make_flow(row_id, "normal", value="0") for row_id in BENIGN_IDS]
        + [make_flow(row_id, "dos", value="1") for row_id in DOS_IDS]
        + [make_flow(row_id, "probe", value="2") for row_id in PROBE_IDS]
    )
    return write_dataset(tmp_path / "data", CONFIG, {"pool": pool, "paper": paper})


def make_config(card: Path, tmp_path: Path, **sections: Any) -> ArenaConfig:
    """The Run the tests measure: the offline Detector at k = 1, dos the only attacked Category, `paper` the evaluation Split."""
    config = ArenaConfig(
        arena=ArenaSettings(
            dataset=card,
            learn_split="arena",
            gate_split="arena-val",
            eval_split="paper",
            rounds=2,
            seeds=(0,),
            results_dir=tmp_path / "out",
        ),
        detector=DetectorSettings(name="offline", k=1),
        attacker=AttackerSettings(kind="mimicry", flows_per_round=4, max_queries_per_flow=3, categories=("dos",)),
        curator=CuratorSettings(kind="llm", proposals_per_round=1),
        budget=BudgetSettings(max_detector_calls=10000, max_curator_calls=100),
        threats=ThreatSettings(),
    )
    return replace(config, **sections)


def strategy_entry(row_id: int, bucket: str, *, evaded: bool = True, padding: int = 8, seconds: int = 2) -> dict[str, Any]:
    """One `attack.strategies` entry of a Round record."""
    return {
        "row_id": row_id,
        "evaded": evaded,
        "bucket": bucket if evaded else None,
        "padding_bytes": padding if evaded else None,
        "added_seconds": seconds if evaded else None,
        "queries": 3,
        "start_p_attack": 0.9,
        "final_p_attack": 0.2 if evaded else 0.8,
    }


def make_round(round_index: int, version: int, accepted: int, strategies: Sequence[dict[str, Any]], seed: int = 0) -> dict[str, Any]:
    """One Round record in the shape the loop writes, reduced to the parts the final measurement reads."""
    evaded = sum(bool(item["evaded"]) for item in strategies)
    return {
        "run_id": "arena-run",
        "seed": seed,
        "round": round_index,
        "context": {"version": version, "rules": [], "example_ids": [], "parent": None, "note": ""},
        "prompt_hash": f"hash-{version}",
        "attack": {
            "flows": len(strategies),
            "evaded": evaded,
            "evasion_rate": evaded / len(strategies) if strategies else None,
            "queries": 12,
            "strategies": list(strategies),
        },
        "analyst": {"reviewed": 5, "alerts_reviewed": 3, "quiet_reviewed": 2, "poisoned": 0},
        "shortlist": {"size": 10, "how": "per missed record"},
        "curator": {"kind": "llm", "model": "deepseek-flash", "proposals": 1, "error": None, "notes": []},
        "gate": [],
        "accepted_version": accepted,
        "budget": {"detector_calls": 100, "max_detector_calls": 10000, "curator_calls": 1, "max_curator_calls": 200},
    }


def context_line(context: Context, *, seed: int = 0, round_index: int = 1, accepted: bool = True) -> dict[str, Any]:
    """One `contexts.jsonl` line in the shape `records.append_context` writes."""
    return {"seed": seed, "round": round_index, "accepted": accepted, **context.to_dict()}


def final_context(version: int = 1, rules: Sequence[Rule] = FINAL_RULES) -> Context:
    """The Context the Run ends under: a playbook and two chosen Examples."""
    return Context(version=version, rules=tuple(rules), example_ids=FINAL_EXAMPLES, parent=0, note="the curator's")


def write_source(tmp_path: Path, config: ArenaConfig, rounds: Sequence[dict[str, Any]], contexts: Sequence[dict[str, Any]]) -> Path:
    """A finished Arena Run directory: `config.json`, `rounds.jsonl` and `contexts.jsonl`."""
    run_dir = tmp_path / "arena" / "arena-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    stored = {"run_id": "arena-run", "config": asdict(config), "inputs": {"dataset": "card-hash", "prompt": "prompt-hash"}}
    (run_dir / "config.json").write_text(json.dumps(stored, indent=2, default=str) + "\n", encoding="utf-8")
    for name, lines in (("rounds.jsonl", rounds), ("contexts.jsonl", contexts)):
        (run_dir / name).write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    return run_dir


def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **sections: Any) -> tuple[Path, ArenaConfig]:
    """A synthetic Dataset, prompt and finished Run, with the attacker module faked out; the Run directory and its config.

    The Run played two Rounds: Round 1 accepted version 1, Round 2 accepted nothing and left it standing, and its attacker found two
    Strategies (plus one Flow that never evaded, which no arm may replay).
    """
    card = make_dataset(tmp_path)
    prompts = tmp_path / "prompts" / CONFIG["name"]
    prompts.mkdir(parents=True, exist_ok=True)
    (prompts / "jev.json").write_text(JEV_PROMPT["text"], encoding="utf-8")
    monkeypatch.setattr(final, "ROOT", tmp_path)
    monkeypatch.setattr(loop, "attacker_module", FakeModule)
    config = make_config(card, tmp_path, **sections)
    rounds = [
        make_round(1, 0, 1, [strategy_entry(1, "old", padding=1, seconds=1)]),
        make_round(
            2,
            1,
            1,
            [
                strategy_entry(2, "quiet", padding=8, seconds=2),
                strategy_entry(3, "busy", padding=16, seconds=4),
                strategy_entry(4, "never", evaded=False),
            ],
        ),
    ]
    contexts = [
        context_line(baseline_context(), round_index=0),
        context_line(final_context(), round_index=1),
        context_line(Context(version=2, rules=(Rule("r9", "rejected", 2),), parent=1, note="no"), round_index=2, accepted=False),
    ]
    return write_source(tmp_path, config, rounds, contexts), config


def install_recorder(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, int, str, int]]:
    """Hand the measurement a Detector that records every Flow it is shown; the recording, in call order."""
    seen: list[tuple[int, int, str, int]] = []

    def build(measurement: final.Eval, context: Context) -> Any:
        return Recorder(context, context.to_prompt(measurement.template), seen)

    monkeypatch.setattr(final, "build_detector", build)
    return seen


def measure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **sections: Any) -> tuple[Path, list[tuple[int, int, str, int]]]:
    """One whole measurement of the synthetic Run, judged by the recording Detector; its directory and the recording."""
    source, _config = setup(tmp_path, monkeypatch, **sections)
    seen = install_recorder(monkeypatch)
    return final.run_final(source, results_dir=tmp_path / "eval"), seen


def rows_of(run_dir: Path, arm: str) -> list[Prediction]:
    """The Predictions of one arm, in the order they were written."""
    return [row for row in read_predictions(run_dir) if row["arm"] == arm]


def traffic_of(block: Sequence[tuple[int, int, str, int]]) -> list[tuple[int, str]]:
    """One arm's recording as the traffic it judged: the Flow and the values it carried, in call order."""
    return [(row_id, values) for _version, row_id, values, _examples in block]


def versions_of(seen: Sequence[tuple[int, int, str, int]]) -> list[int]:
    """The Context version behind every recorded call, in call order."""
    return [version for version, *_rest in seen]


def values_of(block: Sequence[tuple[int, int, str, int]], row_ids: Sequence[int]) -> set[str]:
    """The attribute values one arm was shown for the Flows named."""
    return {values for _version, row_id, values, _examples in block if row_id in row_ids}


def table(run_dir: Path) -> dict[str, dict[str, Any]]:
    """`summarize_eval` keyed by arm, for the one-seed Runs every test below measures."""
    return {row["arm"]: row for row in final.summarize_eval(run_dir)}


def test_the_four_arms_judge_the_identical_flows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir, seen = measure(tmp_path, monkeypatch)
    judged = len(JUDGED_IDS)
    # The whole Split, four times over: nothing is left out, so a Category nobody attacked is judged too.
    assert judged == 20
    assert len(read_predictions(run_dir)) == len(final.ARMS) * judged
    assert {arm: {row["row_id"] for row in rows_of(run_dir, arm)} for arm in final.ARMS} == dict.fromkeys(final.ARMS, JUDGED_IDS)
    # Not only the same row_ids: the same traffic behind them. The recording is arm after arm, twenty Flows each, and the four blocks are
    # identical Flow by Flow and mutation by mutation -- which is the whole reason this measurement exists.
    blocks = [traffic_of(seen[start : start + judged]) for start in range(0, len(final.ARMS) * judged, judged)]
    assert blocks[0] == blocks[1] == blocks[2] == blocks[3]
    expected = (0, final.EXAMPLES_ONLY_VERSION, final.PLACEBO_VERSION, 1)
    assert versions_of(seen) == [version for version in expected for _flow in range(judged)]
    # The attacked Category carries a mutation of the Run's last Round; the benign Flows and the Category nobody attacked do not.
    assert values_of(seen[:judged], DOS_IDS) <= {"0,8,2", "0,16,4"}
    assert values_of(seen[:judged], BENIGN_IDS) == {"0,0,0"}
    assert values_of(seen[:judged], PROBE_IDS) == {"2,2,2"}
    # And every row says which side of that line its Flow was on, so the table can split recall by it.
    assert {row["row_id"] for row in read_predictions(run_dir) if row["mutated"]} == set(DOS_IDS)


def test_the_placebo_matches_the_final_context_shape_and_is_deterministic() -> None:
    curated = final_context()
    placebo = final.placebo_context(curated)
    # As many Rules as the curated Context carries, each of closely matching length, and the same chosen Examples.
    assert len(placebo.rules) == len(curated.rules)
    assert [len(rule.id) and rule.added_round for rule in placebo.rules] == [rule.added_round for rule in curated.rules]
    assert all(abs(len(made.text) - len(rule.text)) <= 5 for made, rule in zip(placebo.rules, curated.rules, strict=True))
    assert abs(final.rule_chars(placebo) - final.rule_chars(curated)) <= 10
    assert placebo.example_ids == curated.example_ids
    # Same input, same placebo; and a version no curator can ever have proposed, carrying the version it was cut from.
    assert final.placebo_context(curated) == placebo
    assert (placebo.version, placebo.parent) == (final.PLACEBO_VERSION, curated.version)
    assert "never by a curator" in placebo.note
    # Every sentence comes from the audited catalogue, and none of them is shown twice while the catalogue lasts.
    texts = [rule.text for rule in placebo.rules]
    assert set(texts) <= set(final.PLACEBO_SENTENCES)
    assert len(set(texts)) == len(texts)
    # A playbook longer than the catalogue starts it again rather than failing.
    long = final.placebo_rules([Rule(f"r{i}", "x" * 80, 1) for i in range(len(final.PLACEBO_SENTENCES) + 2)])
    assert len(long) == len(final.PLACEBO_SENTENCES) + 2


def test_the_placebo_names_no_category_and_no_feature() -> None:
    forbidden = FEATURE_NAMES.split() + DECISION_WORDS.split()
    for sentence in final.PLACEBO_SENTENCES:
        named = [word for word in forbidden if re.search(rf"\b{re.escape(word)}\b", sentence.lower())]
        assert not named, f"{sentence!r} names {named}"
    assert len(set(final.PLACEBO_SENTENCES)) == len(final.PLACEBO_SENTENCES)
    assert len({len(sentence) for sentence in final.PLACEBO_SENTENCES}) == len(final.PLACEBO_SENTENCES)


def test_a_measurement_that_cannot_finish_is_refused_before_the_first_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, _config = setup(tmp_path, monkeypatch, budget=BudgetSettings(max_detector_calls=47, max_curator_calls=100))
    projection = final.preflight(source)
    # The whole Split, four arms and one seed, and every one of those calls is really made: this is the count, not a worst case.
    assert (projection.flows, projection.arms, projection.seeds) == (20, 4, 1)
    assert projection.detector_calls == 80
    assert projection.to_dict()["fits"] is False
    with pytest.raises(BudgetExhausted, match="detector_calls: 80 projected against a cap of 47"):
        final.run_final(source, results_dir=tmp_path / "eval")
    # A measurement that dies halfway is worth less than one never begun, so the refused one leaves no directory behind either.
    assert not (tmp_path / "eval").exists()


def test_the_committed_defaults_project_the_headline_number() -> None:
    # The shipped configs/arena.toml over the whole untouched `paper` Split, against the same cap the loop is held to.
    config = load_arena_config(ARENA_CONFIG)
    _card, _path, flows = final.eval_split(config)
    assert len(flows) == 2000
    one_seed = final.project(config, config.arena.seeds, len(flows))
    assert (one_seed.arms, one_seed.detector_calls, one_seed.max_detector_calls) == (4, 8000, 20000)
    assert one_seed.to_dict()["fits"] is True
    # Three seeds is 24,000 and does NOT fit the committed cap: the fourth arm is what tipped it over, and the measurement says so
    # before it starts rather than dying in the third seed.
    three_seeds = final.project(config, (0, 1, 2), len(flows))
    assert three_seeds.detector_calls == 24000
    assert "detector_calls: 24,000 projected against a cap of 20,000" in (three_seeds.shortfall or "")


def test_a_run_whose_last_round_accepted_nothing_still_measures_the_incumbent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The Run of `setup` is exactly that Run: Round 2 accepted no proposal and left version 1 standing, and version 2 was rejected.
    source, _config = setup(tmp_path, monkeypatch)
    recovered = final.read_source(source)
    assert recovered.seeds == (0,)
    assert recovered.contexts[0].version == 1
    assert [rule.text for rule in recovered.contexts[0].rules] == [rule.text for rule in FINAL_RULES]
    assert recovered.rounds[0] == 2
    run_dir = final.run_final(source, results_dir=tmp_path / "eval")
    assert {row["context_version"] for row in rows_of(run_dir, "final")} == {1}
    assert {row["context_version"] for row in rows_of(run_dir, "placebo")} == {final.PLACEBO_VERSION}


def test_the_incumbent_can_be_version_zero_and_a_run_without_a_round_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, config = setup(tmp_path, monkeypatch)
    # A Run whose gate rejected everything ends under version 0: the final arm is then the baseline, and the table says so.
    write_source(tmp_path, config, [make_round(1, 0, 0, [strategy_entry(1, "quiet")])], [context_line(baseline_context(), round_index=0)])
    recovered = final.read_source(source)
    assert recovered.contexts[0] == baseline_context()
    assert final.placebo_context(recovered.contexts[0]).rules == ()
    # A Run that played no Round at all has no final Context, and a `final` arm silently equal to the baseline is worse than a refusal.
    write_source(tmp_path, config, [], [context_line(baseline_context(), round_index=0)])
    with pytest.raises(ValueError, match="nothing to measure"):
        final.read_source(source)


def test_a_round_without_an_accepted_version_falls_back_to_the_last_accepted_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, config = setup(tmp_path, monkeypatch)
    # A Round record written without the field at all: the last Context the Run accepted is the one that was standing.
    record = make_round(1, 1, 1, [strategy_entry(1, "quiet")])
    record["accepted_version"] = None
    contexts = [context_line(baseline_context(), round_index=0), context_line(final_context(), round_index=1)]
    write_source(tmp_path, config, [record], contexts)
    assert final.read_source(source).contexts[0].version == 1


def test_a_measurement_stopped_by_its_budget_keeps_what_it_judged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, _config = setup(tmp_path, monkeypatch)
    install_recorder(monkeypatch)
    prepared = final.prepare

    def shrink(recovered: final.Source, results_dir: Path) -> final.Eval:
        # The cap is checked before the first call, so the only way to hit it mid-measurement is for the Budget to shrink under it.
        return replace(prepared(recovered, results_dir), budget=Budget(24, final.NO_CURATOR_CALLS))

    monkeypatch.setattr(final, "prepare", shrink)
    run_dir = final.run_final(source, results_dir=tmp_path / "eval")
    # The whole baseline arm and four Flows of the next one: appended as they came, so nothing judged was lost.
    assert len(read_predictions(run_dir)) == 24
    rows = table(run_dir)
    assert (rows["baseline"]["flows"], rows["examples_only"]["flows"]) == (20, 4)
    assert "placebo" not in rows and "final" not in rows
    # And the table says so rather than hiding it: the paired test ran over the four Flows both arms reached, and no more.
    assert rows["examples_only"]["vs_baseline_flows"] == 4


def test_only_the_last_rounds_evading_strategies_are_replayed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir, _seen = measure(tmp_path, monkeypatch)
    recorded = [json.loads(line) for line in (run_dir / "strategies.jsonl").read_text("utf-8").splitlines()]
    # One line per mutated Flow, so the evaluation set can be rebuilt without rerunning the draw.
    assert {item["row_id"] for item in recorded} == set(DOS_IDS)
    # Round 1's `old` bucket is gone and the Flow that never evaded is not a technique: only Round 2's two successes are replayed.
    assert {item["bucket"] for item in recorded} <= {"quiet", "busy"}
    assert {item["from_round"] for item in recorded} == {2}
    assert {(item["padding_bytes"], item["added_seconds"]) for item in recorded} <= {(8, 2), (16, 4)}


def test_a_round_in_which_nothing_evaded_mutates_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, config = setup(tmp_path, monkeypatch)
    write_source(
        tmp_path,
        config,
        [make_round(1, 1, 1, [strategy_entry(1, "none", evaded=False)])],
        [context_line(baseline_context(), round_index=0), context_line(final_context(), round_index=1)],
    )
    seen = install_recorder(monkeypatch)
    run_dir = final.run_final(source, results_dir=tmp_path / "eval")
    assert not (run_dir / "strategies.jsonl").exists()
    # Every attack Flow is judged exactly as the Split has it, which is the honest reading of a Run whose attacker never got through.
    assert values_of(seen, DOS_IDS) == {"1,1,1"}
    assert values_of(seen, PROBE_IDS) == {"2,2,2"}
    assert not any(row["mutated"] for row in read_predictions(run_dir))


def test_the_run_directory_says_what_it_measured_before_the_first_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir, _seen = measure(tmp_path, monkeypatch)
    assert run_dir.parent == tmp_path / "eval"
    assert run_dir.name.endswith("-test-offline-eval")
    stored = json.loads((run_dir / "config.json").read_text("utf-8"))
    assert stored["arms"] == list(final.ARMS)
    assert stored["eval_split"] == "paper"
    assert stored["projection"] == {"flows": 20, "arms": 4, "seeds": 1, "detector_calls": 80, "max_detector_calls": 10000, "fits": True}
    # What the set is made of: the whole Split, with the attack Flows split into the ones a Strategy moved and the ones it did not.
    assert (stored["eval_set"]["flows"], stored["eval_set"]["benign"], stored["eval_set"]["attacks"]) == (20, 10, 10)
    assert (stored["eval_set"]["mutated_attacks"], stored["eval_set"]["mutated_categories"]) == (6, ["dos"])
    assert (stored["eval_set"]["unmutated_attacks"], stored["eval_set"]["unmutated_categories"]) == (4, ["probe"])
    # The Run measured, its final versions, and the hashes of the bytes the numbers came from.
    assert stored["measures"]["run_id"] == "arena-run"
    assert stored["measures"]["final_versions"] == {"0": 1}
    assert stored["measures"]["strategies"] == {"0": 2}
    assert len(stored["inputs"]["eval_split"]) == 64
    assert len(stored["inputs"]["source_rounds"]) == 64
    # Its own Budget, with no curator call to spend: the placebo must never be produced by a curator, and this is the cap that says so.
    assert stored["budget"]["max_curator_calls"] == 0
    assert stored["config"]["attacker"]["categories"] == ["dos"]
    # Every Context judged is on disk beside the Predictions, so the placebo's own sentences can be read and audited.
    contexts = [json.loads(line) for line in (run_dir / "contexts.jsonl").read_text("utf-8").splitlines()]
    assert [(item["arm"], item["version"], len(item["rules"])) for item in contexts] == [
        ("baseline", 0, 0),
        ("examples_only", final.EXAMPLES_ONLY_VERSION, 0),
        ("placebo", final.PLACEBO_VERSION, 2),
        ("final", 1, 2),
    ]
    assert [rule["text"] for rule in contexts[2]["rules"]] != [rule["text"] for rule in contexts[3]["rules"]]


def test_the_paired_mcnemar_is_taken_against_the_baseline_arm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir, _seen = measure(tmp_path, monkeypatch)
    rows = table(run_dir)
    assert list(rows) == list(final.ARMS)
    assert all(row["flows"] == 20 and row["attack_flows"] == 10 and row["benign_flows"] == 10 for row in rows.values())
    assert [rows[arm]["recall"] for arm in final.ARMS] == [0.4, 0.6, 0.7, 0.6]
    assert [rows[arm]["false_alarm_rate"] for arm in final.ARMS] == [0.0, 0.0, 0.0, 0.1]
    assert rows["final"]["f1"] == pytest.approx(2 * 6 / (7 + 10))
    # Every arm is paired against the baseline over all twenty Flows, and the baseline against itself: p = 1 and no discordant pair.
    assert all(row["vs_baseline_flows"] == 20 for row in rows.values())
    assert (rows["baseline"]["vs_baseline_discordant"], rows["baseline"]["mcnemar_p"]) == (0, 1.0)
    # The Examples bought two Flows and the extra text a third, each of them a clean gain over the baseline.
    assert (rows["examples_only"]["vs_baseline_discordant"], rows["examples_only"]["arm_correct"]) == (2, 2)
    assert rows["examples_only"]["mcnemar_p"] == pytest.approx(0.5)
    assert (rows["placebo"]["vs_baseline_discordant"], rows["placebo"]["arm_correct"]) == (3, 3)
    assert rows["placebo"]["mcnemar_p"] == pytest.approx(0.25)
    # And the final arm: six mutated Flows won, four unmutated ones and one benign Flow lost. Restricted to the attacked Category it
    # would have read as a clean 6-0 sweep; over the whole Split the paired test says the two Contexts are indistinguishable.
    assert (rows["final"]["vs_baseline_discordant"], rows["final"]["arm_correct"], rows["final"]["baseline_correct"]) == (11, 6, 5)
    assert rows["final"]["mcnemar_p"] == pytest.approx(1.0)


def test_a_regression_outside_the_attacked_categories_is_visible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir, _seen = measure(tmp_path, monkeypatch)
    rows = table(run_dir)
    # Six mutated Flows of the attacked Category and four untouched ones of a Category nobody attacked, in every arm.
    assert {row["mutated_flows"] for row in rows.values()} == {len(DOS_IDS)}
    # The final Context caught every Flow the attacker moved and lost every Flow it did not touch. That is the trade a measurement
    # restricted to the attacked Categories would have hidden completely, and here it is two columns wide.
    assert (rows["final"]["recall_mutated"], rows["final"]["recall_unmutated"]) == (1.0, 0.0)
    assert (rows["baseline"]["recall_mutated"], rows["baseline"]["recall_unmutated"]) == (0.0, 1.0)
    assert [rows[arm]["recall_dos"] for arm in final.ARMS] == [0.0, pytest.approx(1 / 3), 0.5, 1.0]
    assert [rows[arm]["recall_probe"] for arm in final.ARMS] == [1.0, 1.0, 1.0, 0.0]


def test_the_table_reports_the_tokens_and_the_price_beside_the_recall(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir, _seen = measure(tmp_path, monkeypatch)
    rows = table(run_dir)
    # Step one, the Examples: the same empty playbook and the same prompt length on both sides, so only the Examples moved.
    assert (rows["baseline"]["rules"], rows["examples_only"]["rules"]) == (0, 0)
    assert rows["baseline"]["input_tokens_mean"] == rows["examples_only"]["input_tokens_mean"] == 100
    assert rows["baseline"]["examples"] == 0
    assert rows["examples_only"]["examples"] == len(FINAL_EXAMPLES)
    # Step two, the length: the same Examples on both sides, and the placebo's prompt is the longer one.
    assert rows["examples_only"]["examples"] == rows["placebo"]["examples"]
    assert rows["placebo"]["input_tokens_mean"] == 140
    # Step three, the meaning: as many Rules of matching length and the same Examples, so only the wording separates these two.
    assert rows["final"]["rules"] == rows["placebo"]["rules"] == len(FINAL_RULES)
    assert abs(rows["final"]["rule_chars"] - rows["placebo"]["rule_chars"]) <= 10
    assert rows["final"]["input_tokens_mean"] == rows["placebo"]["input_tokens_mean"] == 140
    assert rows["final"]["examples"] == rows["placebo"]["examples"]
    # A playbook is billed on every Flow, so the price stands in the same row as the recall it bought.
    assert rows["baseline"]["cost_usd_per_1m"] == pytest.approx(100 * INPUT_PRICE)
    assert rows["final"]["cost_usd_per_1m"] == pytest.approx(140 * INPUT_PRICE)
    assert {row["n_examples"] for row in rows_of(run_dir, "baseline")} == {len(CONFIG["categories"])}
    assert {row["n_examples"] for row in rows_of(run_dir, "final")} == {len(FINAL_EXAMPLES)}


def test_the_examples_only_arm_is_version_zero_carrying_the_final_examples() -> None:
    curated = final_context()
    arm = final.examples_context(curated)
    # The final Context's Examples under an empty playbook: no Rule of either kind, and a version no curator can have proposed.
    assert (arm.rules, arm.example_ids) == ((), curated.example_ids)
    assert (arm.version, arm.parent) == (final.EXAMPLES_ONLY_VERSION, curated.version)
    assert "never by a curator" in arm.note
    # Chosen Examples travel as `predict`'s argument and never through the template, so this arm renders the committed template byte for
    # byte exactly as the baseline does: the step between them is the Examples and nothing else.
    assert arm.to_prompt(JEV_PROMPT["text"]) == baseline_context().to_prompt(JEV_PROMPT["text"])
    # A Run whose curator chose no Examples leaves this arm identical to the baseline in everything but its version, and says so.
    assert final.examples_context(baseline_context()).example_ids == ()
    assert tuple(item.name for item in final.arms_of(0, curated)) == final.ARMS


def test_two_seeds_are_measured_and_paired_one_at_a_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, config = setup(tmp_path, monkeypatch)
    seeded = replace(config, arena=replace(config.arena, seeds=(0, 1)))
    rounds = [
        make_round(1, 0, 1, [strategy_entry(2, "quiet")], seed=0),
        make_round(1, 0, 3, [strategy_entry(2, "busy", padding=16, seconds=4)], seed=1),
    ]
    contexts = [
        context_line(baseline_context(), round_index=0),
        context_line(final_context(), round_index=1),
        context_line(baseline_context(), seed=1, round_index=0),
        context_line(final_context(version=3, rules=FINAL_RULES[:1]), seed=1, round_index=1),
    ]
    write_source(tmp_path, seeded, rounds, contexts)
    install_recorder(monkeypatch)
    run_dir = final.run_final(source, results_dir=tmp_path / "eval")
    rows = final.summarize_eval(run_dir)
    # Eight rows, four arms per seed, and each seed's own final Context: the seeds are two independent replications and never pooled.
    assert [(row["seed"], row["arm"]) for row in rows] == [(seed, arm) for seed in (0, 1) for arm in final.ARMS]
    assert {row["context_version"] for row in rows if row["seed"] == 1} == {
        0,
        3,
        final.EXAMPLES_ONLY_VERSION,
        final.PLACEBO_VERSION,
    }
    assert all(row["vs_baseline_flows"] == 20 for row in rows)
    # Seed 1's Run ended with one Rule, so its placebo carries one; both controls are cut from their own seed's Context and no other.
    assert [row["rules"] for row in rows if row["seed"] == 1] == [0, 0, 1, 1]
    recorded = [json.loads(line) for line in (run_dir / "strategies.jsonl").read_text("utf-8").splitlines()]
    assert {item["seed"] for item in recorded} == {0, 1}
    assert {item["bucket"] for item in recorded if item["seed"] == 1} == {"busy"}


def test_the_measurement_judges_with_jev_itself_when_the_run_did(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, _config = setup(tmp_path, monkeypatch, detector=DetectorSettings(name="jev", k=1))
    measurement = final.prepare(final.read_source(source), tmp_path / "eval")
    # Built, not called: `JevDetector` needs no key until its first request, and this measurement makes none here.
    detector = final.build_detector(measurement, baseline_context())
    assert (detector.name, detector.model) == ("jev", "jev-1.13.0")
    # Version 0 renders the committed template byte for byte, so the baseline arm is the published Run at that k.
    assert detector.prompt_hash == baseline_context().to_prompt(measurement.template)["sha256"]
    assert final.build_detector(measurement, final_context()).prompt_hash != detector.prompt_hash


def test_the_offline_detector_runs_the_whole_measurement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # No recorder: the real offline Detector, so the plumbing from the Card to `predictions.jsonl` is exercised end to end.
    source, _config = setup(tmp_path, monkeypatch)
    run_dir = final.run_final(source, results_dir=tmp_path / "eval")
    rows = read_predictions(run_dir)
    assert len(rows) == 80
    assert {row["detector"] for row in rows} == {"offline"}
    assert {row["split"] for row in rows} == {"paper"}
    assert {row["dataset"] for row in rows} == {"test"}
    assert all(row.get("error") is None for row in rows)
    # A forest cannot read a playbook of either kind, so the three arms that share the final Context's Examples answer identically and
    # only the baseline's own Example draw moves anything. Nothing in an offline table is a result, and this is why.
    verdicts = {arm: [row["classification_verdict"] for row in rows_of(run_dir, arm)] for arm in final.ARMS}
    assert verdicts["examples_only"] == verdicts["placebo"] == verdicts["final"]
    offline = table(run_dir)
    assert offline["placebo"]["mcnemar_p"] == offline["final"]["mcnemar_p"] == offline["examples_only"]["mcnemar_p"]


def test_an_empty_directory_summarizes_to_nothing(tmp_path: Path) -> None:
    assert final.summarize_eval(tmp_path) == []
