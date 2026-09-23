"""The Round record and the four files of an Arena Run directory."""

import json
from datetime import UTC, datetime
from pathlib import Path

from jev_ids.arena.budget import Budget
from jev_ids.arena.config import ArenaConfig, ArenaSettings, CuratorSettings, DetectorSettings
from jev_ids.arena.context import Context, Rule, baseline_context
from jev_ids.arena.gate import GateVerdict
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
    code_commit,
    read_rounds,
    run_id,
    sha256,
    start_run,
)

VERDICT = GateVerdict(
    accepted=True,
    reason="recall held",
    candidate_recall=0.7,
    incumbent_recall=0.6,
    candidate_false_alarm_rate=0.01,
    incumbent_false_alarm_rate=0.01,
    candidate_f1=0.8,
    incumbent_f1=0.7,
    candidate_error_rate=0.0,
    incumbent_error_rate=0.0,
    mcnemar_p=0.25,
    candidate_only_hits=2,
    incumbent_only_hits=0,
)


def make_record(**overrides: object) -> RoundRecord:
    """A Round record with every part filled in; `overrides` win."""
    fields: dict[str, object] = {
        "run_id": "run-1",
        "seed": 0,
        "round_index": 1,
        "context": Context(version=1, rules=(Rule("r1", "watch short sessions", 1),), example_ids=(7,), parent=0, note="why"),
        "prompt_hash": "abc",
        "attack": AttackRecord(
            flows=2,
            evaded=1,
            evasion_rate=0.5,
            queries=12,
            strategies=(
                EvasionRecord(123, True, "slow-narrow", 0, 0, 8, 0.91, 0.32),
                EvasionRecord(124, False, None, None, None, 4, 0.88, None),
            ),
        ),
        "analyst": AnalystRecord(reviewed=62, alerts_reviewed=50, quiet_reviewed=12, poisoned=3),
        "shortlist": ShortlistRecord(size=40, how="per-miss category, seeded"),
        "curator": CuratorRecord(kind="llm", model="deepseek-flash", proposals=2, error=None, notes=("a", "b")),
        "gate": (GateRecord(version=1, verdict=VERDICT),),
        "accepted_version": 1,
        "budget": {"detector_calls": 1100, "max_detector_calls": 20000, "curator_calls": 1, "max_curator_calls": 200},
    }
    fields.update(overrides)
    return RoundRecord(**fields)  # pyright: ignore[reportArgumentType]


def make_config(tmp_path: Path) -> ArenaConfig:
    """An ArenaConfig writing into `tmp_path`."""
    return ArenaConfig(
        arena=ArenaSettings(dataset=Path("data/nsl-kdd/dataset.json"), rounds=2, seeds=(0,), results_dir=tmp_path / "results"),
        detector=DetectorSettings(name="offline", k=1),
        curator=CuratorSettings(kind="heuristic"),
    )


def test_round_record_writes_exactly_the_documented_shape() -> None:
    written = make_record().to_dict()
    assert list(written) == [
        "run_id",
        "seed",
        "round",
        "context",
        "prompt_hash",
        "attack",
        "analyst",
        "shortlist",
        "curator",
        "gate",
        "accepted_version",
        "budget",
    ]
    # `round` in the file, `round_index` in Python; the design doc fixed the JSON name and the report reads it.
    assert written["round"] == 1
    assert written["context"] == {
        "version": 1,
        "rules": [{"id": "r1", "text": "watch short sessions", "added_round": 1}],
        "example_ids": [7],
        "parent": 0,
        "note": "why",
    }
    assert written["attack"]["evasion_rate"] == 0.5
    assert written["attack"]["strategies"][0] == {
        "row_id": 123,
        "evaded": True,
        "bucket": "slow-narrow",
        "padding_bytes": 0,
        "added_seconds": 0,
        "queries": 8,
        "start_p_attack": 0.91,
        "final_p_attack": 0.32,
    }
    # A Flow that did not evade carries no Strategy, and the three knob columns stay empty rather than reading as zeros.
    assert written["attack"]["strategies"][1]["bucket"] is None
    assert written["analyst"] == {"reviewed": 62, "alerts_reviewed": 50, "quiet_reviewed": 12, "poisoned": 3}
    assert written["shortlist"] == {"size": 40, "how": "per-miss category, seeded"}
    assert written["curator"] == {"kind": "llm", "model": "deepseek-flash", "proposals": 2, "error": None, "notes": ["a", "b"]}
    # Every GateVerdict field travels beside the version it was about.
    assert written["gate"][0]["version"] == 1
    assert written["gate"][0]["accepted"] is True
    assert written["gate"][0]["candidate_recall"] == 0.7
    assert set(written["gate"][0]) == {"version", *vars(VERDICT)}
    assert written["budget"]["max_detector_calls"] == 20000


def test_a_run_directory_is_named_and_configured_before_the_first_call(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    budget = Budget(100, 5)
    inputs = Inputs(dataset="d", learn_split="l", gate_split="g", prompt="p", curator_prompt=None, mutations="m")
    run_dir = start_run(config, inputs, {"detector_calls": 90, "fits": True}, budget)
    assert run_dir.parent == tmp_path / "results"
    # <UTC timestamp>-<dataset>-<detector>-<curator>, the three things two Arena Runs are compared by.
    assert run_dir.name.endswith("-nsl-kdd-offline-heuristic")
    stored = json.loads((run_dir / "config.json").read_text("utf-8"))
    assert stored["run_id"] == run_dir.name
    assert stored["config"]["arena"]["rounds"] == 2
    assert stored["config"]["gate"]["mode"] == "guarded"
    assert stored["inputs"] == {
        "dataset": "d",
        "learn_split": "l",
        "gate_split": "g",
        "prompt": "p",
        "curator_prompt": None,
        "mutations": "m",
    }
    assert stored["projection"] == {"detector_calls": 90, "fits": True}
    assert stored["budget"] == {"detector_calls": 0, "max_detector_calls": 100, "curator_calls": 0, "max_curator_calls": 5}
    assert isinstance(stored["code_commit"], str)
    assert stored["started_at"]


def test_rounds_and_contexts_are_appended_one_line_at_a_time(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    assert read_rounds(run_dir) == []
    append_round(run_dir, make_record())
    append_round(run_dir, make_record(round_index=2, accepted_version=0, gate=()))
    written = read_rounds(run_dir)
    assert [item["round"] for item in written] == [1, 2]
    assert written[1]["gate"] == []
    # Every Context ever proposed, accepted or not: a Run that rejected fifteen must not read like one that proposed none.
    append_context(run_dir, baseline_context(), seed=0, round_index=0, accepted=True)
    append_context(run_dir, Context(version=1, parent=0, note="rejected"), seed=0, round_index=1, accepted=False)
    lines = [json.loads(line) for line in (run_dir / "contexts.jsonl").read_text("utf-8").splitlines()]
    assert [(item["seed"], item["round"], item["accepted"], item["version"]) for item in lines] == [(0, 0, True, 0), (0, 1, False, 1)]
    assert lines[1]["note"] == "rejected"


def test_a_prediction_row_gains_the_three_arena_fields() -> None:
    fields = arena_fields({"run_id": "r", "split": "arena"}, Stamp(round_index=3, context_version=2, stage="gate-candidate"))
    assert fields == {"run_id": "r", "split": "arena", "round": 3, "context_version": 2, "arena_stage": "gate-candidate"}


def test_the_hash_of_a_missing_input_is_none_and_the_commit_is_a_string(tmp_path: Path) -> None:
    present = tmp_path / "card.json"
    present.write_text("{}", encoding="utf-8")
    assert sha256(present) == "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    # A Dataset without a mutations.json must not stop a Run record from being written.
    assert sha256(tmp_path / "nothing.json") is None
    assert isinstance(code_commit(), str)


def test_the_run_id_carries_the_dataset_the_detector_and_the_curator(tmp_path: Path) -> None:
    name = run_id(datetime(2026, 9, 23, 12, 0, tzinfo=UTC), make_config(tmp_path))
    assert name == "20260923T120000.000000Z-nsl-kdd-offline-heuristic"
