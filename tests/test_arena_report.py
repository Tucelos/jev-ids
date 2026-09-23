"""The Arena's tables over a synthetic Run directory: the Rounds, the Run's answer, and the baselines it refuses to fake."""

import json
from pathlib import Path
from typing import Any

import pytest

from jev_ids import cli
from jev_ids.arena import report
from jev_ids.records import Prediction
from tests.helpers import make_prediction

# A Run's traffic: four attack Flows and six benign ones, the same row_ids every Round, so two Contexts pair Flow by Flow.
ATTACK_IDS = (1, 2, 3, 4)
BENIGN_IDS = (101, 102, 103, 104, 105, 106)
# The held-out Flows the gate judges; disjoint from the traffic, as `arena-val` is from `arena`.
GATE_IDS = (201, 202)
# A model priced in prices.json, so `cost_usd_per_1m` is a number and not None. Output tokens are free at this price.
MODEL = "jev-1.13.0"
INPUT_PRICE = 0.042

CONFIG: dict[str, Any] = {
    "run_id": "arena-llm",
    # The sha256 of everything the Run was made from: what a comparison is allowed to be checked against, names never being enough.
    "inputs": {"dataset": "card-hash", "learn_split": "learn-hash", "gate_split": "gate-hash", "prompt": "prompt-hash"},
    "config": {
        "arena": {"learn_split": "arena", "gate_split": "arena-val", "eval_split": "paper", "rounds": 2},
        "detector": {"name": "jev", "k": 1},
        "attacker": {"kind": "mimicry", "flows_per_round": 20, "categories": ["r2l"]},
        "curator": {"kind": "llm"},
        "gate": {"mode": "guarded"},
        "threats": {"poisoning": False, "failure_rate": 0.0},
    },
}


def judged(row_ids: tuple[int, ...], is_attack: int, alerts: int, tokens: int, **fields: Any) -> list[Prediction]:
    """The Flows of one group, the first `alerts` of them alerted on, all judged at the same prompt length."""
    return [
        make_prediction(
            row_id,
            is_attack,
            0.9 if index < alerts else 0.1,
            model=MODEL,
            usage={"input_tokens": tokens, "output_tokens": 0},
            **fields,
        )
        for index, row_id in enumerate(row_ids)
    ]


def traffic(round_number: int, version: int, hits: int, false_alarms: int, tokens: int) -> list[Prediction]:
    """One Round's observed traffic under one Context: `hits` of the four attacks caught, `false_alarms` of the six benign alerted on."""
    fields: dict[str, Any] = {"seed": 0, "round": round_number, "context_version": version, "arena_stage": "traffic"}
    return judged(ATTACK_IDS, 1, hits, tokens, **fields) + judged(BENIGN_IDS, 0, false_alarms, tokens, **fields)


def make_round(round_number: int, version: int, **overrides: Any) -> dict[str, Any]:
    """One (seed, Round) record in the shape the loop writes, every section filled; `overrides` replace a whole section."""
    record: dict[str, Any] = {
        "run_id": CONFIG["run_id"],
        "seed": 0,
        "round": round_number,
        "context": {
            "version": version,
            "rules": [{"id": f"r{i}", "text": "advice", "added_round": i} for i in range(1, version + 1)],
            "example_ids": [],
            "parent": version - 1 if version else None,
            "note": "",
        },
        "prompt_hash": f"hash-{version}",
        "attack": {
            "flows": 20,
            "evaded": 7,
            "evasion_rate": 0.35,
            "queries": 412,
            "strategies": [{"row_id": 1, "evaded": True, "bucket": "slow-narrow", "padding_bytes": 0, "added_seconds": 0}],
        },
        "analyst": {"reviewed": 5, "alerts_reviewed": 3, "quiet_reviewed": 2, "poisoned": 0},
        "shortlist": {"size": 40, "how": "per-miss category, seeded"},
        "curator": {"kind": "llm", "model": "deepseek-flash", "proposals": 1, "error": None, "notes": []},
        "gate": [],
        "accepted_version": None,
        "budget": {
            "detector_calls": 1100 * round_number,
            "max_detector_calls": 20000,
            "curator_calls": round_number,
            "max_curator_calls": 200,
        },
    }
    record.update(overrides)
    return record


def verdict(version: int, *, accepted: bool) -> dict[str, Any]:
    """One `GateVerdict` as the Round record holds it, reduced to the fields the report reads."""
    return {
        "version": version,
        "accepted": accepted,
        "reason": "recall 0.500 -> 0.750" if accepted else "recall fell from 0.750 to 0.250",
        "candidate_recall": 0.75 if accepted else 0.25,
        "incumbent_recall": 0.5,
        "candidate_false_alarm_rate": 0.05,
        "mcnemar_p": 0.031,
    }


def write_run(run_dir: Path, records: list[dict[str, Any]], predictions: list[Prediction], config: dict[str, Any] = CONFIG) -> Path:
    """A Run directory with the three files every test needs; the one test that needs contexts.jsonl writes it itself."""
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    for name, rows in (("rounds.jsonl", records), ("predictions.jsonl", predictions)):
        (run_dir / name).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return run_dir


def two_round_run(tmp_path: Path) -> Path:
    """The Run every test below reads: Round 1 under version 0 accepts version 1, Round 2 under version 1 accepts nothing.

    Version 0 caught two of the four attack Flows and raised one false alarm at 100 input tokens; version 1 caught three and raised none
    at 140. Round 2 also judged two held-out Flows under each of version 1 and the rejected version 2, which no pairing may touch.
    """
    records = [
        make_round(1, 0, gate=[verdict(1, accepted=True)], accepted_version=1),
        # `accepted_version` is the version in force after the gate, so a Round that accepted nothing repeats the incumbent's.
        make_round(
            2,
            1,
            gate=[verdict(2, accepted=False)],
            accepted_version=1,
            attack={"flows": 20, "evaded": 4, "evasion_rate": 0.2, "queries": 300},
        ),
    ]
    held_out: dict[str, Any] = {"seed": 0, "round": 2}
    predictions = [
        *traffic(1, 0, hits=2, false_alarms=1, tokens=100),
        *traffic(2, 1, hits=3, false_alarms=0, tokens=140),
        *judged(GATE_IDS, 1, 1, 140, context_version=1, arena_stage="gate-incumbent", **held_out),
        *judged(GATE_IDS, 1, 2, 180, context_version=2, arena_stage="gate-candidate", **held_out),
    ]
    return write_run(tmp_path / "arena-llm", records, predictions)


def test_summarize_rounds_reports_the_evasion_rate_beside_the_prompt_it_was_bought_at(tmp_path: Path) -> None:
    first, second = report.summarize_rounds(two_round_run(tmp_path))

    assert (first["seed"], first["round"], first["context_version"]) == (0, 1, 0)
    assert (first["evasion_rate"], first["attacker_evaded"], first["attacker_flows"]) == (0.35, 7, 20)
    assert second["evasion_rate"] == 0.2
    # Recall and mean input_tokens in the same row: version 1 caught one more attack Flow, and its prompt was 40 tokens longer.
    assert (first["recall"], first["input_tokens_mean"]) == (0.5, 100.0)
    assert (second["recall"], second["input_tokens_mean"]) == (0.75, 140.0)
    assert first["false_alarm_rate"] == pytest.approx(1 / 6)
    assert second["false_alarm_rate"] == 0.0
    assert (first["misses"], first["false_alarms"], first["flows"]) == (2, 1, 10)
    assert (first["rules"], second["rules"]) == (0, 1)
    # The gate stages are the gate's own numbers and never enter a Round's traffic, so Round 2 still judged ten Flows.
    assert second["flows"] == 10


def test_summarize_rounds_reports_how_little_of_the_round_the_analyst_saw(tmp_path: Path) -> None:
    first, _second = report.summarize_rounds(two_round_run(tmp_path))

    # The counts are Round-wide; the analyst reached five of the ten Flows they were taken over.
    assert (first["misses"], first["false_alarms"]) == (2, 1)
    assert (first["analyst_reviewed"], first["analyst_reviewed_share"]) == (5, 0.5)
    assert (first["analyst_alerts_reviewed"], first["analyst_quiet_reviewed"], first["analyst_poisoned"]) == (3, 2, 0)
    assert (first["shortlist_size"], first["shortlist_how"]) == (40, "per-miss category, seeded")
    assert (first["detector_calls"], first["max_detector_calls"]) == (1100, 20000)


def test_summarize_rounds_keeps_the_gate_s_reason_for_a_round_that_accepted_nothing(tmp_path: Path) -> None:
    first, second = report.summarize_rounds(two_round_run(tmp_path))

    assert (first["gate_proposals"], first["gate_accepted"], first["gate_rejected"]) == (1, 1, 0)
    assert first["accepted_version"] == 1
    assert (first["gate_candidate_recall"], first["gate_incumbent_recall"]) == (0.75, 0.5)
    assert first["gate_mcnemar_p"] == 0.031
    assert first["gate_reasons"].startswith("v1 kept: recall 0.500 -> 0.750")

    # A Round with no accepted proposal: the incumbent stands, and the row says so rather than borrowing a rejected proposal's numbers.
    assert (second["gate_proposals"], second["gate_accepted"], second["gate_rejected"]) == (1, 0, 1)
    # `accepted_version` still reads 1, the version in force after the gate; `gate_accepted` is the column that says nothing was kept.
    assert second["accepted_version"] == 1
    assert (second["gate_candidate_recall"], second["gate_mcnemar_p"]) == (None, None)
    assert second["gate_reasons"] == "v2 rolled back: recall fell from 0.750 to 0.250"


def test_summarize_run_pairs_the_final_context_against_version_0_over_the_same_flows(tmp_path: Path) -> None:
    (row,) = report.summarize_run(two_round_run(tmp_path))

    assert (row["seed"], row["rounds"], row["final_version"], row["baseline_version"]) == (0, 2, 1, 0)
    assert (row["final_rules"], row["final_examples"]) == (1, 0)
    # Only the ten Flows both Contexts judged: the held-out Flows of Round 2 belong to one side each and are dropped.
    assert row["paired_flows"] == 10
    # Two Flows the two Contexts split on, both of them version 1's: the attack Flow it caught and the false alarm it dropped.
    assert (row["discordant"], row["final_correct"], row["v0_correct"]) == (2, 2, 0)
    assert row["mcnemar_p"] == pytest.approx(0.5)
    assert (row["recall_final"], row["recall_v0"]) == (0.75, 0.5)
    assert (row["false_alarm_rate_final"], row["false_alarm_rate_v0"]) == (0.0, pytest.approx(1 / 6))
    # A false-alarm rate of zero is only good news when the calls came back: a Context that answers nothing buys one for free.
    assert (row["error_rate_final"], row["error_rate_v0"]) == (0.0, 0.0)
    # The confound beside the result: the recall rose and the prompt grew, and the cost of a million Flows grew with it.
    assert (row["input_tokens_mean_final"], row["input_tokens_mean_v0"]) == (140.0, 100.0)
    assert row["cost_usd_per_1m_final"] == pytest.approx(140 * INPUT_PRICE)
    assert row["cost_usd_per_1m_v0"] == pytest.approx(100 * INPUT_PRICE)
    # The other confound: the two sides were measured in different Rounds, so the attack Flows carried different mutations.
    assert row["paired_same_round"] is False


def test_summarize_run_reports_the_trajectory_the_gate_and_the_budget(tmp_path: Path) -> None:
    (row,) = report.summarize_run(two_round_run(tmp_path))

    assert (row["evasion_rate_first"], row["evasion_rate_last"]) == (0.35, 0.2)
    assert row["evasion_rate_mean"] == pytest.approx(0.275)
    assert row["evasion_rate_by_round"] == "0.350 0.200"
    assert (row["gate_accepted"], row["gate_rejected"], row["curator_errors"]) == (1, 1, 0)
    assert (row["detector_calls"], row["curator_calls"], row["max_curator_calls"]) == (2200, 2, 200)


def test_summarize_run_of_a_run_whose_curator_errored_every_round(tmp_path: Path) -> None:
    failed: dict[str, Any] = {"kind": "llm", "model": "deepseek-flash", "proposals": 0, "error": "timeout", "notes": []}
    records = [make_round(number, 0, curator=failed) for number in (1, 2)]
    predictions = [*traffic(1, 0, hits=2, false_alarms=1, tokens=100), *traffic(2, 0, hits=2, false_alarms=1, tokens=100)]
    run_dir = write_run(tmp_path / "arena-broken", records, predictions)

    rounds = report.summarize_rounds(run_dir)
    assert [record["curator_error"] for record in rounds] == ["timeout", "timeout"]
    assert [record["gate_proposals"] for record in rounds] == [0, 0]

    (row,) = report.summarize_run(run_dir)
    # Nothing was ever accepted, so the Run ended on the Context it started with and the answer is version 0 against itself.
    assert (row["final_version"], row["curator_errors"], row["final_rules"]) == (0, 2, 0)
    assert (row["discordant"], row["mcnemar_p"]) == (0, 1.0)
    assert row["recall_final"] == row["recall_v0"] == 0.5
    assert row["input_tokens_mean_final"] == row["input_tokens_mean_v0"] == 100.0
    assert row["paired_same_round"] is True


def test_summarize_run_takes_the_final_playbook_from_contexts_jsonl(tmp_path: Path) -> None:
    # The Context accepted in the last Round was never in force, so no Round record embeds it; contexts.jsonl is where it lives.
    records = [make_round(1, 0, gate=[verdict(1, accepted=True)], accepted_version=1)]
    run_dir = write_run(tmp_path / "arena-late", records, traffic(1, 0, hits=2, false_alarms=1, tokens=100))
    accepted = {"version": 1, "rules": [{"id": "r1", "text": "a", "added_round": 1}], "example_ids": [7, 9], "parent": 0, "note": ""}
    baseline: dict[str, Any] = {"version": 0, "rules": [], "example_ids": [], "parent": None, "note": "baseline"}
    # Both shapes a line may take, and one that is neither: the file's shape is not fixed by the protocol, so it is read leniently.
    lines: list[dict[str, Any]] = [
        {"seed": 0, "round": 0, "accepted": True, **baseline},
        {"context": accepted},
        {"note": "not a Context at all"},
    ]
    (run_dir / "contexts.jsonl").write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    # Keyed by (seed, version): the line that named its seed under it, the one that named none under None.
    assert set(report.read_contexts(run_dir, [])) == {(0, 0), (None, 1)}

    (row,) = report.summarize_run(run_dir)
    assert (row["final_version"], row["final_rules"], row["final_examples"]) == (1, 1, 2)
    # No Flow was ever judged under it inside this Run, and the row says that rather than implying a comparison happened.
    assert (row["paired_flows"], row["paired_same_round"], row["recall_final"]) == (0, None, None)


def test_the_tables_of_a_run_that_played_no_round_are_empty(tmp_path: Path) -> None:
    empty = tmp_path / "arena-empty"
    empty.mkdir()
    assert report.summarize_rounds(empty) == []
    assert report.summarize_run(empty) == []
    assert report.compare_runs([]) == []


def baseline_run(tmp_path: Path, name: str, curator: str) -> Path:
    """A second arm of the same experiment: the same Card, Splits and attacker, one setting moved."""
    config = json.loads(json.dumps(CONFIG))
    config["run_id"] = name
    config["config"]["curator"]["kind"] = curator
    records = [make_round(1, 0, gate=[verdict(1, accepted=True)], accepted_version=1), make_round(2, 1)]
    predictions = [*traffic(1, 0, hits=2, false_alarms=1, tokens=100), *traffic(2, 1, hits=2, false_alarms=1, tokens=105)]
    return write_run(tmp_path / name, records, predictions, config)


def test_compare_runs_pairs_every_arm_against_the_first(tmp_path: Path) -> None:
    reference = two_round_run(tmp_path)
    heuristic = baseline_run(tmp_path, "arena-heuristic", "heuristic")

    first, second = report.compare_runs([reference, heuristic])

    assert first["arm"] == "curator=llm gate=guarded poisoning=False failure_rate=0.0"
    assert second["arm"].startswith("curator=heuristic")
    assert first["reference"] == second["reference"] == "arena-llm"
    assert "card" in first["compared_on"] and "gate_split" in first["compared_on"]
    # The reference paired against itself: every Flow its final Context judged, the ten of the traffic and the two held-out ones.
    assert (first["vs_reference_flows"], first["vs_reference_discordant"], first["vs_reference_mcnemar_p"]) == (12, 0, 1.0)
    # The heuristic arm's final Context caught one attack Flow fewer than the LLM arm's, over the same ten Flows.
    assert (second["vs_reference_flows"], second["vs_reference_discordant"]) == (10, 2)
    assert (second["vs_reference_correct"], second["reference_correct"]) == (0, 2)
    # Each arm's own answer travels in the same row, tokens included, so the length the recall was bought at is never out of sight.
    assert (second["recall_final"], second["input_tokens_mean_final"]) == (0.5, 105.0)
    # The two arms' attackers ended on different knob settings here only because the strategies differ; the column never assumes they do.
    assert first["vs_reference_same_strategies"] is True


def altered(tmp_path: Path, name: str, path: tuple[str, ...], value: Any) -> Path:
    """A Run whose config differs from CONFIG at one key path and nowhere else."""
    config = json.loads(json.dumps(CONFIG))
    config["run_id"] = name
    table: Any = config
    for key in path[:-1]:
        table = table[key]
    table[path[-1]] = value
    return write_run(tmp_path / name, [make_round(1, 0)], traffic(1, 0, hits=2, false_alarms=1, tokens=100), config)


def test_compare_runs_refuses_runs_measured_over_different_splits(tmp_path: Path) -> None:
    reference = two_round_run(tmp_path)
    moved = altered(tmp_path, "arena-elsewhere", ("inputs", "gate_split"), "another-hash")

    with pytest.raises(ValueError, match="gate_split is 'gate-hash' in .* and 'another-hash' in") as raised:
        report.compare_runs([reference, moved])
    assert "not a comparison" in str(raised.value)


def test_compare_runs_refuses_runs_whose_card_differs(tmp_path: Path) -> None:
    reference = two_round_run(tmp_path)
    elsewhere = altered(tmp_path, "arena-other-card", ("inputs", "dataset"), "another-hash")

    with pytest.raises(ValueError, match="card is 'card-hash'"):
        report.compare_runs([reference, elsewhere])


def test_compare_runs_refuses_a_longer_experiment_against_a_shorter_one(tmp_path: Path) -> None:
    reference = two_round_run(tmp_path)

    # Ten Rounds against two is not an arm against an arm, and the extra Rounds would read as the curator's doing.
    with pytest.raises(ValueError, match="rounds is 2 .* and 10 in"):
        report.compare_runs([reference, altered(tmp_path, "arena-longer", ("config", "arena", "rounds"), 10)])
    # The same for the Detector under attack, the Examples it is given, and the prompt template both were measured on.
    with pytest.raises(ValueError, match="detector is 'jev' .* and 'offline' in"):
        report.compare_runs([reference, altered(tmp_path, "arena-offline", ("config", "detector", "name"), "offline")])
    with pytest.raises(ValueError, match="k is 1 .* and 4 in"):
        report.compare_runs([reference, altered(tmp_path, "arena-k4", ("config", "detector", "k"), 4)])
    with pytest.raises(ValueError, match="prompt is 'prompt-hash' .* and 'reworded' in"):
        report.compare_runs([reference, altered(tmp_path, "arena-reworded", ("inputs", "prompt"), "reworded")])


def test_compare_runs_refuses_splits_that_were_never_hashed(tmp_path: Path) -> None:
    # Two Runs naming `arena` and `arena-val` and hashing neither: the names match and the bytes are unknown, which is not a check.
    unhashed = [altered(tmp_path, name, ("inputs",), {"dataset": "card-hash", "prompt": "prompt-hash"}) for name in ("a", "b")]

    with pytest.raises(ValueError, match="No Run recorded the sha256 of its Splits"):
        report.compare_runs(unhashed)


def test_compare_runs_refuses_runs_that_recorded_nothing_to_compare_on(tmp_path: Path) -> None:
    records, predictions = [make_round(1, 0)], traffic(1, 0, hits=2, false_alarms=1, tokens=100)
    bare = [write_run(tmp_path / name, records, predictions, {"run_id": name}) for name in ("bare-a", "bare-b")]

    # A check that could not run is not a check that passed: every dimension is named, and none is assumed equal.
    with pytest.raises(ValueError) as raised:
        report.compare_runs(bare)
    for dimension in ("Card", "Splits", "attacker settings", "prompt template", "Detector", "Rounds"):
        assert dimension in str(raised.value), dimension


def test_compare_runs_says_in_the_table_that_prompt_length_is_not_controlled_here(tmp_path: Path) -> None:
    reference = two_round_run(tmp_path)
    heuristic = baseline_run(tmp_path, "arena-heuristic", "heuristic")

    rows = report.compare_runs([reference, heuristic])

    # Every row carries it, because every row is one a reader could quote on its own, and it points at where the control does live.
    for row in rows:
        assert row["prompt_length_control"] == report.PROMPT_LENGTH_CONTROL
    assert "prompt length not controlled here" in report.PROMPT_LENGTH_CONTROL
    assert "jev_ids/arena/final.py" in report.PROMPT_LENGTH_CONTROL


def test_the_rows_render_as_csv_unchanged(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cli.print_csv(report.summarize_rounds(two_round_run(tmp_path)))
    header, first, _second = capsys.readouterr().out.splitlines()
    assert header.startswith("run_id,seed,round,context_version,rules,examples,attacker_flows")
    assert "evasion_rate" in header and "input_tokens_mean" in header
    assert first.startswith("arena-llm,0,1,0,0,0,20,7,0.35")
