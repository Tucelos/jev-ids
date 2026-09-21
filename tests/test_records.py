"""The Prediction row: completion by the run loop, and the run files."""

from pathlib import Path

from jev_ids import records
from tests.helpers import make_flow, make_prediction

FLOW = make_flow(3, "dos", novel_attack=True)
CELL = {
    "run_id": "r1",
    "dataset": "test",
    "detector": "jev",
    "model": "m",
    "split": "smoke",
    "prompt_hash": "abc",
    "k": 2,
    "seed": 0,
    "repetition": 0,
    "n_examples": 6,
}


def test_complete_prediction_adds_cell_truth_verdict_id_and_time() -> None:
    row = records.complete_prediction({"p_attack": 0.7, "latency_ms": 12.0}, FLOW, CELL)
    assert {name: row[name] for name in CELL} == CELL
    assert (row["row_id"], row["is_attack"], row["classification_verdict"]) == (3, 1, 1)
    assert (row["category_true"], row["novel_attack"]) == ("dos", True)
    assert (row["p_attack"], row["latency_ms"]) == (0.7, 12.0)
    assert len(row["request_id"]) == 36
    assert row["ts_utc"].endswith("+00:00")
    # The Verdict is taken at p_attack >= 0.5, the same point for every Detector.
    assert records.complete_prediction({"p_attack": 0.5}, FLOW, CELL)["classification_verdict"] == 1
    assert records.complete_prediction({"p_attack": 0.49}, FLOW, CELL)["classification_verdict"] == 0
    # A failed call has no p_attack at all; its Verdict is None (fail-open).
    measured = {"error": "HTTP 500", "retries": 4}
    failed = records.complete_prediction(measured, FLOW, CELL)
    assert (failed["classification_verdict"], failed["error"], failed["retries"]) == (
        None,
        "HTTP 500",
        4,
    )


def test_run_files_append_and_read_back(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    records.write_config(run_dir, {"spec": {"k": [0], "results_dir": tmp_path}})
    first = make_prediction(3, 1, 0.2, raw={"ok": True})
    second = make_prediction(3, 1, 0.9, rep=1)  # no raw answer, like the forest
    records.append_prediction(run_dir, first)
    records.append_prediction(run_dir, second)

    rows = records.read_predictions(run_dir)
    assert [p["p_attack"] for p in rows] == [0.2, 0.9]
    # Every key reaches the file but `raw`, which goes to responses.jsonl instead.
    assert set(rows[0]) == set(first) - {"raw"}
    assert set(rows[1]) == set(second)
    assert (run_dir / "config.json").read_text(encoding="utf-8").startswith("{")
    responses = (run_dir / "responses.jsonl").read_text(encoding="utf-8")
    assert responses.count("\n") == 1
    assert '"request_id": "q3", "response": {"ok": true}' in responses
    assert records.read_predictions(tmp_path / "missing") == []
