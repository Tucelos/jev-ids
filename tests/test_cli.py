"""CLI wiring for the run, metrics and compare subcommands."""

from pathlib import Path

import pytest

from somids import cli, records, run
from tests.helpers import make_prediction


def test_missing_arguments_and_removed_commands_are_rejected() -> None:
    with pytest.raises(SystemExit):
        cli.main(["metrics"])
    with pytest.raises(SystemExit):  # --dataset is required
        cli.main(["run", "--detector", "jev", "--split", "pilot"])
    for removed in ("download", "split"):
        with pytest.raises(SystemExit):
            cli.main([removed])


def test_run_builds_a_spec_from_the_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[run.RunSpec] = []

    def fake_run(spec: run.RunSpec) -> Path:
        seen.append(spec)
        return Path("x")

    monkeypatch.setattr(run, "run_from_spec", fake_run)
    card = "data/x/dataset.json"
    argv = ["run", "--dataset", card, "--detector", "random_forest", "--split", "smoke"]
    argv += ["--k", "1,all", "--seeds", "1", "--reps", "3", "--model", "m"]
    assert cli.main(argv) == 0
    expected = run.RunSpec("random_forest", Path(card), "smoke", (1, None), (1,), reps=3, model_id="m")
    assert seen == [expected]
    argv = ["run", "--dataset", card, "--detector", "jev", "--split", "pilot"]
    assert cli.main(argv) == 0
    assert seen[1].k_values == (0, 1, 2, 4, 8, 16)
    assert seen[1].seeds == (0, 1, 2)
    assert seen[1].model_id is None


def test_metrics_prints_one_csv_over_every_run_given(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    records.append_prediction(tmp_path / "a", make_prediction(1, 1, 0.9))
    # The second run reports one usage field the first lacks: the header is the union of the rows' keys, in order of first appearance.
    other = make_prediction(2, 0, 0.1, detector="random_forest", usage={"duration": 2.0})
    records.append_prediction(tmp_path / "b", other)
    assert cli.main(["metrics", str(tmp_path / "a"), str(tmp_path / "b")]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("dataset,detector,model,split,k,cells,flows,predictions,f1_mean,")
    assert lines[0].endswith(",cost_usd_per_1m,latency_ms_mean,duration_mean")
    assert len(lines) == 3
    assert lines[1] == "test,jev,m,internal,1,1,1,1,1.0,1.0,1.0,,1.0,0.0,,100.0,10.0,,500.0,"
    assert lines[2] == "test,random_forest,m,internal,1,1,1,1,,,,,,0.0,,,,,500.0,2.0"
    assert cli.main(["metrics", str(tmp_path / "empty")]) == 0
    assert capsys.readouterr().out == ""


def test_compare_selects_the_subset_cuts_to_ks_and_prints_csv(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a = [make_prediction(0, 1, 1.0, novel_attack=True), make_prediction(1, 1, 0.0)]
    b = [
        make_prediction(0, 1, 0.0, novel_attack=True, k=None),
        make_prediction(1, 1, 1.0, k=None),
    ]
    for prediction in [*a, *b]:
        records.append_prediction(tmp_path / prediction["detector"], prediction)
    argv = ["compare", str(tmp_path / "jev"), str(tmp_path / "jev")]
    argv += ["--subset", "novel", "--k-a", "1", "--k-b", "all"]
    assert cli.main(argv) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "k_a,k_b,repetition,pairs,discordant,a_correct,b_correct,mcnemar_p,f1_a,f1_b"
    assert lines[1] == "1,,0,1,1,1,0,1.0,1.0,0.0"
    with pytest.raises(SystemExit, match="come together"):
        cli.main(["compare", "a", "b", "--k-a", "0"])
