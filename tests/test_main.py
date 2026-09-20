"""CLI wiring for the download and split subcommands."""

from __future__ import annotations

from pathlib import Path

import pytest

from somids import __main__ as cli
from somids import compare, dataset, metrics, run


def test_download_prints_digests(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(dataset, "download", lambda: {"KDDTest+.txt": "abc"})
    assert cli.main(["download"]) == 0
    assert capsys.readouterr().out == "KDDTest+.txt: sha256 abc\n"


def test_split_prints_the_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = tmp_path / "SOURCE.json"
    manifest.write_text('{"seed": 1}\n', encoding="utf-8")
    monkeypatch.setattr(dataset, "write_splits", lambda: manifest)
    assert cli.main(["split"]) == 0
    assert capsys.readouterr().out == '{"seed": 1}\n'


def test_split_band_draws_only_that_band(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = tmp_path / "SOURCE.json"
    manifest.write_text('{"sizes": {"mid": 4}}\n', encoding="utf-8")
    seen: list[str] = []

    def fake_band(name: str) -> Path:
        seen.append(name)
        return manifest

    monkeypatch.setattr(dataset, "write_band_split", fake_band)
    monkeypatch.setattr(dataset, "write_splits", must_not_run)
    assert cli.main(["split", "--band", "mid"]) == 0
    assert seen == ["mid"]
    assert capsys.readouterr().out == '{"sizes": {"mid": 4}}\n'


def must_not_run() -> Path:
    msg = "the proportional splits must not be redrawn by `split --band`"
    raise AssertionError(msg)


def test_compare_passes_both_runs_and_the_resamples(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[Path, Path, int]] = []

    def fake_report(run_a: Path, run_b: Path, resamples: int) -> list[object]:
        seen.append((run_a, run_b, resamples))
        return []

    monkeypatch.setattr(compare, "report", fake_report)
    assert cli.main(["compare", "results/a", "results/b", "--bootstrap", "10"]) == 0
    assert seen == [(Path("results/a"), Path("results/b"), 10)]


def test_unknown_command_is_rejected() -> None:
    with pytest.raises(SystemExit):
        cli.main(["metrics"])


def test_run_builds_a_spec_from_the_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[run.RunSpec] = []

    def fake_run(spec: run.RunSpec) -> Path:
        seen.append(spec)
        return Path("x")

    monkeypatch.setattr(run, "run_from_spec", fake_run)
    argv = [
        "run",
        "--detector",
        "jev",
        "--split",
        "smoke",
        "--k",
        "0,4",
        "--seeds",
        "1",
    ]
    argv += ["--reps", "3", "--format", "kv"]
    assert cli.main(argv) == 0
    assert seen == [
        run.RunSpec("jev", "smoke", (0, 4), (1,), reps=3, batch=1, fmt="kv")
    ]


def test_metrics_passes_the_run_directories(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[list[Path], Path | None]] = []

    def fake_report(run_dirs: list[Path], out: Path | None) -> Path:
        seen.append((run_dirs, out))
        return Path("summary.csv")

    monkeypatch.setattr(metrics, "report", fake_report)
    assert cli.main(["metrics", "results/a", "results/b", "--out", "x.csv"]) == 0
    assert seen == [([Path("results/a"), Path("results/b")], Path("x.csv"))]


def test_k_accepts_all() -> None:
    assert cli.parse_ks("0,1, all") == (0, 1, None)
