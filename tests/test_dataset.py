"""Loader, category table, novel flag, formats, k-shot sampling and splits."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from somids import dataset

BASE_VALUES: list[str] = ["0"] * len(dataset.COLUMNS)
BASE_VALUES[1:4] = ["tcp", "http", "SF"]


def make_line(attack_name: str, difficulty: int = 20, src_bytes: str = "0") -> str:
    values = list(BASE_VALUES)
    values[4] = src_bytes
    return ",".join([*values, attack_name, str(difficulty)])


TRAIN_ROWS = [
    ("normal", "10"),
    ("normal", "11"),
    ("normal", "12"),
    ("neptune", "0"),
    ("neptune", "1"),
    ("satan", "2"),
    ("satan", "3"),
    ("guess_passwd", "4"),
    ("guess_passwd", "5"),
    ("buffer_overflow", "6"),
    ("buffer_overflow", "7"),
]
TEST_ROWS = [
    ("normal", "20"),
    ("normal", "21"),
    ("normal", "22"),
    ("normal", "23"),
    ("neptune", "24"),
    ("neptune", "25"),
    ("apache2", "26"),
    ("apache2", "27"),
    ("mscan", "28"),
    ("ps", "29"),
]


def fake_which(_name: str) -> str:
    return "/opt/bin/kaggle"


def missing_which(_name: str) -> None:
    return None


@pytest.fixture
def raw_dir(tmp_path: Path) -> Path:
    """Train+ at the mirror root, Test+ under the mirror's subdirectory."""
    raw = tmp_path / "raw"
    (raw / dataset.MIRROR_SUBDIR).mkdir(parents=True)
    train = "".join(make_line(name, src_bytes=b) + "\n" for name, b in TRAIN_ROWS)
    test = "".join(make_line(name, src_bytes=b) + "\n" for name, b in TEST_ROWS)
    (raw / dataset.TRAIN_FILE).write_text(train, encoding="utf-8")
    (raw / dataset.MIRROR_SUBDIR / dataset.TEST_FILE).write_text(test, encoding="utf-8")
    return raw


def test_parse_line_exposes_values_category_and_difficulty() -> None:
    flow = dataset.parse_line(7, make_line("teardrop", difficulty=15) + "\n")
    assert flow.row_id == 7
    assert len(flow.values) == 41
    assert flow.values[1:4] == ("tcp", "http", "SF")
    assert flow.attack_name == "teardrop"
    assert flow.category == "dos"
    assert flow.is_attack
    assert flow.difficulty == 15
    assert not flow.novel_attack


def test_parse_line_rejects_wrong_field_count() -> None:
    with pytest.raises(ValueError, match="expected 43 fields"):
        dataset.parse_line(0, "0,tcp,http")


def test_category_table_covers_all_names_and_rejects_unknown() -> None:
    assert dataset.category_of("normal") == "normal"
    assert dataset.category_of("snmpgetattack") == "r2l"
    assert dataset.category_of("worm") == "r2l"
    assert dataset.category_of("httptunnel") == "u2r"
    assert len(dataset.ATTACK_CATEGORY) == 39
    with pytest.raises(KeyError, match="missing from ATTACK_CATEGORY"):
        dataset.category_of("teleport")


def test_load_test_derives_novel_attack_from_train_names(raw_dir: Path) -> None:
    test = dataset.load_test(raw_dir)
    by_name = {flow.attack_name: flow for flow in test}
    assert [flow.row_id for flow in test] == list(range(len(TEST_ROWS)))
    assert by_name["apache2"].novel_attack
    assert by_name["mscan"].novel_attack
    assert by_name["ps"].novel_attack
    assert not by_name["neptune"].novel_attack
    assert not by_name["normal"].novel_attack


def test_format_flow_csv_and_kv() -> None:
    flow = dataset.parse_line(0, make_line("normal", src_bytes="291"))
    assert dataset.format_flow(flow, "csv") == flow.text
    kv = dataset.format_flow(flow, "kv")
    assert kv.startswith(
        "duration=0 protocol_type=tcp service=http flag=SF src_bytes=291"
    )
    assert kv.count("=") == 41


def test_sample_examples_is_balanced_nested_and_deterministic(raw_dir: Path) -> None:
    train = dataset.load_train(raw_dir)
    k1 = dataset.sample_examples(train, 1, seed=0)
    k2 = dataset.sample_examples(train, 2, seed=0)
    assert len(k1) == 5
    assert len(k2) == 10
    for category in dataset.CATEGORIES:
        assert sum(example.category == category for example in k2) == 2
    ids_k1 = {example.flow.row_id for example in k1}
    ids_k2 = {example.flow.row_id for example in k2}
    assert ids_k1 <= ids_k2
    assert dataset.sample_examples(train, 2, seed=0) == k2
    with pytest.raises(ValueError, match="k = 3 asked"):
        dataset.sample_examples(train, 3, seed=0)


def test_draw_splits_is_disjoint_and_enforces_the_novel_floor(raw_dir: Path) -> None:
    test = dataset.load_test(raw_dir)
    sizes = {"internal": 3, "paper": 5, "smoke": 2}
    splits = dataset.draw_splits(test, sizes, seed=1, min_novel_in_paper=0)
    assert {name: len(flows) for name, flows in splits.items()} == sizes
    all_ids = [flow.row_id for flows in splits.values() for flow in flows]
    assert len(all_ids) == len(set(all_ids))
    with pytest.raises(ValueError, match="below the floor of 10"):
        dataset.draw_splits(test, sizes, seed=1, min_novel_in_paper=10)


def test_write_splits_round_trips_and_writes_manifest(
    raw_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dataset, "SPLIT_SIZES", {"internal": 3, "paper": 5, "smoke": 2})
    monkeypatch.setattr(dataset, "MIN_NOVEL_IN_PAPER", 0)
    splits_dir = tmp_path / "splits"

    manifest_path = dataset.write_splits(raw_dir, splits_dir)

    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["sizes"] == {"internal": 3, "paper": 5, "smoke": 2}
    assert manifest["category_table_version"] == dataset.CATEGORY_TABLE_VERSION
    assert set(manifest["source_files"]) == {dataset.TRAIN_FILE, dataset.TEST_FILE}
    reloaded = dataset.load_split("paper", splits_dir)
    original = dataset.draw_splits(
        dataset.load_test(raw_dir), dataset.SPLIT_SIZES, min_novel_in_paper=0
    )["paper"]
    assert reloaded == original


def hard_rows() -> list[dataset.Flow]:
    names = ["normal", "normal", "normal", "neptune", "mscan", "apache2"]
    hard = [
        dataset.parse_line(i, make_line(name, difficulty=5) + "\n")
        for i, name in enumerate(names)
    ]
    easy = [
        dataset.parse_line(10 + i, make_line(name, difficulty=20) + "\n")
        for i, name in enumerate(["normal", "neptune"])
    ]
    return [*hard, *easy]


def test_draw_band_split_is_balanced_filtered_disjoint_and_seeded() -> None:
    rows = hard_rows()
    band = dataset.Band(size=4, min_difficulty=0, max_difficulty=10)
    drawn = dataset.draw_band_split(rows, {0}, band, seed=1)
    assert len(drawn) == 4
    assert sum(flow.is_attack for flow in drawn) == 2
    assert all(flow.difficulty <= 10 for flow in drawn)
    assert 0 not in {flow.row_id for flow in drawn}
    assert drawn == dataset.draw_band_split(rows, {0}, band, seed=1)
    with pytest.raises(ValueError, match="only 1 unused normal flows in the band"):
        dataset.draw_band_split(rows, {0, 1}, band, seed=1)


def test_draw_band_split_respects_the_lower_bound() -> None:
    band = dataset.Band(size=2, min_difficulty=11, max_difficulty=21)
    drawn = dataset.draw_band_split(hard_rows(), set(), band, seed=1)
    assert {flow.difficulty for flow in drawn} == {20}


def test_write_band_split_stays_disjoint_and_extends_the_manifest(
    raw_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    splits_dir = tmp_path / "splits"
    splits_dir.mkdir()
    test = dataset.load_test(raw_dir)
    dataset.write_split(test[:1], splits_dir / "internal.csv")
    dataset.write_split(test[1:2], splits_dir / "hard.csv")
    monkeypatch.setattr(dataset, "SPLIT_SIZES", {"internal": 1})
    band = dataset.Band(size=4, min_difficulty=0, max_difficulty=21)
    monkeypatch.setattr(dataset, "BANDS", {"hard": band, "mid": band})

    manifest_path = dataset.write_band_split("mid", raw_dir, splits_dir)

    mid = dataset.load_split("mid", splits_dir)
    assert len(mid) == 4
    assert sum(flow.is_attack for flow in mid) == 2
    assert {flow.row_id for flow in mid}.isdisjoint({0, 1})
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["sizes"] == {"internal": 1, "hard": 1, "mid": 4}
    assert set(manifest["bands"]) == {"hard", "mid"}
    assert manifest["bands"]["mid"] == {
        "min_difficulty": 0,
        "max_difficulty": 21,
        "balanced_classes": True,
    }


def test_verify_checksums_accepts_unpinned_and_rejects_mismatch(
    raw_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dataset, "CHECKSUMS", {dataset.TRAIN_FILE: ""})
    digests = dataset.verify_checksums(raw_dir)
    assert len(digests[dataset.TRAIN_FILE]) == 64
    monkeypatch.setattr(dataset, "CHECKSUMS", {dataset.TRAIN_FILE: "0" * 64})
    with pytest.raises(ValueError, match="differs from the pinned"):
        dataset.verify_checksums(raw_dir)


def test_download_skips_kaggle_when_files_exist(
    raw_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("kaggle must not run when the files exist")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(
        dataset, "CHECKSUMS", {dataset.TRAIN_FILE: "", dataset.TEST_FILE: ""}
    )
    digests = dataset.download(raw_dir)
    assert set(digests) == {dataset.TRAIN_FILE, dataset.TEST_FILE}


def test_download_runs_kaggle_when_files_are_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = tmp_path / "raw"
    calls: list[list[str]] = []

    def fake_run(command: list[str], *, check: bool) -> None:
        calls.append(command)
        assert check
        (raw / dataset.TRAIN_FILE).write_text(make_line("normal") + "\n")
        (raw / dataset.TEST_FILE).write_text(make_line("apache2") + "\n")

    monkeypatch.setattr(dataset.shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(
        dataset, "CHECKSUMS", {dataset.TRAIN_FILE: "", dataset.TEST_FILE: ""}
    )

    dataset.download(raw)

    assert calls == [
        ["/opt/bin/kaggle", "datasets", "download", "-d", dataset.KAGGLE_DATASET]
        + ["-p", str(raw), "--unzip"]
    ]


def test_download_requires_the_kaggle_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dataset.shutil, "which", missing_which)
    with pytest.raises(FileNotFoundError, match="kaggle"):
        dataset.download(tmp_path / "raw")


def test_resolve_raw_reports_missing_files(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="somids download"):
        dataset.resolve_raw(tmp_path, dataset.TEST_FILE)
