"""CLI wiring for the download and split subcommands."""

from __future__ import annotations

from pathlib import Path

import pytest

from somids import __main__ as cli
from somids import dataset


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


def test_unknown_command_is_rejected() -> None:
    with pytest.raises(SystemExit):
        cli.main(["metrics"])
