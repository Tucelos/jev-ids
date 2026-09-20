"""Prompt files: sections, category bullets and hashing."""

from __future__ import annotations

from pathlib import Path

import pytest

from somids import prompt as prompt_module


def test_v1_has_the_three_sections_and_five_categories() -> None:
    loaded = prompt_module.load_prompt("v1")
    assert loaded.version == "v1"
    assert len(loaded.sha256) == 64
    assert loaded.task.startswith("You are given one record")
    assert list(loaded.categories) == ["normal", "dos", "probe", "r2l", "u2r"]
    assert loaded.categories["u2r"].startswith("user-to-root")
    assert loaded.columns.startswith("duration,protocol_type")
    assert loaded.categories_text.startswith("- `normal`: legitimate traffic.")


def test_missing_section_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "v9.md").write_text("# P\n\n## Task\n\nDo it.\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Task, Categories and Columns"):
        prompt_module.load_prompt("v9", tmp_path)


def test_missing_category_is_rejected() -> None:
    with pytest.raises(ValueError, match="lacks a description"):
        prompt_module.parse_categories("- `normal`: fine.\n- `dos`: flood.\n")
