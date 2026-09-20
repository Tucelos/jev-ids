"""Versioned prompts: load `prompts/<version>.md`, split its sections and hash it."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from somids.dataset import CATEGORIES, ROOT, Category

PROMPTS_DIR = ROOT / "prompts"
SECTION_PATTERN = re.compile(r"^## (?P<title>.+?)\s*$", re.MULTILINE)
BULLET_PATTERN = re.compile(
    r"^- `(?P<name>[a-z0-9]+)`:\s*(?P<text>.+?)(?=^- `|\Z)", re.M | re.S
)


@dataclass(frozen=True, slots=True)
class Prompt:
    """One versioned prompt file, already split into its three sections."""

    version: str
    sha256: str
    task: str
    categories: dict[Category, str]
    columns: str

    @property
    def categories_text(self) -> str:
        return "\n".join(
            f"- `{name}`: {text}" for name, text in self.categories.items()
        )


def sections_of(markdown: str) -> dict[str, str]:
    """Map every `## Title` of a Markdown file to its body text."""
    matches = list(SECTION_PATTERN.finditer(markdown))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(markdown)
        sections[match.group("title")] = markdown[match.end() : end].strip()
    return sections


def parse_categories(body: str) -> dict[Category, str]:
    """Read the `- \\`name\\`: text` bullets of the Categories section."""
    found = {
        m.group("name"): " ".join(m.group("text").split())
        for m in BULLET_PATTERN.finditer(body)
    }
    missing = [name for name in CATEGORIES if name not in found]
    if missing:
        msg = f"prompt lacks a description for {missing}"
        raise ValueError(msg)
    return {name: found[name] for name in CATEGORIES}


def load_prompt(version: str = "v1", prompts_dir: Path = PROMPTS_DIR) -> Prompt:
    path = prompts_dir / f"{version}.md"
    raw = path.read_bytes()
    sections = sections_of(raw.decode("utf-8"))
    try:
        task, categories, columns = (
            sections["Task"],
            sections["Categories"],
            sections["Columns"],
        )
    except KeyError as exc:
        msg = f"{path} must have the sections Task, Categories and Columns"
        raise ValueError(msg) from exc
    return Prompt(
        version=version,
        sha256=hashlib.sha256(raw).hexdigest(),
        task=" ".join(task.split()),
        categories=parse_categories(categories),
        columns=columns.strip(),
    )
