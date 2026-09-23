"""Draw one split from a dataset's test file, disjoint from every split already on disk.

Run from the repository root. The `paper` split of NSL-KDD was drawn proportionally, and the Arena's two splits by stated Category counts:

    uv run python -m scripts.draw_split --dataset data/nsl-kdd --name paper --size 2000 --min-novel 300
    uv run python -m scripts.draw_split --dataset data/nsl-kdd --name arena --counts normal=250,r2l=150,dos=100,probe=40,u2r=10

The rows of `test.csv` are shuffled once with the seed and the rows whose `row_id` no other split file holds are taken: `--size` takes the
first of them, so a uniform sample keeps the file's mix of Categories and of novel attacks and the split is proportional; `--counts` takes
the first of each Category named, so the split states its own mix (see `stratified`). Skipping the taken rows keeps a split disjoint from
the ones it leaves in place. A split of the same name is replaced and does not count as taken. Rows are copied verbatim from the test
file, header included, so the split keeps its trace columns. `SOURCE.json` gets the new size, the novel count and the draw.
"""

import argparse
import csv
import json
import random
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from jev_ids.dataset import write_split


def parse_args() -> argparse.Namespace:
    """The command line: the dataset folder, the split's name and size, the seed and the novel floor."""
    parser = argparse.ArgumentParser(description="draw one split from a dataset's test file")
    parser.add_argument("--dataset", type=Path, required=True, help="folder holding test.csv and splits/")
    parser.add_argument("--name", required=True, help="the split to write, splits/<name>.csv")
    parser.add_argument("--size", type=int, help="rows to draw; omit when --counts says how many of each Category")
    parser.add_argument("--seed", type=int, default=20260920, help="the seed the other NSL-KDD splits were drawn with")
    parser.add_argument("--min-novel", type=int, default=0, help="refuse a draw with fewer novel-attack rows than this")
    parser.add_argument("--counts", type=parse_counts, help="stratified draw, `normal=300,r2l=150,dos=100`, instead of a proportional one")
    args = parser.parse_args()
    if (args.size is None) == (args.counts is None):
        parser.error("give either --size, for a proportional draw, or --counts, for a stratified one")
    return args


def parse_counts(text: str) -> dict[str, int]:
    """`normal=300,r2l=150` as a mapping; the Categories a stratified draw asks for."""
    counts: dict[str, int] = {}
    for part in text.split(","):
        name, _, size = part.partition("=")
        counts[name.strip()] = int(size)
    return counts


def stratified(rows: list[list[str]], header: Sequence[str], counts: Mapping[str, int]) -> list[list[str]]:
    """The first `counts[category]` Flows of each Category asked for, in the shuffled order.

    A proportional draw keeps a Dataset's own mix, which is what the reported splits want. A stratified one states the mix instead, for a
    split whose job is to exercise a Category the Dataset is thin on: NSL-KDD's test file is 12% r2l, too few for an attacker to work
    with in one Round. The order of the rows stays the shuffled one, so the file is not grouped by Category.
    """
    category = header.index("category")
    remaining = dict(counts)
    drawn: list[list[str]] = []
    for row in rows:
        if remaining.get(row[category], 0) > 0:
            drawn.append(row)
            remaining[row[category]] -= 1
    missing = {name: short for name, short in remaining.items() if short > 0}
    if missing:
        raise ValueError(f"the test file has no untaken Flows left for {missing}")
    return drawn


def taken_row_ids(splits_dir: Path, name: str) -> tuple[list[str], set[str]]:
    """The names of the other split files and every row_id they hold."""
    others = sorted(path.stem for path in splits_dir.glob("*.csv") if path.stem != name)
    taken: set[str] = set()
    for other in others:
        with (splits_dir / f"{other}.csv").open(encoding="utf-8", newline="") as handle:
            taken.update(row["row_id"] for row in csv.DictReader(handle))
    return others, taken


def main() -> None:
    """Draw the split, write it next to the others and record it in SOURCE.json."""
    args = parse_args()
    with (args.dataset / "test.csv").open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        rows = list(reader)
    row_id, novel = header.index("row_id"), header.index("novel_attack")
    others, taken = taken_row_ids(args.dataset / "splits", args.name)
    random.Random(args.seed).shuffle(rows)  # noqa: S311  seeded, reproducible draw
    free = [row for row in rows if row[row_id] not in taken]
    drawn = stratified(free, header, args.counts) if args.counts else free[: args.size]
    novel_rows = sum(row[novel] == "1" for row in drawn)
    wanted = sum(args.counts.values()) if args.counts else args.size
    if len(drawn) < wanted or novel_rows < args.min_novel:
        raise ValueError(f"{len(drawn)} rows drawn, {novel_rows} novel attacks; asked {wanted} with at least {args.min_novel} novel")
    write_split(args.dataset / "splits" / f"{args.name}.csv", header, drawn)

    # The manifest keeps the sizes and novel counts of every split, plus how this one was drawn, so the draw can be audited and repeated.
    manifest_path = args.dataset / "splits" / "SOURCE.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["sizes"][args.name] = len(drawn)
    manifest["novel_attack_rows"][args.name] = novel_rows
    manifest.setdefault("draws", {})[args.name] = {
        "seed": args.seed,
        "disjoint_from": others,
        "drawn_on": datetime.now(UTC).date().isoformat(),
        "counts": args.counts,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"{args.name}: {len(drawn)} rows, {novel_rows} novel attacks, disjoint from {', '.join(others)}")


if __name__ == "__main__":
    main()
