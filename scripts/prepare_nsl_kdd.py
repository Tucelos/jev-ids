"""Convert the NSL-KDD Kaggle mirror into the shared CSV shape of `data/nsl-kdd/`.

Run once, from the repository root, after downloading https://www.kaggle.com/datasets/hassan06/nslkdd into `data/raw/nsl-kdd`:

    uv run python -m scripts.prepare_nsl_kdd

`KDDTrain+.txt` becomes `pool.csv`, the pool that Examples are drawn from, and `KDDTest+.txt` becomes `test.csv`, the file that splits are
drawn from. Both raw files have no header and 43 comma-separated fields per line: the 41 attributes of the card, the attack name and the
difficulty. The card's `attack_names` gives each name its category: the 22 training names follow the KDD Cup 99 page
`training_attack_types`; the 17 test-only names follow the majority of the published community mappings, which disagree only on
`snmpgetattack` and `worm` (r2l here, dos in one of them). A Test+ attack whose name never occurs in Train+ is a novel attack (CONTEXT.md,
"Novel attack").
"""

import argparse
from collections.abc import Mapping
from pathlib import Path

from somids.dataset import Config, load_config, write_split

TRAIN_FILE = "KDDTrain+.txt"
TEST_FILE = "KDDTest+.txt"
# Kept after the shared columns so a row can be traced back to its raw line.
EXTRA_COLUMNS = ("attack_name", "difficulty")


def category_by_name(config: Config) -> dict[str, str]:
    """Attack name -> category from the card; the benign label maps to itself."""
    categories = {config["benign"]: config["benign"]}
    for category, names in config["attack_names"].items():
        for name in names:
            categories[name] = category
    return categories


def read_lines(path: Path, width: int) -> list[list[str]]:
    """The fields of every line, in file order; a line of another width raises."""
    rows: list[list[str]] = []
    with path.open(encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            fields = line.rstrip("\r\n").split(",")
            if len(fields) != width:
                raise ValueError(f"{path.name} line {index}: {len(fields)} fields, expected {width}")
            rows.append(fields)
    return rows


def shared_row(
    row_id: int,
    fields: list[str],
    categories: Mapping[str, str],
    known: frozenset[str] | None,
) -> list[object]:
    """One row of the shared shape from the fields of one raw line.

    `known` holds the attack names of the training file: a test name outside it is a novel attack. None, for the training file itself, marks
    nothing.
    """
    *attributes, attack_name, _difficulty = fields
    novel = known is not None and attack_name not in known
    return [row_id, *attributes, categories[attack_name], int(novel)]


def convert(source: Path, target: Path, config: Config, known: frozenset[str] | None) -> frozenset[str]:
    """Write `source` as `target` in the shared shape; return the names it holds.

    `row_id` is the 0-based line index of the raw file, so a row can be checked against it with `sed -n`.
    """
    categories = category_by_name(config)
    lines = read_lines(source, len(config["features"]) + len(EXTRA_COLUMNS))
    rows = [[*shared_row(row_id, fields, categories, known), *fields[-2:]] for row_id, fields in enumerate(lines)]
    header = ["row_id", *config["features"], "category", "novel_attack"]
    write_split(target, [*header, *EXTRA_COLUMNS], rows)
    print(f"{target}: {len(rows)} rows")
    return frozenset(fields[-2] for fields in lines)


def main() -> None:
    """Convert the two raw files into pool.csv and test.csv next to the card."""
    parser = argparse.ArgumentParser(description="prepare NSL-KDD for somids")
    parser.add_argument(
        "--raw",
        type=Path,
        default=Path("data/raw/nsl-kdd"),
        help=f"folder holding {TRAIN_FILE} and {TEST_FILE}",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("data/nsl-kdd"),
        help="folder holding dataset.json; receives pool.csv and test.csv",
    )
    args = parser.parse_args()
    config = load_config(args.out / "dataset.json")
    train_names = convert(args.raw / TRAIN_FILE, args.out / "pool.csv", config, None)
    convert(args.raw / TEST_FILE, args.out / "test.csv", config, train_names)


if __name__ == "__main__":
    main()
