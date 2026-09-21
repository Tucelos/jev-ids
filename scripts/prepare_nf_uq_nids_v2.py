"""Sample NF-UQ-NIDS-v2 into the shared CSV shape of `data/nf-uq-nids-v2/`, in one pass.

Run once, from the repository root, after downloading
https://www.kaggle.com/datasets/aryashah2k/nfuqnidsv2-network-intrusion-detection-dataset into `data/raw/nf-uq-nids-v2/` (one CSV of about
13.7 GB, with a header):

    uv run python -m scripts.prepare_nf_uq_nids_v2 --novel <CATEGORY> [<CATEGORY> ...]

The file is far too large to be a pool, so one pass over it fills two kinds of reservoir at once: one per category for `pool.csv`
(`--pool-per-category` rows each, none for the categories named by `--novel`, which are held out as novel attacks) and one uniform sample of
`--test-size` rows from which the `smoke`, `internal` and `paper` splits are cut in seeded order, after dropping any row that also landed in
the pool. The card's `features` decide which columns are kept: the two IPv4 addresses are out because they identify the testbed, not the
traffic; the `Dataset` column survives as the trace column `source_dataset`. `SOURCE.json` records the file's sha256, the rows read, the
count per category, the seed, the sizes, the held-out categories and the dropped columns. Here k = all means the whole pool, a
class-balanced sample, not the whole file. Rehearse with a `head -n 200000` copy of the file before the full pass.
"""

import argparse
import csv
import hashlib
import json
import random
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from somids.dataset import Config, load_config, write_split

KAGGLE_DATASET = "aryashah2k/nfuqnidsv2-network-intrusion-detection-dataset"
LABEL_COLUMN = "Attack"
TESTBED_COLUMN = "Dataset"
# Proportional splits cut from the uniform reservoir.
SPLIT_SIZES = {"smoke": 5, "internal": 50, "paper": 300}

# One retained record: its 0-based index among the data rows (the file line is row_id + 2, the header being line 1) and its raw fields.
Row = tuple[int, list[str]]


def parse_args() -> argparse.Namespace:
    """The command line: the raw CSV, the output folder and the sampling knobs."""
    parser = argparse.ArgumentParser(description="prepare NF-UQ-NIDS-v2 for somids")
    parser.add_argument(
        "--raw",
        type=Path,
        default=Path("data/raw/nf-uq-nids-v2/NF-UQ-NIDS-v2.csv"),
        help="the raw CSV with a header",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("data/nf-uq-nids-v2"),
        help="folder holding dataset.json; receives pool.csv, splits/ and SOURCE.json",
    )
    parser.add_argument("--pool-per-category", type=int, default=2000)
    parser.add_argument("--test-size", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=20260921)
    parser.add_argument(
        "--novel",
        nargs="*",
        default=[],
        metavar="CATEGORY",
        help="categories held out of the pool; their Flows are the novel attacks",
    )
    return parser.parse_args()


def check_header(header: Sequence[str], config: Config, novel: Sequence[str]) -> None:
    """Refuse a header that lacks a card feature, or a `--novel` name off the card."""
    missing = [name for name in [*config["features"], LABEL_COLUMN, TESTBED_COLUMN] if name not in header]
    if missing:
        raise ValueError(f"the CSV header lacks {missing}")
    unknown = [name for name in novel if name not in config["categories"]]
    if unknown:
        raise ValueError(f"--novel names {unknown} are not categories of the card")


def offer(bucket: list[Row], size: int, seen: int, item: Row, rng: random.Random) -> None:
    """Reservoir step: keep each row seen so far with probability size/seen."""
    if len(bucket) < size:
        bucket.append(item)
    elif (slot := rng.randrange(seen)) < size:
        bucket[slot] = item


def sample(path: Path, config: Config, args: argparse.Namespace) -> tuple[list[str], dict[str, list[Row]], list[Row], Counter[str]]:
    """One pass: the header, the pool reservoirs, the test reservoir and the counts."""
    rng = random.Random(args.seed)  # noqa: S311  # seeded, reproducible draw
    pool: dict[str, list[Row]] = defaultdict(list)
    test: list[Row] = []
    counts: Counter[str] = Counter()
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        check_header(header, config, args.novel)
        label = header.index(LABEL_COLUMN)
        for index, fields in enumerate(reader):
            category = fields[label]
            counts[category] += 1
            if category not in args.novel:
                offer(
                    pool[category],
                    args.pool_per_category,
                    counts[category],
                    (index, fields),
                    rng,
                )
            offer(test, args.test_size, index + 1, (index, fields), rng)
    return header, pool, test, counts


def shared_rows(header: Sequence[str], config: Config, rows: Sequence[Row], novel: Sequence[str]) -> list[list[object]]:
    """Rows in the shared shape, plus the testbed as the trace column."""
    indexes = [header.index(name) for name in config["features"]]
    label, testbed = header.index(LABEL_COLUMN), header.index(TESTBED_COLUMN)
    return [
        [
            row_id,
            *(fields[i] for i in indexes),
            fields[label],
            int(fields[label] in novel),
            fields[testbed],
        ]
        for row_id, fields in rows
    ]


def cut_splits(test: Sequence[Row], pool_ids: set[int], seed: int) -> dict[str, list[Row]]:
    """The three disjoint splits, seeded order, from test rows outside the pool."""
    candidates = [row for row in test if row[0] not in pool_ids]
    random.Random(f"{seed}:splits").shuffle(candidates)  # noqa: S311  # seeded
    needed = sum(SPLIT_SIZES.values())
    if len(candidates) < needed:
        raise ValueError(f"{len(candidates)} test rows outside the pool; the splits need {needed}")
    splits: dict[str, list[Row]] = {}
    start = 0
    for name, size in SPLIT_SIZES.items():
        splits[name] = candidates[start : start + size]
        start += size
    return splits


def sha256_of(path: Path) -> str:
    """The sha256 hex digest of a file, read in 1 MiB chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def describe_splits(
    header: Sequence[str],
    config: Config,
    splits: dict[str, list[Row]],
    novel: Sequence[str],
) -> dict[str, object]:
    """The manifest entries about columns and splits: dropped, sizes, novel rows."""
    kept = {*config["features"], LABEL_COLUMN, TESTBED_COLUMN}
    label = header.index(LABEL_COLUMN)
    novel_rows = {name: sum(fields[label] in novel for _, fields in rows) for name, rows in splits.items()}
    return {
        "dropped_columns": [name for name in header if name not in kept],
        "sizes": {name: len(rows) for name, rows in splits.items()},
        "novel_attack_rows": novel_rows,
    }


def main() -> None:
    """Sample the raw file into pool.csv, splits/ and SOURCE.json next to the card."""
    args = parse_args()
    config = load_config(args.out / "dataset.json")
    header, pool, test, counts = sample(args.raw, config, args)
    pool_rows = sorted(row for rows in pool.values() for row in rows)
    splits = cut_splits(test, {row_id for row_id, _ in pool_rows}, args.seed)
    shared_header = [
        "row_id",
        *config["features"],
        "category",
        "novel_attack",
        "source_dataset",
    ]
    write_split(
        args.out / "pool.csv",
        shared_header,
        shared_rows(header, config, pool_rows, args.novel),
    )
    for name, rows in splits.items():
        write_split(
            args.out / "splits" / f"{name}.csv",
            shared_header,
            shared_rows(header, config, rows, args.novel),
        )
    manifest: dict[str, object] = {
        "dataset": KAGGLE_DATASET,
        "source_file": {
            "name": args.raw.name,
            "sha256": sha256_of(args.raw),
            "rows": sum(counts.values()),
        },
        "seed": args.seed,
        "pool_per_category": args.pool_per_category,
        "test_size": args.test_size,
        "novel_categories": list(args.novel),
        "rows_per_category": dict(counts.most_common()),
        "pool_rows": len(pool_rows),
        **describe_splits(header, config, splits, args.novel),
        "drawn_on": datetime.now(UTC).date().isoformat(),
    }
    (args.out / "splits" / "SOURCE.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    shown = ("source_file", "pool_rows", "sizes", "novel_attack_rows")
    print(json.dumps({key: manifest[key] for key in shown}, indent=2))


if __name__ == "__main__":
    main()
