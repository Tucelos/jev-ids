"""NSL-KDD access: download, loading, category table, novel-attack flag, row
formats, frozen splits and nested k-shot sampling.

Vocabulary follows CONTEXT.md: a Flow is one NSL-KDD connection record, an
Example is a labeled Flow from KDDTrain+ shown to a Detector, and k is the
number of Examples per Category.
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import shutil
import subprocess
import sys
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
SPLITS_DIR = DATA_DIR / "splits"
MANIFEST_NAME = "SOURCE.json"

KAGGLE_DATASET = "hassan06/nslkdd"
TRAIN_FILE = "KDDTrain+.txt"
TEST_FILE = "KDDTest+.txt"
# The mirror ships every file twice: at the root and under this prefix.
MIRROR_SUBDIR = "nsl-kdd"

# sha256 of the mirror's files, pinned after the first download (2026-09-20).
# An empty value would mean "not pinned yet"; both were pinned on 2026-09-20.
CHECKSUMS: dict[str, str] = {
    TRAIN_FILE: "1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95",
    TEST_FILE: "fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84",
}

COLUMNS: tuple[str, ...] = (
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
)
# Each .txt line has the 41 attributes, the attack name and the difficulty.
FIELD_COUNT = len(COLUMNS) + 2

Category = Literal["normal", "dos", "probe", "r2l", "u2r"]
CATEGORIES: tuple[Category, ...] = ("normal", "dos", "probe", "r2l", "u2r")
RowFormat = Literal["csv", "kv"]

CATEGORY_TABLE_VERSION = "2026-09-20"
# The 22 training names follow the KDD Cup 99 page `training_attack_types`.
# The 17 test-only names follow the majority of the published community
# mappings (thinline72/nsl-kdd, gcamfer/Anomaly-ReactionRL, kahramankostas).
# Those mappings disagree only on `snmpgetattack` and `worm`, which one of the
# three files puts under dos; r2l is used here (remote access over SNMP and
# remote propagation). No primary source assigns the 17 test-only names.
ATTACK_CATEGORY: dict[str, Category] = {
    # dos, training
    "back": "dos",
    "land": "dos",
    "neptune": "dos",
    "pod": "dos",
    "smurf": "dos",
    "teardrop": "dos",
    # dos, test-only
    "apache2": "dos",
    "mailbomb": "dos",
    "processtable": "dos",
    "udpstorm": "dos",
    # probe, training
    "ipsweep": "probe",
    "nmap": "probe",
    "portsweep": "probe",
    "satan": "probe",
    # probe, test-only
    "mscan": "probe",
    "saint": "probe",
    # r2l, training
    "ftp_write": "r2l",
    "guess_passwd": "r2l",
    "imap": "r2l",
    "multihop": "r2l",
    "phf": "r2l",
    "spy": "r2l",
    "warezclient": "r2l",
    "warezmaster": "r2l",
    # r2l, test-only
    "named": "r2l",
    "sendmail": "r2l",
    "snmpgetattack": "r2l",  # source: majority mapping; alternative: dos
    "snmpguess": "r2l",
    "worm": "r2l",  # source: majority mapping; alternative: dos
    "xlock": "r2l",
    "xsnoop": "r2l",
    # u2r, training
    "buffer_overflow": "u2r",
    "loadmodule": "u2r",
    "perl": "u2r",
    "rootkit": "u2r",
    # u2r, test-only
    "httptunnel": "u2r",
    "ps": "u2r",
    "sqlattack": "u2r",
    "xterm": "u2r",
}

SPLIT_SIZES: dict[str, int] = {"internal": 50, "paper": 300, "smoke": 5}
SPLIT_SEED = 20260920
MIN_NOVEL_IN_PAPER = 30


@dataclass(frozen=True, slots=True)
class Band:
    """A diagnostic split: half attacks, half normals, all inside a band of
    NSL-KDD difficulty (how many of 21 classic learners got the record right)."""

    size: int
    min_difficulty: int
    max_difficulty: int


BANDS: dict[str, Band] = {
    # features point most learners the wrong way
    "hard": Band(size=100, min_difficulty=0, max_difficulty=10),
    # learners split; where two Detectors disagree the most
    "mid": Band(size=240, min_difficulty=11, max_difficulty=17),
}


@dataclass(frozen=True, slots=True)
class Flow:
    """One NSL-KDD connection record."""

    row_id: int
    text: str  # the 41 attribute values as in the file, comma separated
    attack_name: str
    difficulty: int
    novel_attack: bool = False

    @property
    def values(self) -> tuple[str, ...]:
        return tuple(self.text.split(","))

    @property
    def category(self) -> Category:
        return category_of(self.attack_name)

    @property
    def is_attack(self) -> bool:
        return self.attack_name != "normal"


@dataclass(frozen=True, slots=True)
class Example:
    """A labeled Flow from KDDTrain+ shown to a Detector."""

    flow: Flow
    category: Category


def category_of(attack_name: str) -> Category:
    """Map an attack name (or `normal`) to its Category; unknown names raise."""
    if attack_name == "normal":
        return "normal"
    try:
        return ATTACK_CATEGORY[attack_name]
    except KeyError as exc:
        msg = f"attack name {attack_name!r} is missing from ATTACK_CATEGORY"
        raise KeyError(msg) from exc


def parse_line(row_id: int, line: str) -> Flow:
    """Turn one line of a KDD*.txt file into a Flow."""
    fields = line.rstrip("\r\n").split(",")
    if len(fields) != FIELD_COUNT:
        msg = f"line {row_id}: expected {FIELD_COUNT} fields, found {len(fields)}"
        raise ValueError(msg)
    *values, attack_name, difficulty = fields
    return Flow(
        row_id=row_id,
        text=",".join(values),
        attack_name=sys.intern(attack_name),
        difficulty=int(difficulty),
    )


def read_flows(path: Path) -> list[Flow]:
    """Read every Flow of a KDD*.txt file; `row_id` is the 0-based line index."""
    with path.open(encoding="utf-8") as handle:
        return [parse_line(i, line) for i, line in enumerate(handle) if line.strip()]


def flag_novel(test: Iterable[Flow], train_names: frozenset[str]) -> list[Flow]:
    """Copy Test+ Flows with `novel_attack` set from the names seen in Train+."""
    return [
        Flow(
            row_id=flow.row_id,
            text=flow.text,
            attack_name=flow.attack_name,
            difficulty=flow.difficulty,
            novel_attack=flow.is_attack and flow.attack_name not in train_names,
        )
        for flow in test
    ]


def attack_names(flows: Iterable[Flow]) -> frozenset[str]:
    return frozenset(flow.attack_name for flow in flows if flow.is_attack)


def load_train(raw_dir: Path = RAW_DIR) -> list[Flow]:
    return read_flows(resolve_raw(raw_dir, TRAIN_FILE))


def load_test(raw_dir: Path = RAW_DIR) -> list[Flow]:
    """Test+ Flows with `novel_attack` derived from the names present in Train+."""
    train_names = attack_names(load_train(raw_dir))
    return flag_novel(read_flows(resolve_raw(raw_dir, TEST_FILE)), train_names)


def format_flow(flow: Flow, fmt: RowFormat) -> str:
    """Render the 41 attributes as raw CSV or as `name=value` pairs."""
    if fmt == "csv":
        return flow.text
    pairs = zip(COLUMNS, flow.values, strict=True)
    return " ".join(f"{name}={value}" for name, value in pairs)


def sample_examples(train: Sequence[Flow], k: int, seed: int) -> list[Example]:
    """k Examples per Category, drawn at random within each Category.

    For one seed the sets are nested across k (the Examples for k = 4 are among
    those for k = 8) because each Category uses a prefix of the same seeded
    permutation. The final order is a deterministic shuffle by seed, shared by
    every Detector.
    """
    chosen: list[Example] = []
    for category in CATEGORIES:
        pool = _category_pool(train, category, k, seed)
        chosen.extend(Example(flow, category) for flow in pool[:k])
    random.Random(f"{seed}:order").shuffle(chosen)  # noqa: S311
    return chosen


def _category_pool(
    train: Sequence[Flow], category: Category, k: int, seed: int
) -> list[Flow]:
    """The Flows of one Category in the seeded order that defines the k-prefix."""
    pool = [flow for flow in train if flow.category == category]
    if len(pool) < k:
        msg = f"category {category!r} has {len(pool)} flows, k = {k} asked"
        raise ValueError(msg)
    # Seeded sampling for reproducibility, not for secrecy.
    random.Random(f"{seed}:{category}").shuffle(pool)  # noqa: S311
    return pool


def draw_splits(
    test: Sequence[Flow],
    sizes: Mapping[str, int] = SPLIT_SIZES,
    seed: int = SPLIT_SEED,
    min_novel_in_paper: int = MIN_NOVEL_IN_PAPER,
) -> dict[str, list[Flow]]:
    """Disjoint, proportional random samples of Test+ cut from one permutation."""
    order = list(test)
    random.Random(seed).shuffle(order)  # noqa: S311  # seeded, reproducible draw
    splits: dict[str, list[Flow]] = {}
    start = 0
    for name, size in sizes.items():
        splits[name] = order[start : start + size]
        start += size
    novel = sum(flow.novel_attack for flow in splits.get("paper", []))
    if "paper" in splits and novel < min_novel_in_paper:
        msg = (
            f"paper split has {novel} novel-attack flows, below the floor of "
            f"{min_novel_in_paper}; raise its size instead of changing proportions"
        )
        raise ValueError(msg)
    return splits


def draw_band_split(
    test: Sequence[Flow],
    used_ids: Collection[int],
    band: Band,
    seed: int = SPLIT_SEED,
) -> list[Flow]:
    """Seeded balanced draw inside a difficulty band: `band.size // 2` attacks
    and as many normals, none of them in `used_ids`."""
    pool = [
        flow
        for flow in test
        if band.min_difficulty <= flow.difficulty <= band.max_difficulty
        and flow.row_id not in used_ids
    ]
    attacks = [flow for flow in pool if flow.is_attack]
    normals = [flow for flow in pool if not flow.is_attack]
    half = band.size // 2
    return [
        *_draw_class(attacks, half, seed, "attack"),
        *_draw_class(normals, half, seed, "normal"),
    ]


def _draw_class(candidates: list[Flow], count: int, seed: int, kind: str) -> list[Flow]:
    if len(candidates) < count:
        msg = (
            f"only {len(candidates)} unused {kind} flows in the band; "
            f"the split needs {count}"
        )
        raise ValueError(msg)
    random.Random(seed).shuffle(candidates)  # noqa: S311  # seeded, reproducible
    return candidates[:count]


def used_row_ids(splits_dir: Path, names: Iterable[str]) -> set[int]:
    """Row ids already taken by the named split files."""
    return {flow.row_id for name in names for flow in load_split(name, splits_dir)}


SPLIT_HEADER: tuple[str, ...] = (
    "row_id",
    *COLUMNS,
    "attack_name",
    "difficulty",
    "category",
    "novel_attack",
)


def write_split(flows: Sequence[Flow], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(SPLIT_HEADER)
        for flow in flows:
            writer.writerow(
                [
                    flow.row_id,
                    *flow.values,
                    flow.attack_name,
                    flow.difficulty,
                    flow.category,
                    int(flow.novel_attack),
                ]
            )


def load_split(name: str, splits_dir: Path = SPLITS_DIR) -> list[Flow]:
    """Read a committed split back into Flows."""
    path = splits_dir / f"{name}.csv"
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return [
            Flow(
                row_id=int(row["row_id"]),
                text=",".join(row[column] for column in COLUMNS),
                attack_name=sys.intern(row["attack_name"]),
                difficulty=int(row["difficulty"]),
                novel_attack=row["novel_attack"] == "1",
            )
            for row in reader
        ]


def write_splits(raw_dir: Path = RAW_DIR, splits_dir: Path = SPLITS_DIR) -> Path:
    """Draw the three proportional splits from Test+ and refresh the manifest."""
    splits = draw_splits(
        load_test(raw_dir), SPLIT_SIZES, SPLIT_SEED, MIN_NOVEL_IN_PAPER
    )
    splits_dir.mkdir(parents=True, exist_ok=True)
    for name, flows in splits.items():
        write_split(flows, splits_dir / f"{name}.csv")
    return write_manifest(raw_dir, splits_dir)


def write_band_split(
    name: str, raw_dir: Path = RAW_DIR, splits_dir: Path = SPLITS_DIR
) -> Path:
    """Draw one diagnostic split disjoint from every other split file present,
    then refresh the manifest."""
    others = [other for other in split_names(splits_dir) if other != name]
    flows = draw_band_split(
        load_test(raw_dir), used_row_ids(splits_dir, others), BANDS[name], SPLIT_SEED
    )
    write_split(flows, splits_dir / f"{name}.csv")
    return write_manifest(raw_dir, splits_dir)


def split_names(splits_dir: Path) -> list[str]:
    """Split files present on disk: the proportional ones first, then the rest."""
    present = {path.stem for path in splits_dir.glob("*.csv")}
    known = [name for name in SPLIT_SIZES if name in present]
    return [*known, *sorted(present.difference(SPLIT_SIZES))]


def _bands_present(splits: Mapping[str, Sequence[Flow]]) -> dict[str, object]:
    return {
        name: {
            "min_difficulty": band.min_difficulty,
            "max_difficulty": band.max_difficulty,
            "balanced_classes": True,
        }
        for name, band in BANDS.items()
        if name in splits
    }


def write_manifest(raw_dir: Path, splits_dir: Path) -> Path:
    """Describe every split file present in `splits_dir` in SOURCE.json."""
    splits = {name: load_split(name, splits_dir) for name in split_names(splits_dir)}
    manifest: dict[str, object] = {
        "dataset": KAGGLE_DATASET,
        "source_files": {
            name: sha256_of(resolve_raw(raw_dir, name)) for name in CHECKSUMS
        },
        "seed": SPLIT_SEED,
        "sizes": {name: len(flows) for name, flows in splits.items()},
        "novel_attack_rows": {
            name: sum(flow.novel_attack for flow in flows)
            for name, flows in splits.items()
        },
        "category_table_version": CATEGORY_TABLE_VERSION,
        "drawn_on": datetime.now(UTC).date().isoformat(),
    }
    manifest["bands"] = _bands_present(splits)
    manifest_path = splits_dir / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest_path


def resolve_raw(raw_dir: Path, name: str) -> Path:
    """Find a mirror file at the root of `raw_dir` or under its subdirectory."""
    for candidate in (raw_dir / name, raw_dir / MIRROR_SUBDIR / name):
        if candidate.exists():
            return candidate
    msg = f"{name} not found under {raw_dir}; run `python -m somids download`"
    raise FileNotFoundError(msg)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksums(raw_dir: Path) -> dict[str, str]:
    """Compare the raw files with the pinned checksums; return the digests."""
    digests: dict[str, str] = {}
    for name, expected in CHECKSUMS.items():
        actual = sha256_of(resolve_raw(raw_dir, name))
        if expected and actual != expected:
            msg = f"{name}: sha256 {actual} differs from the pinned {expected}"
            raise ValueError(msg)
        digests[name] = actual
    return digests


def download(raw_dir: Path = RAW_DIR) -> dict[str, str]:
    """Fetch the Kaggle mirror if the files are missing, then verify checksums.

    Kaggle credentials come from `.env` (`KAGGLE_USERNAME`, `KAGGLE_KEY`).
    """
    load_dotenv(ROOT / ".env")
    raw_dir.mkdir(parents=True, exist_ok=True)
    missing = [
        name
        for name in CHECKSUMS
        if not any((raw_dir / prefix / name).exists() for prefix in ("", MIRROR_SUBDIR))
    ]
    if missing:
        kaggle = shutil.which("kaggle")
        if kaggle is None:
            msg = "the `kaggle` CLI is not installed; run `uv sync`"
            raise FileNotFoundError(msg)
        command = [kaggle, "datasets", "download", "-d", KAGGLE_DATASET]
        command += ["-p", str(raw_dir), "--unzip"]
        # Fixed executable and constant arguments; nothing here is user input.
        subprocess.run(command, check=True)  # noqa: S603
    return verify_checksums(raw_dir)
