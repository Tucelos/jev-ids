"""CLI entry point: `python -m somids <download|split>`; `run` and `metrics`
land with their modules.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from somids import dataset


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="somids")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser(
        "download", help="fetch NSL-KDD from Kaggle and verify checksums"
    )
    subcommands.add_parser(
        "split", help="draw the internal, paper and smoke splits from KDDTest+"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "download":
        for name, digest in dataset.download().items():
            print(f"{name}: sha256 {digest}")
    elif args.command == "split":
        manifest = dataset.write_splits()
        print(manifest.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
