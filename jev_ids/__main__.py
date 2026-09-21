"""`python -m jev_ids`: the same entry as the `jev-ids` console script."""

from jev_ids import cli

if __name__ == "__main__":
    raise SystemExit(cli.main())
