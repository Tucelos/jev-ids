"""SOMIDS: intrusion detection with Jev, a System One Model, against two baselines.

The package, in reading order:

- `dataset`: the card of a dataset, the shared CSV shape and the Flow.
- `run`: one run of one Detector over one split, cell by cell.
- `detectors/`: `jev` (TypeSafe's Jev through the Vercel AI Gateway), `llm` (DeepSeek and GPT-5.x through an Agno Agent, the latter via
  `chatgpt`) and `random_forest` (scikit-learn).
- `records`: the Prediction row and the three files of a run.
- `metrics`: summary tables and paired comparisons computed from those rows.
- `cli`: the `run`, `metrics` and `compare` subcommands.

Every design decision is recorded in `dev-docs/grilling-01-decisions.md`, cited here as "grilling Q<n>" or "§<n>".
"""

from pathlib import Path

# The repository root: `data/`, `prompts/`, `results/`, `prices.json` and `.env` hang off it.
ROOT = Path(__file__).resolve().parent.parent
