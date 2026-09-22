"""Jev IDS: intrusion detection with Jev, a System One Model, against three baselines.

The package, in reading order:

- `dataset`: the card of a dataset, the shared CSV shape and the Flow.
- `run`: one run of one Detector over one split, cell by cell.
- `detectors/`: `jev` (TypeSafe's Jev through its SDK), `llm` (DeepSeek, GPT-5.x and Gemini through an Agno Agent, GPT-5.x via
  `chatgpt`, Gemini via Vertex AI), `random_forest` and `isolation_forest` (both scikit-learn).
- `records`: the Prediction row and the three files of a run.
- `metrics`: summary tables and paired comparisons computed from those rows.
- `cli`: the `run`, `metrics` and `compare` subcommands.
"""

from pathlib import Path

# The repository root: `data/`, `prompts/`, `results/`, `prices.json` and `.env` hang off it.
ROOT = Path(__file__).resolve().parent.parent
