"""The offline Detector: a Random Forest wearing a Context's prompt hash, so the Arena runs without an API key.

In reading order:

- `OfflineDetector`: `predict` delegates to a `RandomForestDetector` and stamps the rendered Context's hash on the row.

WARNING: this Detector exists to exercise the pipeline and produces no valid scientific result. A forest cannot read a playbook, so the
curator's Rules cannot influence a single answer it gives; only the Examples a Context chooses can. Any curve measured against it says
something about the plumbing of the loop and nothing about whether a Context helps. Read a number off it and you will be wrong.

It is still the Detector the loop should be debugged on: it costs nothing, it answers in a millisecond, and it reacts to a new Context
exactly where the Arena needs it to, by changing the `prompt_hash` on every row it writes.
"""

from collections.abc import Sequence
from typing import Any

from jev_ids.dataset import Flow
from jev_ids.detectors.random_forest import N_ESTIMATORS, RandomForestDetector, Vocabulary


class OfflineDetector:
    """Judges Flows with a Random Forest fitted on the cell's Examples, under a Context's prompt hash."""

    name = "offline"

    def __init__(self, prompt: dict[str, Any], vocabulary: Vocabulary, benign: str) -> None:
        """Keep the rendered Context and wrap a forest; fitting waits for `predict`.

        Args:
            prompt: `Context.to_prompt` of the Detector's Context, in the shape `run.load_prompt` returns.
            vocabulary: the symbolic values of the Pool (see `random_forest.vocabulary`).
            benign: the card's benign Category, whose probability gives p_attack.
        """
        self.prompt_hash: str = prompt["sha256"]
        self.model = f"offline-random-forest-{N_ESTIMATORS}"
        # Everything a forest does is already written once, in the Random Forest baseline; this Detector adds the prompt hash and nothing
        # else, so it wraps that one rather than growing a second copy of it.
        self.forest = RandomForestDetector(vocabulary, benign)

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One Flow: what the forest measured, plus the hash of the Context in force.

        The hash travels in the measurement and not only in the run fields, so a Round that writes its own rows still records which version
        of the Context each Flow was judged under.
        """
        return {**self.forest.predict(flow, examples), "prompt_hash": self.prompt_hash}
