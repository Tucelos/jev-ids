"""The Random Forest baseline.

In reading order:

- `vocabulary`: the values every symbolic feature takes in the pool, so the one-hot encoding is fixed for the whole run.
- `feature_vector`: one Flow as numbers, numeric features first, then one column per known symbolic value.
- `RandomForestDetector`: one forest of 100 trees with a fixed seed per cell, fitted on the Examples, one class per Category; `predict`
  judges one Flow.

`p_attack = 1 - P(benign)`, the Verdict is taken at the shared threshold like every Detector, and the training time is repeated in every row
of the cell.
"""

import time
from collections.abc import Sequence
from typing import Any

import numpy as np
from sklearn.ensemble import (  # pyright: ignore[reportMissingTypeStubs]
    RandomForestClassifier,
)

from somids.dataset import Config, Flow

N_ESTIMATORS = 100
RANDOM_STATE = 0

# Feature index -> the sorted values it takes in the pool, one entry per symbolic feature, in card order.
Vocabulary = dict[int, tuple[str, ...]]


def vocabulary(flows: Sequence[Flow], config: Config) -> Vocabulary:
    """The sorted values of each symbolic feature of the card, by feature index.

    Taken from the whole pool and not from the Examples of a cell, so that every cell of a run encodes a Flow the same way whatever k was
    drawn.
    """
    indexes: list[int] = [config["features"].index(name) for name in config["symbolic"]]
    seen: dict[int, set[str]] = {index: set() for index in indexes}
    for flow in flows:
        values = flow.attribute_values
        for index in indexes:
            seen[index].add(values[index])
    return {index: tuple(sorted(seen[index])) for index in indexes}


def feature_vector(flow: Flow, vocabulary: Vocabulary) -> list[float]:
    """The numeric features as floats, in order, then the symbolic ones one-hot.

    A symbolic value absent from the pool becomes all zeros, the equivalent of scikit-learn's `handle_unknown="ignore"`, so a split Flow
    never breaks the forest.
    """
    values = flow.attribute_values
    numeric = [float(value) for index, value in enumerate(values) if index not in vocabulary]
    one_hot: list[float] = []
    for index, known_values in vocabulary.items():
        one_hot.extend(float(known == values[index]) for known in known_values)
    return numeric + one_hot


class RandomForestDetector:
    """Judges Flows with a RandomForestClassifier fitted on the cell's Examples."""

    name = "rf"
    prompt_hash = None  # the forest reads no prompt

    def __init__(
        self,
        vocabulary: Vocabulary,
        benign: str,
        n_estimators: int = N_ESTIMATORS,
        random_state: int = RANDOM_STATE,
    ) -> None:
        """Keep the encoding and the forest settings; fitting waits for `predict`.

        Args:
            vocabulary: the symbolic values of the pool (see `vocabulary`).
            benign: the card's benign category, whose probability gives p_attack.
            n_estimators: trees in the forest.
            random_state: seed of the forest, fixed so a cell is reproducible.
        """
        self.vocabulary = vocabulary
        self.benign = benign
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = f"sklearn-random-forest-{n_estimators}"
        self.fits = 0
        # The run loop hands the same Examples list to every rep of a cell, so the forest is fitted once per list (by identity) and
        # the training time is repeated in every row of that cell.
        self._fitted_on: int | None = None
        self._forest: Any = None
        self._train_time_ms = 0.0

    def fit(self, examples: Sequence[Flow]) -> None:
        """Fit a fresh forest on the Examples, labeled by Category, and time it."""
        if not examples:
            raise ValueError("the Random Forest needs k >= 1: nothing to train at k = 0")
        matrix = np.asarray(
            [feature_vector(example, self.vocabulary) for example in examples],
            dtype=float,
        )
        labels = np.asarray([example.category for example in examples])
        self._forest = RandomForestClassifier(n_estimators=self.n_estimators, random_state=self.random_state)
        started = time.perf_counter()
        self._forest.fit(matrix, labels)
        self._train_time_ms = (time.perf_counter() - started) * 1000
        self._fitted_on = id(examples)
        self.fits += 1

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One Flow: p_attack = 1 - P(benign), the most probable Category, timings.

        Latency is the wall clock around `predict_proba` alone.
        """
        if self._fitted_on != id(examples):
            self.fit(examples)
        matrix = np.asarray([feature_vector(flow, self.vocabulary)], dtype=float)
        started = time.perf_counter()
        row: list[float] = self._forest.predict_proba(matrix)[0].tolist()
        latency_ms = (time.perf_counter() - started) * 1000
        classes: list[str] = [str(label) for label in self._forest.classes_]
        probabilities = dict(zip(classes, row, strict=True))
        return {
            "p_attack": 1.0 - probabilities.get(self.benign, 0.0),
            "category_pred": max(probabilities, key=lambda name: probabilities[name]),
            "latency_ms": latency_ms,
            "train_time_ms": self._train_time_ms,
        }
