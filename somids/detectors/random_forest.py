"""Random Forest baseline: one 5-class forest trained on the Examples, with a
fixed one-hot vocabulary for the three symbolic attributes.

`p_attack = 1 - P(normal)`; the Verdict uses the shared 0.5 threshold. The
forest is fitted once per Examples object (the run loop reuses the same list
across reps and batches) and the training time is repeated in every Outcome.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, cast

import numpy as np
from sklearn.ensemble import (  # pyright: ignore[reportMissingTypeStubs]
    RandomForestClassifier,
)

from somids.dataset import COLUMNS, Category, Example, Flow
from somids.detectors.base import Outcome

SYMBOLIC = ("protocol_type", "service", "flag")
SYMBOLIC_INDEX = tuple(COLUMNS.index(name) for name in SYMBOLIC)
N_ESTIMATORS = 100
RANDOM_STATE = 0


@dataclass(frozen=True, slots=True)
class Vocabulary:
    """The values each symbolic attribute takes in Train+, in a fixed order."""

    values: dict[str, tuple[str, ...]]

    @classmethod
    def from_flows(cls, flows: Sequence[Flow]) -> Vocabulary:
        seen: dict[str, set[str]] = {name: set() for name in SYMBOLIC}
        for flow in flows:
            values = flow.values
            for name, index in zip(SYMBOLIC, SYMBOLIC_INDEX, strict=True):
                seen[name].add(values[index])
        return cls({name: tuple(sorted(seen[name])) for name in SYMBOLIC})

    @property
    def width(self) -> int:
        return len(COLUMNS) - len(SYMBOLIC) + sum(len(v) for v in self.values.values())

    def vector(self, flow: Flow) -> list[float]:
        """Numeric attributes as floats, then the symbolic ones one-hot."""
        values = flow.values
        return _numeric(values) + self._one_hot(values)

    def _one_hot(self, values: tuple[str, ...]) -> list[float]:
        """Unknown values (absent from Train+) become all zeros."""
        encoded: list[float] = []
        for name, index in zip(SYMBOLIC, SYMBOLIC_INDEX, strict=True):
            encoded.extend(
                1.0 if known == values[index] else 0.0 for known in self.values[name]
            )
        return encoded


def _numeric(values: tuple[str, ...]) -> list[float]:
    return [
        float(value)
        for index, value in enumerate(values)
        if index not in SYMBOLIC_INDEX
    ]


@dataclass(slots=True)
class RandomForestDetector:
    """Detector backed by scikit-learn's RandomForestClassifier."""

    vocabulary: Vocabulary
    n_estimators: int = N_ESTIMATORS
    random_state: int = RANDOM_STATE
    fits: int = 0
    _fitted_on: int | None = field(default=None, repr=False)
    _estimator: Any = field(default=None, repr=False)
    _classes: list[str] = field(default_factory=list[str], repr=False)
    _train_time_ms: float = 0.0

    @property
    def name(self) -> str:
        return "rf"

    @property
    def model(self) -> str:
        return f"sklearn-random-forest-{self.n_estimators}"

    def fit(self, examples: Sequence[Example]) -> None:
        if not examples:
            msg = "the Random Forest needs k >= 1: there is nothing to train at k = 0"
            raise ValueError(msg)
        matrix = np.asarray(
            [self.vocabulary.vector(e.flow) for e in examples], dtype=float
        )
        labels = np.asarray([e.category for e in examples])
        estimator: Any = RandomForestClassifier(
            n_estimators=self.n_estimators, random_state=self.random_state
        )
        started = time.perf_counter()
        estimator.fit(matrix, labels)
        self._train_time_ms = (time.perf_counter() - started) * 1000
        self._estimator = estimator
        self._classes = [str(label) for label in estimator.classes_]
        self._fitted_on = id(examples)
        self.fits += 1

    def predict(
        self, flows: Sequence[Flow], examples: Sequence[Example]
    ) -> list[Outcome]:
        if self._fitted_on != id(examples):
            self.fit(examples)
        matrix = np.asarray(
            [self.vocabulary.vector(flow) for flow in flows], dtype=float
        )
        started = time.perf_counter()
        rows: list[list[float]] = self._estimator.predict_proba(matrix).tolist()
        latency_ms = (time.perf_counter() - started) * 1000
        request_id = str(uuid.uuid4())
        return [
            self._outcome(
                flow, dict(zip(self._classes, row, strict=True)), latency_ms, request_id
            )
            for flow, row in zip(flows, rows, strict=True)
        ]

    def _outcome(
        self,
        flow: Flow,
        probabilities: dict[str, float],
        latency_ms: float,
        request_id: str,
    ) -> Outcome:
        category = cast(Category, max(probabilities, key=lambda c: probabilities[c]))
        return Outcome(
            flow=flow,
            model=self.model,
            p_attack=1.0 - probabilities.get("normal", 0.0),
            category_pred=category,
            confidence=None,
            probabilities=probabilities,
            input_tokens=None,
            output_tokens=None,
            cache_tokens=None,
            reasoning_tokens=None,
            cost_usd=None,
            billed_cost_usd=None,
            latency_e2e_ms=latency_ms,
            latency_provider_ms=None,
            time_to_first_token_ms=None,
            train_time_ms=self._train_time_ms,
            retries=0,
            error=None,
            request_id=request_id,
        )
