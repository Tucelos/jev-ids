"""Detector protocol and the Outcome every detector returns per Flow."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from somids.dataset import Category, Example, Flow

THRESHOLD = 0.5


@dataclass(frozen=True, slots=True)
class Outcome:
    """What one detector measured for one Flow; `run.py` adds the run context."""

    flow: Flow
    model: str
    p_attack: float | None
    category_pred: Category | None
    confidence: float | None
    probabilities: dict[str, float] | None
    input_tokens: int | None
    output_tokens: int | None
    cache_tokens: int | None
    reasoning_tokens: int | None
    cost_usd: float | None
    billed_cost_usd: float | None
    latency_e2e_ms: float | None
    latency_provider_ms: float | None
    time_to_first_token_ms: float | None
    train_time_ms: float | None
    retries: int
    error: str | None
    request_id: str
    raw: dict[str, Any] = field(default_factory=dict[str, Any])

    @property
    def y_pred(self) -> int | None:
        """Verdict at the shared 0.5 threshold; None when there is no p_attack."""
        if self.p_attack is None:
            return None
        return int(self.p_attack >= THRESHOLD)


class Detector(Protocol):
    """Anything that turns Flows plus Examples into Outcomes."""

    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str: ...

    def predict(
        self, flows: Sequence[Flow], examples: Sequence[Example]
    ) -> list[Outcome]: ...
