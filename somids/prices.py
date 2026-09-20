"""List prices from `prices.json`, used to turn measured tokens into USD."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from somids.dataset import ROOT

PRICES_PATH = ROOT / "prices.json"
PER_TOKENS = 1_000_000


@dataclass(frozen=True, slots=True)
class Price:
    """USD per 1M tokens for one model; `cached_input` is None when not offered."""

    input: float
    cached_input: float | None
    output: float

    def cost(self, input_tokens: int, cached_tokens: int, output_tokens: int) -> float:
        """USD for one call; cached tokens are a subset of `input_tokens`."""
        cached_rate = self.input if self.cached_input is None else self.cached_input
        uncached = max(input_tokens - cached_tokens, 0)
        total = uncached * self.input + cached_tokens * cached_rate
        total += output_tokens * self.output
        return total / PER_TOKENS


@dataclass(frozen=True, slots=True)
class PriceList:
    date: str
    models: dict[str, Price]

    def for_model(self, model: str) -> Price:
        try:
            return self.models[model]
        except KeyError as exc:
            msg = f"no list price for {model!r} in {PRICES_PATH.name}"
            raise KeyError(msg) from exc


def load_prices(path: Path = PRICES_PATH) -> PriceList:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    models = {
        name: Price(
            input=float(entry["input"]),
            cached_input=None
            if entry["cached_input"] is None
            else float(entry["cached_input"]),
            output=float(entry["output"]),
        )
        for name, entry in data["models"].items()
    }
    return PriceList(date=str(data["date"]), models=models)
