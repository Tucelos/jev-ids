"""List prices and the token-to-USD arithmetic."""

from __future__ import annotations

import pytest

from somids import prices


def test_prices_json_loads_the_four_models() -> None:
    price_list = prices.load_prices()
    assert price_list.date == "2026-09-20"
    assert set(price_list.models) >= {
        "typesafe-ai/jev",
        "deepseek-flash",
        "gpt-5.6-luna",
    }
    assert price_list.for_model("typesafe-ai/jev").cached_input is None
    with pytest.raises(KeyError, match="no list price"):
        price_list.for_model("unknown-model")


def test_cost_splits_cached_and_uncached_input() -> None:
    price = prices.Price(input=0.30, cached_input=0.006, output=1.20)
    usd = price.cost(
        input_tokens=1_000_000, cached_tokens=900_000, output_tokens=10_000
    )
    assert usd == pytest.approx(0.1 * 0.30 + 0.9 * 0.006 + 0.01 * 1.20)


def test_cost_without_cache_discount_charges_the_input_rate() -> None:
    price = prices.Price(input=0.042, cached_input=None, output=0.0)
    assert price.cost(1_754, 1_000, 36) == pytest.approx(1_754 * 0.042 / 1_000_000)
