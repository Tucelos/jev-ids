"""Pin the request shape sent to the gateway and the parsing of its response."""

import json
from collections.abc import Callable
from typing import Any

import pytest

import vercel_test

# Trimmed from a real gateway response captured on 2026-09-20.
GATEWAY_BODY: dict[str, Any] = {
    "model": "typesafe-ai/jev",
    "answers": {
        "i0": {
            "type": "choice",
            "choice": "teardrop",
            "confidence": 0.94,
            "probabilities": {"normal": 0.03, "teardrop": 0.97},
        }
    },
    "usage": {"input_tokens": 1754, "output_tokens": 36},
    "provider_metadata": {"gateway": {"cost": "0", "marketCost": "0.000073668"}},
}


class FakeResponse:
    def __init__(self, status_code: int, body: dict[str, Any]) -> None:
        self.status_code = status_code
        self.ok = status_code < 400
        self.text = json.dumps(body)
        self._body = body

    def json(self) -> dict[str, Any]:
        return self._body


def fake_post(status_code: int, body: dict[str, Any]) -> Callable[..., FakeResponse]:
    def _post(*_args: object, **_kwargs: object) -> FakeResponse:
        return FakeResponse(status_code, body)

    return _post


def test_build_payload_mirrors_classifier_dev_shape() -> None:
    payload = vercel_test.build_payload("Rules here.")
    assert payload["model"] == vercel_test.MODEL
    assert payload["state"] == [{"id": "i0", "text": vercel_test.ROW}]
    questions: Any = payload["questions"]
    question = questions["i0"]
    assert question["type"] == "choice"
    assert question["instructions"].endswith(" Rules here.")
    assert question["criteria"] == {"normal": None, "teardrop": None}


def test_main_prints_the_four_numbers_the_paper_needs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AI_GATEWAY_API_KEY", "test-key")
    monkeypatch.setattr(vercel_test.requests, "post", fake_post(200, GATEWAY_BODY))

    vercel_test.main()

    out = capsys.readouterr().out
    assert "choice        : teardrop" in out
    assert "confidence    : 0.94" in out
    assert "input_tokens  : 1754" in out
    assert "cost_usd      : 0" in out
    assert "latency_ms" in out


def test_main_exits_with_the_gateway_error_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AI_GATEWAY_API_KEY", "test-key")
    error = {"error": {"type": "customer_verification_required"}}
    monkeypatch.setattr(vercel_test.requests, "post", fake_post(403, error))

    with pytest.raises(SystemExit, match="HTTP 403.*customer_verification_required"):
        vercel_test.main()
