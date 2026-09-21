"""Jev detector: request body, answer parsing and the retry policy."""

import json
from collections.abc import Callable
from typing import Any

import pytest
import requests

from jev_ids.detectors import jev
from jev_ids.run import sample_examples
from tests.helpers import (
    CONFIG,
    JEV_PROMPT,
    FakeResponse,
    make_flow,
    make_train,
    no_sleep,
)

# Trimmed from a real gateway response captured on 2026-09-20 (warezmaster row).
BODY: dict[str, Any] = {
    "model": "typesafe-ai/jev",
    "answers": {
        "is_attack": {"type": "noul", "noul": 0.78},
        "category": {
            "type": "choice",
            "choice": "r2l",
            "confidence": 0.8,
            "probabilities": {"r2l": 0.84, "probe": 0.02, "normal": 0.14},
        },
    },
    "usage": {"input_tokens": 1606, "output_tokens": 79},
    "provider_metadata": {"gateway": {"cost": "0", "marketCost": "0.000067452"}},
}
FLOW = make_flow(9, "r2l", value="1")
TRAIN = make_train(["normal", "dos", "probe"])


def posting(*responses: FakeResponse | Exception) -> Callable[..., FakeResponse]:
    """A `requests.post` replacement that answers from the queue, in order."""
    queue = list(responses)

    def _post(*_args: object, **_kwargs: object) -> FakeResponse:
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    return _post


@pytest.fixture
def detector(monkeypatch: pytest.MonkeyPatch) -> jev.JevDetector:
    """A detector with a fake key whose backoff does not wait."""
    monkeypatch.setenv(jev.API_KEY_VAR, "test-key")
    monkeypatch.setattr(jev.time, "sleep", no_sleep)
    return jev.JevDetector(JEV_PROMPT)


def test_detector_reads_the_model_and_the_hash_off_the_template(
    detector: jev.JevDetector,
) -> None:
    assert (detector.name, detector.model) == ("jev", "typesafe-ai/jev")
    assert detector.prompt_hash == "h"


def test_request_body_adds_the_flow_the_examples_and_the_rubric(
    detector: jev.JevDetector,
) -> None:
    examples = sample_examples(TRAIN, 1, 0, CONFIG["categories"])
    body = jev.request_body(detector.template, FLOW, examples)
    state = body["state"]
    assert body["model"] == "typesafe-ai/jev"
    assert state["flows"] == {"under_test": FLOW.attributes_csv}
    assert state["instructions"].startswith("You are given one record")
    assert state["columns"] == "a,b,c"
    assert len(state["examples"]) == 3
    assert state["examples"][0].keys() == {"record", "category"}
    assert set(body["questions"]) == {"is_attack", "category"}
    assert body["questions"]["category"]["criteria"] == state["categories"]
    # The template itself is untouched: every call starts from the file again.
    assert "flows" not in json.loads(detector.template)["state"]
    assert "examples" not in jev.request_body(detector.template, FLOW, [])["state"]


def test_predict_reads_the_gateway_answer(detector: jev.JevDetector, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(requests, "post", posting(FakeResponse(200, BODY)))
    prediction = detector.predict(FLOW, [])
    assert prediction["p_attack"] == 0.78
    assert prediction["category_pred"] == "r2l"
    assert prediction["confidence"] == 0.8
    assert prediction["usage"] == {"input_tokens": 1606, "output_tokens": 79}
    assert prediction["latency_ms"] > 0
    assert prediction["retries"] == 0
    assert prediction["raw"] == BODY
    assert "error" not in prediction


def test_retries_on_429_then_succeeds(detector: jev.JevDetector, monkeypatch: pytest.MonkeyPatch) -> None:
    answers = posting(FakeResponse(429, {"error": "rate"}), FakeResponse(200, BODY))
    monkeypatch.setattr(requests, "post", answers)
    prediction = detector.predict(FLOW, [])
    assert prediction["retries"] == 1
    assert prediction["p_attack"] == 0.78


def test_client_errors_fail_without_retry(detector: jev.JevDetector, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(requests, "post", posting(FakeResponse(400, {"error": "bad"})))
    prediction = detector.predict(FLOW, [])
    assert prediction["error"].startswith("HTTP 400")
    assert prediction["retries"] == 0
    assert "p_attack" not in prediction  # nothing measured, nothing written


def test_network_errors_give_up_after_five_attempts(detector: jev.JevDetector, monkeypatch: pytest.MonkeyPatch) -> None:
    failures = [requests.ConnectionError("down") for _ in range(jev.MAX_ATTEMPTS)]
    monkeypatch.setattr(requests, "post", posting(*failures))
    prediction = detector.predict(FLOW, [])
    assert prediction == {"error": "ConnectionError: down", "retries": 4}


def test_missing_api_key_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(jev.API_KEY_VAR, raising=False)
    with pytest.raises(RuntimeError, match="AI_GATEWAY_API_KEY"):
        jev.JevDetector(JEV_PROMPT).predict(FLOW, [])
