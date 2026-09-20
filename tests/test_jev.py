"""Jev detector: payload shape, response parsing and the retry policy."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
import requests

from somids import dataset
from somids.detectors import jev
from somids.prompt import load_prompt

# Trimmed from a real gateway response captured on 2026-09-20 (warezmaster row).
BODY: dict[str, Any] = {
    "model": "typesafe-ai/jev",
    "answers": {
        "is_attack_r0": {"type": "noul", "noul": 0.78},
        "category_r0": {
            "type": "choice",
            "choice": "r2l",
            "confidence": 0.8,
            "probabilities": {
                "r2l": 0.84,
                "probe": 0.02,
                "normal": 0.14,
                "u2r": 0,
                "dos": 0,
            },
        },
    },
    "usage": {"input_tokens": 1606, "output_tokens": 79},
    "provider_metadata": {
        "gateway": {
            "routing": {
                "modelAttempts": [
                    {
                        "success": True,
                        "providerAttempts": [
                            {
                                "success": True,
                                "startTime": 1789940324906,
                                "endTime": 1789940325123,
                            }
                        ],
                    }
                ]
            },
            "cost": "0",
            "marketCost": "0.000067452",
            "generationId": "gen_01",
        }
    },
}
FLOW = dataset.Flow(
    row_id=9, text=",".join(["1"] * 41), attack_name="warezmaster", difficulty=12
)
TRAIN = [
    dataset.Flow(row_id=i, text=",".join([str(i)] * 41), attack_name=name, difficulty=1)
    for i, name in enumerate(["normal", "neptune", "satan", "ftp_write", "perl"])
]


class FakeResponse:
    def __init__(self, status_code: int, body: dict[str, Any]) -> None:
        self.status_code = status_code
        self.ok = status_code < 400
        self.text = json.dumps(body)
        self._body = body

    def json(self) -> dict[str, Any]:
        return self._body


def posting(*responses: FakeResponse | Exception) -> Callable[..., FakeResponse]:
    queue = list(responses)

    def _post(*_args: object, **_kwargs: object) -> FakeResponse:
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    return _post


def no_sleep(_seconds: float) -> None:
    return None


@pytest.fixture
def detector() -> jev.JevDetector:
    return jev.JevDetector(prompt=load_prompt("v1"), api_key="test-key", sleep=no_sleep)


def test_payload_has_shared_state_and_two_questions_per_flow(
    detector: jev.JevDetector,
) -> None:
    examples = dataset.sample_examples(TRAIN, 1, seed=0)
    payload = detector.build_payload([FLOW, TRAIN[0]], examples)
    state = payload["state"]
    assert payload["model"] == "typesafe-ai/jev"
    assert state["records"] == {"r0": FLOW.text, "r1": TRAIN[0].text}
    assert len(state["examples"]) == 5
    assert state["examples"][0].keys() == {"record", "category"}
    assert set(payload["questions"]) == {
        "is_attack_r0",
        "category_r0",
        "is_attack_r1",
        "category_r1",
    }
    assert payload["questions"]["is_attack_r1"]["instructions"].endswith(
        "as reference."
    )
    assert payload["questions"]["category_r0"]["criteria"].keys() == {
        "normal",
        "dos",
        "probe",
        "r2l",
        "u2r",
    }


def test_zero_shot_payload_omits_examples(detector: jev.JevDetector) -> None:
    payload = detector.build_payload([FLOW], [])
    assert "examples" not in payload["state"]
    assert payload["questions"]["is_attack_r0"]["instructions"].endswith("`columns`.")


def test_kv_format_is_applied_to_records_and_examples() -> None:
    kv = jev.JevDetector(prompt=load_prompt("v1"), fmt="kv", api_key="k")
    payload = kv.build_payload([FLOW], dataset.sample_examples(TRAIN, 1, seed=0))
    assert payload["state"]["records"]["r0"].startswith("duration=1 protocol_type=1")
    assert payload["state"]["examples"][0]["record"].count("=") == 41


def test_predict_parses_the_gateway_answer(
    detector: jev.JevDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(requests, "post", posting(FakeResponse(200, BODY)))
    [outcome] = detector.predict([FLOW], [])
    assert outcome.p_attack == 0.78
    assert outcome.y_pred == 1
    assert outcome.category_pred == "r2l"
    assert outcome.confidence == 0.8
    assert outcome.input_tokens == 1606
    assert outcome.output_tokens == 79
    assert outcome.cost_usd == pytest.approx(0.000067452)
    assert outcome.billed_cost_usd == 0.0
    assert outcome.latency_provider_ms == 217.0
    assert outcome.latency_e2e_ms is not None
    assert outcome.retries == 0
    assert outcome.error is None
    assert outcome.raw == BODY


def test_batch_splits_tokens_and_cost_evenly(
    detector: jev.JevDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = json.loads(json.dumps(BODY))
    body["answers"]["is_attack_r1"] = {"type": "noul", "noul": 0.1}
    body["answers"]["category_r1"] = {
        "type": "choice",
        "choice": "normal",
        "confidence": 0.9,
    }
    monkeypatch.setattr(requests, "post", posting(FakeResponse(200, body)))
    first, second = detector.predict([FLOW, TRAIN[0]], [])
    assert (first.input_tokens, second.input_tokens) == (803, 803)
    assert first.cost_usd == pytest.approx(0.000067452 / 2)
    assert second.p_attack == 0.1
    assert second.y_pred == 0
    assert first.request_id == second.request_id


def test_retries_on_429_then_succeeds(
    detector: jev.JevDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        requests,
        "post",
        posting(FakeResponse(429, {"error": "rate"}), FakeResponse(200, BODY)),
    )
    [outcome] = detector.predict([FLOW], [])
    assert outcome.retries == 1
    assert outcome.error is None


def test_client_errors_fail_without_retry(
    detector: jev.JevDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(requests, "post", posting(FakeResponse(400, {"error": "bad"})))
    [outcome] = detector.predict([FLOW], [])
    assert outcome.p_attack is None
    assert outcome.y_pred is None
    assert outcome.retries == 0
    assert outcome.error is not None
    assert outcome.error.startswith("HTTP 400")


def test_network_errors_give_up_after_five_attempts(
    detector: jev.JevDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    failures = [requests.ConnectionError("down") for _ in range(jev.MAX_ATTEMPTS)]
    monkeypatch.setattr(requests, "post", posting(*failures))
    [outcome] = detector.predict([FLOW], [])
    assert outcome.retries == jev.MAX_ATTEMPTS - 1
    assert outcome.error == "ConnectionError: down"


def test_missing_api_key_is_an_error() -> None:
    with pytest.raises(RuntimeError, match="AI_GATEWAY_API_KEY"):
        jev.JevDetector(prompt=load_prompt("v1"), api_key="").predict([FLOW], [])


def test_provider_latency_is_none_without_a_successful_attempt() -> None:
    assert jev.provider_latency_ms({}) is None
    body = {
        "provider_metadata": {
            "gateway": {
                "routing": {
                    "modelAttempts": [{"providerAttempts": [{"success": False}]}]
                }
            }
        }
    }
    assert jev.provider_latency_ms(body) is None
