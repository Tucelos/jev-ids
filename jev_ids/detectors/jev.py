"""Jev, TypeSafe's System One Model, through TypeSafe's own API.

In reading order:

- `JevDetector`: holds the request template of `prompts/<dataset>/jev.json` and the API key; `predict` judges one Flow per request.
- `request_body`: the template with the Flow and the Examples in its `state`.
- `post` and `attempt`: one request, retried when TypeSafe is rate-limited or overloaded.
- `measurements`: what one successful answer measured.

The template is the whole conversation with Jev: a `state` (the instructions, the column header, the Category descriptions) and two
questions that point at state paths in backticks. `is_attack` is a `noul` whose answer is a probability and becomes p_attack;
`category` is a `choice` over the Categories whose answer is the Category with a confidence. Python adds only what changes per call: the
Flow under test at `flows.under_test` and the labeled `examples`. One request judges one Flow (B = 1).
"""

import json
import os
import time
from collections.abc import Sequence
from typing import Any

import requests

from jev_ids.dataset import Flow

API_URL = "https://api.typesafe.ai/v1/systemone"
API_KEY_VAR = "TYPESAFE_API_KEY"
# Retry policy: five attempts with exponential backoff on rate limits (429), overload (529), server errors and network failures; any other
# 4xx fails at once. A failure ends as a row with `error`, never as an exception, so the run continues. TypeSafe's API reference asks for
# exactly this backoff on 429 and 529 (docs.typesafe.ai/api, read on 2026-09-21). The runs up to 2026-09-21 went through the Vercel AI
# Gateway instead, which rate-limited 1,350 of the 1,800 pilot rows at least once.
MAX_ATTEMPTS = 5
BACKOFF_SECONDS = 1.0
TIMEOUT_SECONDS = 60
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504, 529})


class JevDetector:
    """Judges one Flow per request to TypeSafe, retrying when the API is rate-limited or overloaded."""

    name = "jev"

    def __init__(self, prompt: dict[str, Any]) -> None:
        """Keep the template and the key; nothing is sent until `predict`.

        Args:
            prompt: `run.load_prompt` of `prompts/<dataset>/jev.json`, the request body without the Flow and the Examples.
        """
        self.template: str = prompt["text"]
        self.prompt_hash: str = prompt["sha256"]
        # The template names a versioned model id (`jev-1.13.0`), never the moving alias `jev-latest`, so every run pins the version it
        # was made with; the answer also reports the version that produced it, and `measurements` writes that one into the row.
        self.model: str = json.loads(self.template)["model"]
        self.api_key = os.environ.get(API_KEY_VAR, "")

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One request for one Flow: what it measured, or `error` and `retries`."""
        if not self.api_key:
            raise RuntimeError(f"{API_KEY_VAR} is not set")
        return post(request_body(self.template, flow, examples), self.api_key)


def request_body(template: str, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
    """The template with the Flow at `flows.under_test` and the Examples, if any.

    Examples are labeled by Category only, because attack names never reach a model (CONTEXT.md). The Category question grades against the
    descriptions the state already holds, so its `criteria` rubric is copied from `state.categories` here and the file states them once.
    """
    body: dict[str, Any] = json.loads(template)
    body["state"]["flows"] = {"under_test": flow.attributes_csv}
    if examples:
        body["state"]["examples"] = [{"record": example.attributes_csv, "category": example.category} for example in examples]
    body["questions"]["category"]["criteria"] = body["state"]["categories"]
    return body


def attempt(body: dict[str, Any], api_key: str) -> dict[str, Any]:
    """One POST: the measurements on success, else `error` and `retryable`."""
    headers = {"Authorization": f"Bearer {api_key}"}
    started = time.perf_counter()
    try:
        response = requests.post(API_URL, json=body, headers=headers, timeout=TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "retryable": True}
    if not response.ok:
        return {
            "error": f"HTTP {response.status_code}: {response.text[:200]}",
            "retryable": response.status_code in RETRYABLE_STATUS,
        }
    return measurements(response.json(), (time.perf_counter() - started) * 1000)


def post(body: dict[str, Any], api_key: str) -> dict[str, Any]:
    """Up to MAX_ATTEMPTS attempts with exponential backoff.

    Only a retryable failure earns another attempt. `latency_ms` measures the successful attempt alone and `retries` counts the failed ones
    before it.
    """
    result = attempt(body, api_key)
    retries = 0
    while result.get("retryable") and retries < MAX_ATTEMPTS - 1:
        time.sleep(BACKOFF_SECONDS * 2**retries)
        result = attempt(body, api_key)
        retries += 1
    result.pop("retryable", None)
    return {**result, "retries": retries}


def measurements(body: dict[str, Any], latency_ms: float) -> dict[str, Any]:
    """What one answer measured, plus the whole body as `raw` for responses.jsonl.

    p_attack is the `noul` answer; the Category and the recorded confidence come from the `choice` answer. `usage` is TypeSafe's own token
    report (`input_tokens`, `output_tokens`); the metrics price it offline against prices.json. `model` is the version that answered, kept
    in the row so the pin survives even if a template ever names an alias.
    """
    answers = body["answers"]
    return {
        "model": body.get("model"),
        "p_attack": answers["is_attack"].get("noul"),
        "category_pred": answers["category"].get("choice"),
        "confidence": answers["category"].get("confidence"),
        "latency_ms": latency_ms,
        "usage": body.get("usage", {}),
        "raw": body,
    }
