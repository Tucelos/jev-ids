"""Jev, TypeSafe's System One Model, through the official Python SDK or the Vercel AI Gateway.

In reading order:

- `JevDetector`: holds the request template of `prompts/<dataset>/jev.json` and the chosen gateway; `predict` judges one Flow per request.
- `request_body`: the template with the Flow and the Examples in its `state`.
- `attempt` and `attempt_gateway`: one request to TypeSafe through the SDK, or one to the Vercel AI Gateway with `requests`.
- `post`: either of those retried, when Jev is rate-limited or overloaded.
- `measurements`: what one successful answer measured.

The template is the whole conversation with Jev: a `state` (the instructions, the column header, the Category descriptions) and two
questions that point at state paths in backticks. `is_attack` is a `noul` whose answer is a probability and becomes p_attack;
`category` is a `choice` over the Categories whose answer is the Category with a confidence. Python adds only what changes per call: the
Flow under test at `flows.under_test` and the labeled `examples`. One request judges one Flow (B = 1). The SDK sends the template's
`state`, `model` and `questions` exactly as the file has them, so the file still describes the request byte for byte.

`JEV_GATEWAY` picks the road: `typesafe` (the default) goes direct through the SDK, `vercel` goes through the AI Gateway the runs up to
2026-09-21 went through, which a reader with gateway credits and no TypeSafe account can still reproduce them on. The two share one retry
policy and one `measurements`, so a row means the same thing whichever road made it; only the transport and the model id differ.
"""

import json
import os
import time
from collections.abc import Callable, Sequence
from functools import partial
from typing import Any

import requests
from typesafe_sdk import RetryPolicy, SystemOneResponse, TypeSafeAPIConnectionError, TypeSafeAPIError, TypeSafeClient

from jev_ids.dataset import Flow

API_KEY_VAR = "TYPESAFE_API_KEY"  # read by the SDK itself
GATEWAY_VAR = "JEV_GATEWAY"
GATEWAYS = ("typesafe", "vercel")  # the two roads to Jev; the first is the default
GATEWAY_URL = "https://ai-gateway.vercel.sh/typesafe/v1/systemone"
GATEWAY_KEY_VAR = "AI_GATEWAY_API_KEY"
# The gateway masks the version (`jev-1.13.0` -> `typesafe-ai/jev`); prices.json prices both ids, and the run date in config.json is the
# only version pin the gateway road offers.
GATEWAY_MODEL = "typesafe-ai/jev"
# Retry policy: five attempts with exponential backoff on rate limits (429), overload (529), server errors and network failures; any other
# 4xx fails at once. A failure ends as a row with `error`, never as an exception, so the run continues. The SDK's own retries stay off,
# because a retry it made silently would hide inside `latency_ms` and escape `retries`: the run measures the successful attempt alone and
# counts the failed ones. The runs up to 2026-09-21 went through the Vercel AI Gateway, which rate-limited 1,350 of the 1,800 pilot rows at
# least once.
MAX_ATTEMPTS = 5
BACKOFF_SECONDS = 1.0
TIMEOUT_SECONDS = 60
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504, 529})
NO_RETRY = RetryPolicy(max_retries=0, timeout=None)


class JevDetector:
    """Judges one Flow per request to Jev, retrying when the API is rate-limited or overloaded."""

    name = "jev"

    def __init__(self, prompt: dict[str, Any]) -> None:
        """Keep the template and read the gateway; neither road needs its key until the first call.

        Args:
            prompt: `run.load_prompt` of `prompts/<dataset>/jev.json`, the request body without the Flow and the Examples.

        Raises:
            ValueError: `JEV_GATEWAY` names a road that does not exist; a typo there would silently run the other one.
        """
        self.template: str = prompt["text"]
        self.prompt_hash: str = prompt["sha256"]
        self.gateway = os.environ.get(GATEWAY_VAR, GATEWAYS[0])
        if self.gateway not in GATEWAYS:
            raise ValueError(f"{GATEWAY_VAR}={self.gateway!r}: one of {', '.join(GATEWAYS)}")
        # Direct, the template names a versioned model id (`jev-1.13.0`), never the moving alias `jev-latest`, so every run pins the
        # version it was made with; the answer also reports the version that produced it, and `measurements` writes that one into the row.
        # Through the gateway there is no version to pin, only the masked id, which is what the row is then priced by.
        self.model: str = GATEWAY_MODEL if self.gateway == "vercel" else json.loads(self.template)["model"]
        self.client: TypeSafeClient | None = None

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One request for one Flow: what it measured, or `error` and `retries`."""
        body = request_body(self.template, flow, examples)
        if self.gateway == "vercel":
            api_key = os.environ.get(GATEWAY_KEY_VAR, "")
            if not api_key:
                raise RuntimeError(f"{GATEWAY_KEY_VAR} is not set")
            return post(partial(attempt_gateway, body, api_key))
        if self.client is None:
            # The SDK reads TYPESAFE_API_KEY on its own and refuses to start without it.
            self.client = TypeSafeClient(retry=NO_RETRY, timeout=TIMEOUT_SECONDS)
        return post(partial(attempt, self.client, body))


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


def attempt(client: TypeSafeClient, body: dict[str, Any]) -> dict[str, Any]:
    """One request: the measurements on success, else `error` and `retryable`."""
    started = time.perf_counter()
    try:
        response: SystemOneResponse = client.system_one(  # pyright: ignore[reportUnknownMemberType]  the SDK's return type has an unsolved TypeVar
            body["state"], body["questions"], model=body["model"]
        )
    except TypeSafeAPIConnectionError as exc:  # network failures and timeouts, which the SDK raises as one family
        return {"error": f"{type(exc).__name__}: {exc}", "retryable": True}
    except TypeSafeAPIError as exc:  # an HTTP status the API answered with
        return {"error": f"HTTP {exc.status}: {str(exc)[:200]}", "retryable": exc.status in RETRYABLE_STATUS}
    return measurements(response.raw_http_response.json(), (time.perf_counter() - started) * 1000)


def attempt_gateway(body: dict[str, Any], api_key: str) -> dict[str, Any]:
    """One POST to the Vercel AI Gateway: the measurements on success, else `error` and `retryable`.

    The gateway knows Jev under its own id, so the body's `model` is swapped here and nowhere else: `request_body` keeps naming the
    template's version pin, and the two roads disagree about the id in one line instead of in two copies of the template.
    """
    started = time.perf_counter()
    try:
        response = requests.post(
            GATEWAY_URL, json={**body, "model": GATEWAY_MODEL}, headers={"Authorization": f"Bearer {api_key}"}, timeout=TIMEOUT_SECONDS
        )
    except requests.RequestException as exc:  # network failures and timeouts, which `requests` raises as one family
        return {"error": f"{type(exc).__name__}: {exc}", "retryable": True}
    if not response.ok:
        return {"error": f"HTTP {response.status_code}: {response.text[:200]}", "retryable": response.status_code in RETRYABLE_STATUS}
    return measurements(response.json(), (time.perf_counter() - started) * 1000)


def post(send: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Up to MAX_ATTEMPTS calls of `send` with exponential backoff.

    Only a retryable failure earns another attempt. `latency_ms` measures the successful attempt alone and `retries` counts the failed ones
    before it. Both roads are retried by this one loop, so a rate limit costs the same wherever it came from.
    """
    result = send()
    retries = 0
    while result.get("retryable") and retries < MAX_ATTEMPTS - 1:
        time.sleep(BACKOFF_SECONDS * 2**retries)
        result = send()
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
