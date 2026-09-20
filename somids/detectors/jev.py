"""Jev through the Vercel AI Gateway: one shared state per request, and for
every Flow two questions, `is_attack_<id>` (noul) and `category_<id>` (choice).
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

import requests

from somids.dataset import Category, Example, Flow, RowFormat, format_flow
from somids.detectors.base import Outcome
from somids.prompt import Prompt

GATEWAY_URL = "https://ai-gateway.vercel.sh/typesafe/v1/systemone"
MODEL = "typesafe-ai/jev"
API_KEY_VAR = "AI_GATEWAY_API_KEY"
MAX_ATTEMPTS = 5
BACKOFF_SECONDS = 1.0
TIMEOUT_SECONDS = 60
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

# Question templates; `{rid}` is the record id inside `state.records`. They are
# copied into config.json so a run can be traced to the exact wording.
IS_ATTACK_TEMPLATE = (
    "Is the connection `records.{rid}` an intrusion attempt rather than normal "
    "traffic? Judge it by `instructions` and `columns`{examples_clause}."
)
CATEGORY_TEMPLATE = (
    "Which category in `categories` does the connection `records.{rid}` belong to?"
)
EXAMPLES_CLAUSE = ", using the labeled `examples` as reference"


@dataclass(frozen=True, slots=True)
class HttpResult:
    """Outcome of `post_with_retries`: a body, or an error after the attempts."""

    body: dict[str, Any] | None
    latency_ms: float | None
    retries: int
    error: str | None


def _attempt(payload: dict[str, Any], api_key: str) -> tuple[HttpResult, bool]:
    """One POST; the flag says whether a failure is worth retrying."""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    started = time.perf_counter()
    try:
        response = requests.post(
            GATEWAY_URL, headers=headers, json=payload, timeout=TIMEOUT_SECONDS
        )
    except requests.RequestException as exc:
        return HttpResult(None, None, 0, f"{type(exc).__name__}: {exc}"), True
    latency_ms = (time.perf_counter() - started) * 1000
    if response.ok:
        body: dict[str, Any] = response.json()
        return HttpResult(body, latency_ms, 0, None), False
    error = f"HTTP {response.status_code}: {response.text[:200]}"
    return HttpResult(None, None, 0, error), response.status_code in RETRYABLE_STATUS


def post_with_retries(
    payload: dict[str, Any],
    api_key: str,
    sleep: Callable[[float], None] = time.sleep,
) -> HttpResult:
    """Up to MAX_ATTEMPTS on 429, 5xx and network errors; other 4xx fail at once."""
    result = HttpResult(None, None, 0, "no attempt made")
    for attempt in range(MAX_ATTEMPTS):
        result, retryable = _attempt(payload, api_key)
        result = HttpResult(result.body, result.latency_ms, attempt, result.error)
        if result.body is not None or not retryable:
            return result
        if attempt < MAX_ATTEMPTS - 1:
            sleep(BACKOFF_SECONDS * 2**attempt)
    return result


def provider_latency_ms(body: dict[str, Any]) -> float | None:
    """Duration of the successful provider attempt, from the gateway timestamps."""
    routing: dict[str, Any] = (
        body.get("provider_metadata", {}).get("gateway", {}).get("routing", {})
    )
    model_attempts: list[dict[str, Any]] = routing.get("modelAttempts", [])
    for model_attempt in model_attempts:
        provider_attempts: list[dict[str, Any]] = model_attempt.get(
            "providerAttempts", []
        )
        for provider_attempt in provider_attempts:
            if provider_attempt.get("success") and "endTime" in provider_attempt:
                return float(
                    provider_attempt["endTime"] - provider_attempt["startTime"]
                )
    return None


def _money(gateway: dict[str, Any], key: str) -> float | None:
    value = gateway.get(key)
    return None if value is None else float(value)


@dataclass(slots=True)
class JevDetector:
    """Detector backed by Jev; B = len(flows) records share one request."""

    prompt: Prompt
    fmt: RowFormat = "csv"
    api_key: str = field(default_factory=lambda: os.environ.get(API_KEY_VAR, ""))
    sleep: Callable[[float], None] = time.sleep

    @property
    def name(self) -> str:
        return "jev"

    @property
    def model(self) -> str:
        return MODEL

    def build_payload(
        self, flows: Sequence[Flow], examples: Sequence[Example]
    ) -> dict[str, Any]:
        records = {f"r{i}": format_flow(flow, self.fmt) for i, flow in enumerate(flows)}
        state: dict[str, Any] = {
            "instructions": self.prompt.task,
            "columns": self.prompt.columns,
            "categories": dict(self.prompt.categories),
            "records": records,
        }
        if examples:
            state["examples"] = [
                {
                    "record": format_flow(example.flow, self.fmt),
                    "category": example.category,
                }
                for example in examples
            ]
        clause = EXAMPLES_CLAUSE if examples else ""
        questions: dict[str, Any] = {}
        for rid in records:
            questions[f"is_attack_{rid}"] = {
                "type": "noul",
                "instructions": IS_ATTACK_TEMPLATE.format(
                    rid=rid, examples_clause=clause
                ),
            }
            questions[f"category_{rid}"] = {
                "type": "choice",
                "instructions": CATEGORY_TEMPLATE.format(rid=rid),
                "criteria": dict(self.prompt.categories),
            }
        return {"model": MODEL, "state": state, "questions": questions}

    def predict(
        self, flows: Sequence[Flow], examples: Sequence[Example]
    ) -> list[Outcome]:
        if not self.api_key:
            msg = f"{API_KEY_VAR} is not set"
            raise RuntimeError(msg)
        request_id = str(uuid.uuid4())
        result = post_with_retries(
            self.build_payload(flows, examples), self.api_key, self.sleep
        )
        if result.body is None:
            return [self._failed(flow, result, request_id) for flow in flows]
        return [
            self._outcome(flow, f"r{i}", result, request_id, len(flows))
            for i, flow in enumerate(flows)
        ]

    def _failed(self, flow: Flow, result: HttpResult, request_id: str) -> Outcome:
        return Outcome(
            flow=flow,
            model=MODEL,
            p_attack=None,
            category_pred=None,
            confidence=None,
            probabilities=None,
            input_tokens=None,
            output_tokens=None,
            cache_tokens=None,
            reasoning_tokens=None,
            cost_usd=None,
            billed_cost_usd=None,
            latency_e2e_ms=None,
            latency_provider_ms=None,
            time_to_first_token_ms=None,
            train_time_ms=None,
            retries=result.retries,
            error=result.error,
            request_id=request_id,
        )

    def _outcome(
        self, flow: Flow, rid: str, result: HttpResult, request_id: str, batch: int
    ) -> Outcome:
        """Per-Flow view of one response; tokens and cost are split evenly over B."""
        body = result.body or {}
        answers: dict[str, Any] = body.get("answers", {})
        noul: dict[str, Any] = answers.get(f"is_attack_{rid}", {})
        choice: dict[str, Any] = answers.get(f"category_{rid}", {})
        usage: dict[str, Any] = body.get("usage", {})
        gateway: dict[str, Any] = body.get("provider_metadata", {}).get("gateway", {})
        p_attack = noul.get("noul")
        category: Category | None = choice.get("choice")
        market_cost = _money(gateway, "marketCost")
        billed_cost = _money(gateway, "cost")
        return Outcome(
            flow=flow,
            model=str(body.get("model", MODEL)),
            p_attack=None if p_attack is None else float(p_attack),
            category_pred=category,
            confidence=choice.get("confidence"),
            probabilities=choice.get("probabilities"),
            input_tokens=_share(usage.get("input_tokens"), batch),
            output_tokens=_share(usage.get("output_tokens"), batch),
            cache_tokens=None,
            reasoning_tokens=None,
            cost_usd=None if market_cost is None else market_cost / batch,
            billed_cost_usd=None if billed_cost is None else billed_cost / batch,
            latency_e2e_ms=result.latency_ms,
            latency_provider_ms=provider_latency_ms(body),
            time_to_first_token_ms=None,
            train_time_ms=None,
            retries=result.retries,
            error=None,
            request_id=request_id,
            raw=body,
        )


def _share(tokens: int | None, batch: int) -> int | None:
    return None if tokens is None else round(tokens / batch)
