"""LLM baseline through Agno: the same task, categories, columns and Examples
as Jev, flattened into one instruction text, with a structured Judgement back.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from agno.agent import Agent
from agno.models.deepseek import DeepSeek
from agno.run.agent import RunOutput
from pydantic import BaseModel, Field

from somids.dataset import CATEGORIES, Category, Example, Flow, RowFormat, format_flow
from somids.detectors import chatgpt
from somids.detectors.base import Outcome
from somids.prices import Price
from somids.prompt import Prompt

Provider = Literal["deepseek", "chatgpt"]
DEFAULT_MODEL: dict[Provider, str] = {
    "deepseek": "deepseek-flash",
    "chatgpt": "gpt-5.6-luna",
}
MAX_ATTEMPTS = 5
BACKOFF_SECONDS = 1.0
INVALID_PREAMBLE_MARK = "Instructions are not valid"

INSTRUCTIONS_TEMPLATE = """{task}

Categories:
{categories}

Columns of a record, in order:
{columns}
{examples_block}
Answer only with a JSON object with three fields: "verdict" ("attack" or \
"normal"), "category" (one of normal, dos, probe, r2l, u2r) and "p_attack" \
(your probability, between 0 and 1, that the record is an attack)."""
EXAMPLES_HEADER = "\nLabeled example records (record => category):\n"
RECORD_TEMPLATE = "Record:\n{record}"


class Judgement(BaseModel):
    """The structured answer asked of every LLM."""

    verdict: Literal["attack", "normal"]
    category: Category
    p_attack: float = Field(ge=0.0, le=1.0)


def build_instructions(
    prompt: Prompt, examples: Sequence[Example], fmt: RowFormat
) -> str:
    examples_block = ""
    if examples:
        lines = [f"{format_flow(e.flow, fmt)} => {e.category}" for e in examples]
        examples_block = EXAMPLES_HEADER + "\n".join(lines) + "\n"
    return INSTRUCTIONS_TEMPLATE.format(
        task=prompt.task,
        categories=prompt.categories_text,
        columns=prompt.columns,
        examples_block=examples_block,
    )


def make_model(provider: Provider, model_id: str) -> Any:
    """The Agno model for a provider, with the agreed determinism knobs."""
    if provider == "deepseek":
        return DeepSeek(id=model_id, temperature=0.0, use_thinking=False)
    return chatgpt.ChatGPTSubscriptionModel(id=model_id, reasoning_effort="none")


@dataclass(frozen=True, slots=True)
class CallResult:
    run: RunOutput | None
    wall_ms: float | None
    retries: int
    error: str | None


@dataclass(slots=True)
class LLMDetector:
    """Detector backed by an Agno Agent; one call per Flow, no tools."""

    prompt: Prompt
    provider: Provider
    price: Price
    model_id: str = ""
    fmt: RowFormat = "csv"
    sleep: Callable[[float], None] = time.sleep
    agno_model: Any = field(default=None, repr=False)
    agent_factory: Callable[[str], Any] | None = field(default=None, repr=False)
    _agent: Any = field(default=None, repr=False)
    _agent_examples: int | None = field(default=None, repr=False)
    _fell_back: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        self.model_id = self.model_id or DEFAULT_MODEL[self.provider]
        if self.agno_model is None:
            self.agno_model = make_model(self.provider, self.model_id)

    @property
    def name(self) -> str:
        return f"llm:{self.provider}"

    @property
    def model(self) -> str:
        return self.model_id

    @property
    def preamble(self) -> str | None:
        return getattr(self.agno_model, "preamble", None)

    def agent_for(self, examples: Sequence[Example]) -> Any:
        """One Agent per Examples object; the run loop reuses the object per cell."""
        if self._agent is None or self._agent_examples != id(examples):
            instructions = build_instructions(self.prompt, examples, self.fmt)
            self._agent = self._build_agent(instructions)
            self._agent_examples = id(examples)
        return self._agent

    def _build_agent(self, instructions: str) -> Any:
        if self.agent_factory is not None:
            return self.agent_factory(instructions)
        return Agent(
            model=self.agno_model,
            instructions=instructions,
            output_schema=Judgement,
            use_json_mode=self.provider == "deepseek",
            markdown=False,
            retries=0,
            telemetry=False,
        )

    def predict(
        self, flows: Sequence[Flow], examples: Sequence[Example]
    ) -> list[Outcome]:
        return [self._predict_one(flow, examples) for flow in flows]

    def _predict_one(self, flow: Flow, examples: Sequence[Example]) -> Outcome:
        message = RECORD_TEMPLATE.format(record=format_flow(flow, self.fmt))
        result = self._call(message, examples)
        request_id = str(uuid.uuid4())
        if result.run is None:
            return self._outcome(flow, None, result, request_id)
        return self._outcome(flow, result.run, result, request_id)

    def _call(self, message: str, examples: Sequence[Example]) -> CallResult:
        """Up to MAX_ATTEMPTS; a rejected neutral preamble is swapped once."""
        error = "no attempt made"
        for attempt in range(MAX_ATTEMPTS):
            started = time.perf_counter()
            try:
                agent: Any = self.agent_for(examples)
                run: RunOutput = agent.run(message)
            except Exception as exc:  # noqa: BLE001 - every provider error is recorded
                error = self._after_failure(exc, attempt)
                continue
            return CallResult(
                run, (time.perf_counter() - started) * 1000, attempt, None
            )
        return CallResult(None, None, MAX_ATTEMPTS - 1, error)

    def _after_failure(self, exc: Exception, attempt: int) -> str:
        """Record the error, swap the preamble if that was the cause, else back off."""
        error = f"{type(exc).__name__}: {exc}"[:500]
        if not self._fallback_preamble(error) and attempt < MAX_ATTEMPTS - 1:
            self.sleep(BACKOFF_SECONDS * 2**attempt)
        return error

    def _fallback_preamble(self, error: str) -> bool:
        """Grilling Q29: neutral preamble first, the Codex one only if rejected."""
        if (
            self.provider != "chatgpt"
            or self._fell_back
            or INVALID_PREAMBLE_MARK not in error
        ):
            return False
        self.agno_model.set_preamble(chatgpt.CODEX_PREAMBLE)
        self._agent = None
        self._fell_back = True
        return True

    def _outcome(
        self, flow: Flow, run: RunOutput | None, result: CallResult, request_id: str
    ) -> Outcome:
        judgement, parse_error = parse_judgement(run)
        tokens = token_counts(run)
        latency = call_duration_ms(run) if run is not None else None
        return Outcome(
            flow=flow,
            model=str(getattr(run, "model", None) or self.model_id),
            p_attack=None if judgement is None else judgement.p_attack,
            category_pred=None if judgement is None else judgement.category,
            confidence=None,
            probabilities=None,
            input_tokens=tokens.get("input_tokens"),
            output_tokens=tokens.get("output_tokens"),
            cache_tokens=tokens.get("cache_read_tokens"),
            reasoning_tokens=tokens.get("reasoning_tokens"),
            cost_usd=self._cost(tokens),
            billed_cost_usd=0.0 if self.provider == "chatgpt" else None,
            latency_e2e_ms=latency if latency is not None else result.wall_ms,
            latency_provider_ms=None,
            time_to_first_token_ms=first_token_ms(run),
            train_time_ms=None,
            retries=result.retries,
            error=result.error or parse_error,
            request_id=request_id,
            raw=raw_of(run, self.preamble),
        )

    def _cost(self, tokens: dict[str, int]) -> float | None:
        if "input_tokens" not in tokens:
            return None
        return self.price.cost(
            tokens["input_tokens"],
            tokens.get("cache_read_tokens", 0),
            tokens.get("output_tokens", 0),
        )


def parse_judgement(run: RunOutput | None) -> tuple[Judgement | None, str | None]:
    """The structured answer, or the reason it is missing."""
    if run is None:
        return None, None
    content: Any = run.content
    if isinstance(content, Judgement):
        return content, None
    text = str(content)[:200]
    return None, f"parse: {text}"


def token_counts(run: RunOutput | None) -> dict[str, int]:
    metrics = None if run is None else run.metrics
    if metrics is None:
        return {}
    counts: dict[str, int] = {}
    for name in (
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "reasoning_tokens",
    ):
        value: int | None = getattr(metrics, name, None)
        if value is not None:
            counts[name] = int(value)
    return counts


def call_duration_ms(run: RunOutput) -> float | None:
    """The API call's own duration when Agno measured it, else the run's."""
    for message in reversed(run.messages or []):
        if message.role == "assistant" and message.metrics.duration:
            return float(message.metrics.duration) * 1000
    if run.metrics is not None and run.metrics.duration:
        return float(run.metrics.duration) * 1000
    return None


def first_token_ms(run: RunOutput | None) -> float | None:
    if run is None or run.metrics is None or not run.metrics.time_to_first_token:
        return None
    return float(run.metrics.time_to_first_token) * 1000


def raw_of(run: RunOutput | None, preamble: str | None) -> dict[str, Any]:
    if run is None:
        return {"preamble": preamble} if preamble else {}
    content: Any = run.content
    raw: dict[str, Any] = {
        "content": content.model_dump()
        if isinstance(content, BaseModel)
        else str(content),
        "model": run.model,
        "metrics": token_counts(run),
    }
    if preamble:
        raw["preamble"] = preamble
    return raw


CATEGORY_NAMES: tuple[Category, ...] = CATEGORIES
