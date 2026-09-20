"""LLM detector: instructions, parsing, retries and the preamble fallback."""

from __future__ import annotations

from typing import Any

import pytest
from agno.metrics import MessageMetrics, RunMetrics
from agno.models.deepseek import DeepSeek
from agno.models.message import Message
from agno.run.agent import RunOutput

from somids import dataset
from somids.detectors import chatgpt, llm
from somids.prices import Price
from somids.prompt import load_prompt

FLOW = dataset.Flow(
    row_id=5, text=",".join(["2"] * 41), attack_name="neptune", difficulty=1
)
TRAIN = [
    dataset.Flow(row_id=i, text=",".join([str(i)] * 41), attack_name=name, difficulty=1)
    for i, name in enumerate(["normal", "neptune", "satan", "ftp_write", "perl"])
]
PRICE = Price(input=0.30, cached_input=0.006, output=1.20)


def run_output(
    content: Any, *, cached: int = 0, duration: float | None = 0.5
) -> RunOutput:
    metrics = RunMetrics(input_tokens=1000, output_tokens=20, cache_read_tokens=cached)
    metrics.duration = 0.9
    metrics.time_to_first_token = 0.2
    message = Message(role="assistant", content="{}")
    message.metrics = MessageMetrics(duration=duration)
    return RunOutput(
        content=content,
        metrics=metrics,
        messages=[message],
        model="deepseek-flash-2026",
    )


class FakeAgent:
    def __init__(self, outcomes: list[Any]) -> None:
        self.outcomes = outcomes
        self.messages: list[str] = []

    def run(self, message: str) -> RunOutput:
        self.messages.append(message)
        item = self.outcomes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def no_sleep(_seconds: float) -> None:
    return None


def detector_with(
    agent: FakeAgent, provider: llm.Provider = "deepseek", model: Any = None
) -> llm.LLMDetector:
    return llm.LLMDetector(
        load_prompt("v1"),
        provider,
        PRICE,
        model_id="m",
        agno_model=model or object(),
        sleep=no_sleep,
        agent_factory=lambda _instructions: agent,
    )


def test_instructions_carry_task_categories_columns_examples_and_json() -> None:
    prompt = load_prompt("v1")
    text = llm.build_instructions(
        prompt, dataset.sample_examples(TRAIN, 1, seed=0), "kv"
    )
    assert text.startswith(prompt.task)
    assert "- `dos`:" in text
    assert "duration,protocol_type" in text
    assert text.count(" => ") == 6  # the header line plus five examples
    assert "duration=1 protocol_type=1" in text
    assert "JSON" in text
    assert llm.EXAMPLES_HEADER.strip() not in llm.build_instructions(prompt, [], "csv")


def test_happy_path_parses_the_judgement_and_prices_the_tokens() -> None:
    judgement = llm.Judgement(verdict="attack", category="dos", p_attack=0.93)
    agent = FakeAgent([run_output(judgement, cached=800)])

    [outcome] = detector_with(agent).predict([FLOW], [])

    assert agent.messages == [f"Record:\n{FLOW.text}"]
    assert outcome.p_attack == 0.93
    assert outcome.y_pred == 1
    assert outcome.category_pred == "dos"
    assert outcome.model == "deepseek-flash-2026"
    assert (outcome.input_tokens, outcome.output_tokens, outcome.cache_tokens) == (
        1000,
        20,
        800,
    )
    assert outcome.cost_usd == pytest.approx(PRICE.cost(1000, 800, 20))
    assert outcome.billed_cost_usd is None
    assert outcome.latency_e2e_ms == 500.0
    assert outcome.time_to_first_token_ms == 200.0
    assert outcome.error is None
    assert outcome.raw["content"] == {
        "verdict": "attack",
        "category": "dos",
        "p_attack": 0.93,
    }


def test_unparsed_content_is_an_error_but_keeps_tokens_and_latency() -> None:
    agent = FakeAgent([run_output("I think it is an attack", duration=None)])
    [outcome] = detector_with(agent).predict([FLOW], [])
    assert outcome.p_attack is None
    assert outcome.y_pred is None
    assert outcome.error == "parse: I think it is an attack"
    assert outcome.input_tokens == 1000
    assert outcome.latency_e2e_ms == 900.0


def test_provider_errors_are_retried_then_recorded() -> None:
    judgement = llm.Judgement(verdict="normal", category="normal", p_attack=0.1)
    agent = FakeAgent([RuntimeError("503 busy"), run_output(judgement)])
    [outcome] = detector_with(agent).predict([FLOW], [])
    assert outcome.retries == 1
    assert outcome.p_attack == 0.1

    failing = FakeAgent([RuntimeError("down")] * llm.MAX_ATTEMPTS)
    [failed] = detector_with(failing).predict([FLOW], [])
    assert failed.retries == llm.MAX_ATTEMPTS - 1
    assert failed.error == "RuntimeError: down"
    assert failed.p_attack is None
    assert failed.latency_e2e_ms is None


class FakeChatGPTModel:
    def __init__(self) -> None:
        self.preamble = chatgpt.NEUTRAL_PREAMBLE

    def set_preamble(self, preamble: str) -> None:
        self.preamble = preamble


def test_rejected_neutral_preamble_falls_back_to_codex_once() -> None:
    judgement = llm.Judgement(verdict="attack", category="probe", p_attack=0.8)
    agent = FakeAgent(
        [RuntimeError("400 Instructions are not valid"), run_output(judgement)]
    )
    model = FakeChatGPTModel()
    detector = detector_with(agent, provider="chatgpt", model=model)

    [outcome] = detector.predict([FLOW], [])

    assert model.preamble == chatgpt.CODEX_PREAMBLE
    assert outcome.raw["preamble"] == chatgpt.CODEX_PREAMBLE
    assert outcome.billed_cost_usd == 0.0
    assert outcome.retries == 1
    assert detector.name == "llm:chatgpt"


def test_make_model_applies_the_determinism_knobs() -> None:
    deepseek = llm.make_model("deepseek", "deepseek-flash")
    assert isinstance(deepseek, DeepSeek)
    assert deepseek.temperature == 0.0
    assert deepseek.use_thinking is False
    luna = llm.make_model("chatgpt", "gpt-5.6-luna")
    assert isinstance(luna, chatgpt.ChatGPTSubscriptionModel)
    assert luna.reasoning_effort == "none"
    assert (
        llm.LLMDetector(load_prompt("v1"), "deepseek", PRICE).model_id
        == "deepseek-flash"
    )
