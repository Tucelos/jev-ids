"""The curator: what the Evidence may carry, the answers it repairs, and the baseline that writes no rule."""

from dataclasses import fields
from typing import Any

import pytest
from agno.models.deepseek import DeepSeek
from agno.models.ollama import Ollama
from agno.models.openai import OpenAIChat
from agno.run.agent import RunOutput
from agno.run.base import RunStatus

from jev_ids import ROOT
from jev_ids.arena import curator
from jev_ids.arena.context import Context, Rule, baseline_context
from jev_ids.run import load_prompt

PROMPT: dict[str, Any] = load_prompt(ROOT / "prompts" / "arena" / "curator.md")
LIMITS = curator.Limits(max_rules=4, max_examples=3)
CATEGORIES = {"normal": "legitimate traffic.", "dos": "denial of service.", "probe": "surveillance or scanning."}
CANDIDATES = (
    curator.Candidate(row_id=91, attributes_csv="9,tcp,1", category="dos"),
    curator.Candidate(row_id=92, attributes_csv="9,udp,2", category="dos"),
    curator.Candidate(row_id=93, attributes_csv="9,tcp,3", category="normal"),
)
# One Round of a Detector that alerted on row 2 and let rows 1 and 7 past; row 7 carries the poisoned label of THREAT A2, reported benign
# while the Flow really was a probe. Only the four keys of `analyst.for_curator` plus the record ever reach an Observation.
ROUND = [
    {"row_id": 1, "label": "dos", "detector_verdict": 0, "p_attack": 0.2, "true_category": "dos", "poisoned": False},
    {"row_id": 2, "label": "dos", "detector_verdict": 1, "p_attack": 0.9, "true_category": "dos", "poisoned": False},
    {"row_id": 7, "label": "normal", "detector_verdict": 0, "p_attack": None, "true_category": "probe", "poisoned": True},
]


def observed(item: dict[str, Any]) -> curator.Observation:
    """One Observation from what the Round knew, taking only what a curator is allowed to see."""
    return curator.Observation(
        row_id=item["row_id"],
        label=item["label"],
        detector_verdict=item["detector_verdict"],
        p_attack=item["p_attack"],
        attributes_csv=f"{item['row_id']},tcp,0",
    )


def make_evidence(*, round_index: int = 3, candidates: tuple[curator.Candidate, ...] = CANDIDATES) -> curator.Evidence:
    """The Evidence of one Round of ROUND, as the round loop would build it."""
    observations = tuple(observed(item) for item in ROUND)
    return curator.Evidence(
        round_index=round_index,
        columns="a,b,c",
        categories=CATEGORIES,
        benign="normal",
        observations=observations,
        candidates=candidates,
        misses=2,
        false_alarms=1,
    )


def make_context() -> Context:
    """A Context in force with a two-rule playbook and one chosen Example."""
    rules = (
        Rule(id="r1", text="a telnet session with a root shell is an attack", added_round=1),
        Rule(id="r2", text="old advice", added_round=2),
    )
    return Context(version=2, rules=rules, example_ids=(91,), parent=1, note="round 2")


def edits(*changes: curator.RuleEdit, example_ids: list[int] | None = None, note: str = "why") -> curator.Edits:
    """One candidate Context as the model would state it."""
    return curator.Edits(edits=list(changes), example_ids=[] if example_ids is None else example_ids, note=note)


def answered(*proposals: curator.Edits) -> RunOutput:
    """A RunOutput carrying an Answer, what Agno returns when the model followed the schema."""
    return RunOutput(content=curator.Answer(proposals=list(proposals)), model="deepseek-flash")


class FakeAgent:
    """Stands in for `agno.agent.Agent`: records its settings, answers from a queue."""

    outcomes: list[Any] = []
    built: list[dict[str, Any]] = []

    def __init__(self, **settings: Any) -> None:
        FakeAgent.built.append(settings)

    def run(self, message: str) -> RunOutput:
        FakeAgent.built[-1]["message"] = message
        item = FakeAgent.outcomes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def fake_agent(monkeypatch: pytest.MonkeyPatch) -> type[FakeAgent]:
    FakeAgent.outcomes = []
    FakeAgent.built = []
    monkeypatch.setattr(curator, "Agent", FakeAgent)
    return FakeAgent


def test_a_valid_answer_becomes_the_whole_new_playbook_and_the_chosen_examples(fake_agent: type[FakeAgent]) -> None:
    fake_agent.outcomes = [
        answered(
            edits(
                curator.RuleEdit(action="add", text="more than three failed logins to ftp is an attack"), example_ids=[92, 91], note="ftp"
            ),
            edits(curator.RuleEdit(action="drop", id="r2"), example_ids=[93], note="the second rule fires on nothing"),
        )
    ]
    context = make_context()

    proposals = curator.LLMCurator(PROMPT, "deepseek", LIMITS).propose(context, make_evidence(), 2)

    first, second = proposals
    assert [rule.id for rule in first.rules] == ["r1", "r2", "r3"]
    assert first.rules[2] == Rule(id="r3", text="more than three failed logins to ftp is an attack", added_round=3)
    assert (first.example_ids, first.note) == ((92, 91), "ftp")
    assert [rule.id for rule in second.rules] == ["r1"]
    assert second.example_ids == (93,)
    settings = fake_agent.built[0]
    assert (settings["use_json_mode"], settings["retries"], settings["telemetry"], settings["markdown"]) == (True, 0, False, False)
    assert settings["output_schema"] is curator.Answer
    assert "at most 4 rules" in settings["instructions"].lower()
    assert "- r1: a telnet session with a root shell is an attack" in settings["message"]
    assert "91 | dos | 9,tcp,1" in settings["message"]


def test_the_curator_is_told_the_reported_label_and_never_the_truth(fake_agent: type[FakeAgent]) -> None:
    # THREAT A2 only bites if the curator cannot see it: row 7 really is a probe, and all it is ever shown is the benign label reported
    # for it. The shape is the guard, so the fields are asserted as well as the text.
    named = {field.name for field in fields(curator.Observation)} | {field.name for field in fields(curator.Evidence)}
    assert not named & {"true_category", "poisoned"}
    fake_agent.outcomes = [answered(edits(note="nothing to change"))]

    curator.LLMCurator(PROMPT, "deepseek", LIMITS).propose(make_context(), make_evidence(), 1)

    settings = fake_agent.built[0]
    whole = f"{settings['instructions']}\n{settings['message']}"
    assert "poisoned" not in whole
    assert "true_category" not in whole
    labeled = settings["message"].split("Labeled observations:")[1].split("Shortlist of candidate examples:")[0]
    assert "7 | normal | normal | n/a | 7,tcp,0" in labeled
    assert "probe" not in labeled  # the true Category of row 7, which disagrees with the label the analyst reported


def test_an_example_id_the_model_invented_is_dropped_and_said_so(fake_agent: type[FakeAgent]) -> None:
    fake_agent.outcomes = [answered(edits(example_ids=[92, 4242, 92], note="show it the udp one"))]

    proposal = curator.LLMCurator(PROMPT, "deepseek", LIMITS).propose(make_context(), make_evidence(), 1)[0]

    assert proposal.example_ids == (92,)
    assert proposal.note == "show it the udp one [repaired: examples [4242]: not on the shortlist]"


def test_the_context_own_examples_are_keepable_and_an_empty_answer_keeps_them(fake_agent: type[FakeAgent]) -> None:
    # 91 is on the shortlist too, so 55 is the one that proves a Context may hold on to an Example the loop did not re-offer.
    context = Context(version=2, rules=(), example_ids=(55,), parent=1, note="round 2")
    fake_agent.outcomes = [answered(edits(example_ids=[55]), edits(note="rules only"))]

    kept, silent = curator.LLMCurator(PROMPT, "deepseek", LIMITS).propose(context, make_evidence(), 2)

    assert kept.example_ids == (55,)
    assert silent.example_ids == (55,)  # saying nothing about the Examples is not asking for them to be thrown away


def test_more_rules_and_more_examples_than_allowed_are_truncated(fake_agent: type[FakeAgent]) -> None:
    added = [curator.RuleEdit(action="add", text=f"rule number {index}") for index in range(4)]
    fake_agent.outcomes = [answered(edits(*added, example_ids=[91, 92, 93, 91], note="everything at once"))]

    proposal = curator.LLMCurator(PROMPT, "deepseek", curator.Limits(max_rules=4, max_examples=2)).propose(
        make_context(), make_evidence(), 1
    )[0]

    assert [rule.id for rule in proposal.rules] == ["r1", "r2", "r3", "r4"]
    assert proposal.example_ids == (91, 92)
    assert "playbook cut to the 4 rules allowed, 2 of the new ones dropped" in proposal.note
    assert "examples cut to the 2 allowed" in proposal.note


def test_a_long_rule_is_cut_and_an_empty_one_is_discarded(fake_agent: type[FakeAgent]) -> None:
    long_rule = curator.RuleEdit(action="add", text="x" * 400)
    fake_agent.outcomes = [answered(edits(long_rule, curator.RuleEdit(action="add", text="  \n "), note=""))]

    proposal = curator.LLMCurator(PROMPT, "deepseek", LIMITS).propose(baseline_context(), make_evidence(), 1)[0]

    assert proposal.rules == (Rule(id="r1", text="x" * curator.MAX_RULE_TEXT, added_round=3),)
    assert proposal.note == ("no reason given [repaired: add new rule: text cut to 200 characters; add new rule: empty rule text]")


def test_an_edit_to_a_rule_the_playbook_does_not_have_is_discarded(fake_agent: type[FakeAgent]) -> None:
    fake_agent.outcomes = [
        answered(
            edits(curator.RuleEdit(action="drop", id="r9"), curator.RuleEdit(action="rewrite", id="r8", text="not there"), note="tidy")
        )
    ]

    proposal = curator.LLMCurator(PROMPT, "deepseek", LIMITS).propose(make_context(), make_evidence(), 1)[0]

    assert [rule.id for rule in proposal.rules] == ["r1", "r2"]
    assert proposal.note == "tidy [repaired: drop 'r9': no such rule; rewrite 'r8': no such rule]"


def test_rule_ids_stay_the_same_across_rounds_and_a_retired_id_is_never_reused(fake_agent: type[FakeAgent]) -> None:
    # Round 1 writes the playbook from nothing; Round 2 rewrites one rule, drops the other and adds a third.
    fake_agent.outcomes = [
        answered(edits(curator.RuleEdit(action="add", text="first"), curator.RuleEdit(action="add", text="second"))),
        answered(
            edits(
                curator.RuleEdit(action="rewrite", id="r1", text="first, said better"),
                curator.RuleEdit(action="drop", id="r2"),
                curator.RuleEdit(action="add", text="third"),
            )
        ),
    ]
    agent = curator.LLMCurator(PROMPT, "deepseek", LIMITS)

    born = agent.propose(baseline_context(), make_evidence(round_index=1), 1)[0]
    in_force = baseline_context().child(rules=born.rules, example_ids=born.example_ids, version=1, note="round 1")
    grown = agent.propose(in_force, make_evidence(round_index=2), 1)[0]

    assert born.rules == (Rule(id="r1", text="first", added_round=1), Rule(id="r2", text="second", added_round=1))
    assert grown.rules == (
        # The rewritten rule keeps its id and the Round it was added in; the new one is r3, never the r2 that was just retired.
        Rule(id="r1", text="first, said better", added_round=1),
        Rule(id="r3", text="third", added_round=2),
    )


def test_a_provider_error_is_no_proposal_at_all_and_never_an_empty_playbook(fake_agent: type[FakeAgent]) -> None:
    # agno 3.0.10 raises on some failures and returns a failed RunOutput on others; both end the same way, and neither may answer with a
    # Proposal, because an empty playbook would look like a curator that decided the Detector needs no advice.
    fake_agent.outcomes = [
        RuntimeError("503 busy"),
        RunOutput(content="Error code: 503 - Service Unavailable", status=RunStatus.error),
        RunOutput(content="Sure! Here are some rules.", model="deepseek-flash"),
    ]
    agent = curator.LLMCurator(PROMPT, "deepseek", LIMITS)

    assert agent.propose(make_context(), make_evidence(), 1) == []
    assert agent.last_error == "RuntimeError: 503 busy"
    assert agent.propose(make_context(), make_evidence(), 1) == []
    assert agent.last_error == "provider: Error code: 503 - Service Unavailable"
    assert agent.propose(make_context(), make_evidence(), 1) == []
    assert agent.last_error == "parse: Sure! Here are some rules."
    assert len(fake_agent.built) == 3


def test_only_the_proposals_that_were_asked_for_are_kept(fake_agent: type[FakeAgent]) -> None:
    fake_agent.outcomes = [answered(edits(note="one"), edits(note="two"), edits(note="three"))]

    proposals = curator.LLMCurator(PROMPT, "deepseek", LIMITS).propose(make_context(), make_evidence(), 2)

    assert [proposal.note for proposal in proposals] == ["one", "two"]
    assert curator.LLMCurator(PROMPT, "deepseek", LIMITS).last_error is None


def test_the_heuristic_writes_no_rule_and_shows_the_categories_it_missed(fake_agent: type[FakeAgent]) -> None:
    context = make_context()

    proposal = curator.HeuristicCurator(LIMITS, seed=7).propose(context, make_evidence(), 1)[0]

    assert proposal.rules == context.rules
    # Row 1 was missed and reported as dos, so the dos Flows of the shortlist are the ones shown; 93 is a benign Flow and stays out.
    assert set(proposal.example_ids) == {91, 92}
    assert proposal.note == "heuristic: 2 missed records, 1 of them reported as attacks; Examples only, no rule"
    assert not fake_agent.built  # no Agent, no key, no call


def test_the_heuristic_answers_with_as_many_proposals_as_it_was_asked_for_and_no_two_alike() -> None:
    # The gate keeps the best Proposal of a Round, so an arm handing in one against another arm's two would lose part of every Round to
    # the number of draws instead of to what the draws are worth.
    proposals = curator.HeuristicCurator(LIMITS, seed=7).propose(make_context(), make_evidence(), 2)

    assert len(proposals) == 2
    assert proposals[0].example_ids != proposals[1].example_ids
    assert {proposal.rules for proposal in proposals} == {make_context().rules}  # a baseline that writes no rule, whatever the draw
    assert all("of the 2 Proposals asked for" not in proposal.note for proposal in proposals)


def test_the_two_curators_answer_the_same_number_of_proposals(fake_agent: type[FakeAgent]) -> None:
    fake_agent.outcomes = [answered(edits(example_ids=[91], note="one"), edits(example_ids=[92], note="two"))]
    context, evidence = make_context(), make_evidence()

    asked = 2
    intelligent = curator.LLMCurator(PROMPT, "deepseek", LIMITS).propose(context, evidence, asked)
    baseline = curator.HeuristicCurator(LIMITS, seed=7).propose(context, evidence, asked)

    assert len(intelligent) == len(baseline) == asked


def test_the_heuristic_draws_are_reproducible_from_the_seed_alone() -> None:
    context, evidence = make_context(), make_evidence()
    seven = curator.HeuristicCurator(LIMITS, seed=7).propose(context, evidence, 2)

    assert seven == curator.HeuristicCurator(LIMITS, seed=7).propose(context, evidence, 2)
    assert seven == curator.HeuristicCurator(LIMITS, seed=7).propose(context, evidence, 2)
    drawn = {curator.HeuristicCurator(LIMITS, seed=seed).propose(context, evidence, 1)[0].example_ids for seed in range(20)}
    assert len(drawn) > 1  # the seed really is what breaks the tie between two equally good candidate Examples


def test_a_shortlist_too_thin_to_tell_proposals_apart_yields_fewer_and_says_so() -> None:
    one_flow = (curator.Candidate(row_id=91, attributes_csv="9,tcp,1", category="dos"),)

    proposals = curator.HeuristicCurator(LIMITS, seed=7).propose(make_context(), make_evidence(candidates=one_flow), 3)

    assert [proposal.example_ids for proposal in proposals] == [(91,)]  # padded with a duplicate it would be one Context gated twice
    assert proposals[0].note.endswith("; only 1 of the 3 Proposals asked for differ, the shortlist admits no more")


def test_the_heuristic_proposes_nothing_when_there_is_nothing_to_learn_from() -> None:
    nothing_missed = curator.Evidence(round_index=1, columns="a,b,c", categories=CATEGORIES, benign="normal", candidates=CANDIDATES)

    assert curator.HeuristicCurator(LIMITS).propose(make_context(), nothing_missed, 1) == []
    assert curator.HeuristicCurator(LIMITS).propose(make_context(), make_evidence(candidates=()), 1) == []
    assert curator.HeuristicCurator(LIMITS).propose(make_context(), make_evidence(), 0) == []


def test_the_instructions_are_the_committed_file_with_the_limits_filled_in() -> None:
    text = curator.instructions(PROMPT["text"], curator.Limits(max_rules=12, max_examples=6), 3)

    assert "Propose 3 alternative sets of edits" in text
    assert "At most 12 rules" in text
    assert "At most 6 example row ids" in text
    assert "JSON" in text  # DeepSeek's json_object mode refuses a prompt that does not say the word
    assert not {"{max_rules}", "{max_examples}", "{proposals}"} & set(text.split())  # no placeholder left unfilled


def test_the_message_says_when_there_is_no_playbook_and_no_evidence_yet() -> None:
    bare = curator.Evidence(round_index=1, columns="a,b,c", categories=CATEGORIES, benign="normal")

    text = curator.message(baseline_context(), bare)

    assert "Playbook in force: none yet." in text
    assert "Examples the Context shows today: none, the Arena draws them" in text
    assert "Labeled observations: none." in text
    assert "Shortlist of candidate examples: none." in text


def test_make_model_applies_the_determinism_knobs(monkeypatch: pytest.MonkeyPatch) -> None:
    deepseek = curator.make_model("deepseek", "deepseek-flash")
    assert isinstance(deepseek, DeepSeek)
    assert (deepseek.temperature, deepseek.use_thinking) == (0.0, False)
    openai = curator.make_model("openai", "gpt-5.6-luna")
    assert isinstance(openai, OpenAIChat)
    assert (openai.reasoning_effort, openai.temperature) == ("none", None)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    local = curator.make_model("ollama", "llama3.1")
    assert isinstance(local, Ollama)
    assert (local.host, local.options) == (curator.DEFAULT_OLLAMA_HOST, {"temperature": 0.0})
    monkeypatch.setenv("OLLAMA_HOST", "http://gpu-box:11434")
    assert curator.make_model("ollama", "llama3.1").host == "http://gpu-box:11434"
    with pytest.raises(KeyError, match="gemini"):
        curator.make_model("gemini", "gemini-3.6-flash")


def test_the_two_curators_answer_the_same_three_members() -> None:
    llm = curator.LLMCurator(PROMPT, "ollama", LIMITS, model_id="qwen3:8b")
    heuristic = curator.HeuristicCurator(LIMITS)

    assert (llm.name, llm.model, llm.prompt_hash) == ("llm:ollama", "qwen3:8b", PROMPT["sha256"])
    assert (heuristic.name, heuristic.model, heuristic.prompt_hash) == ("heuristic", "", None)
    assert curator.LLMCurator(PROMPT, "openai", LIMITS).model == "gpt-5.6-luna"
    assert callable(llm.propose) and callable(heuristic.propose)
