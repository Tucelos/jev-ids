"""The Context: what it renders into a prompt, what it refuses to touch, and how a version descends from another."""

import json
from typing import Any

import pytest

from jev_ids import ROOT
from jev_ids.arena.context import PLAYBOOK_CLAUSE, Context, Rule, baseline_context, context_from_dict
from jev_ids.detectors.jev import JevDetector
from jev_ids.run import load_prompt
from tests.helpers import CATEGORIES, JEV_PROMPT, TASK

TEMPLATE: str = JEV_PROMPT["text"]
# The prompt hash every upstream row of `results/paper/` was recorded under; the baseline is only comparable while it renders to this.
UPSTREAM_JEV = ROOT / "prompts" / "nsl-kdd" / "jev.json"
UPSTREAM_SHA256 = "e5704395d8a6c11f814d65f346c258408d7a5724ffbf2ab22e5339a9f8d076b2"
RULES = (
    Rule(id="r1", text="A short connection to port 21 that fails to log in is r2l.", added_round=1),
    Rule(id="r2", text="Zero bytes in both directions on many hosts is a probe.", added_round=3),
)


def rendered(context: Context) -> dict[str, Any]:
    """The state of the JSON a Context renders onto the shared template."""
    return json.loads(context.to_prompt(TEMPLATE)["text"])


def test_the_baseline_is_version_zero_with_nothing_chosen() -> None:
    baseline = baseline_context()
    assert (baseline.version, baseline.parent) == (0, None)
    assert (baseline.rules, baseline.example_ids) == ((), ())
    assert "playbook" not in rendered(baseline)["state"]


def test_a_playbook_reaches_the_state_as_plain_sentences_in_order() -> None:
    state = rendered(Context(version=1, rules=RULES))["state"]
    assert state["playbook"] == [RULES[0].text, RULES[1].text]
    # The bookkeeping stays with the curator: a Detector is never told how old a Rule is or what it is called.
    assert "r1" not in json.dumps(state["playbook"])
    assert "added_round" not in json.dumps(state["playbook"])


def test_rendering_leaves_the_protocol_alone() -> None:
    body = rendered(Context(version=7, rules=RULES, example_ids=(3, 8)))
    original: dict[str, Any] = json.loads(TEMPLATE)
    assert body["state"]["instructions"] == TASK
    assert body["state"]["columns"] == "a,b,c"
    assert body["state"]["categories"] == CATEGORIES
    assert body["model"] == "jev-1.13.0"
    # The two questions keep their names, their types and every word the protocol gave them; the renderer only names the new state path
    # at the end, and the same way for every Context that has a playbook.
    assert body["questions"].keys() == original["questions"].keys()
    for name, question in body["questions"].items():
        assert question["type"] == original["questions"][name]["type"]
        assert question["instructions"] == original["questions"][name]["instructions"] + PLAYBOOK_CLAUSE
    # The chosen Examples are the Arena's business: they are drawn from the Pool by row_id, never written into the prompt file.
    assert "example_ids" not in json.dumps(body)


def test_the_baseline_renders_the_committed_file_byte_for_byte() -> None:
    upstream = load_prompt(UPSTREAM_JEV)
    baseline = baseline_context().to_prompt(upstream["text"])
    # Version 0 must be the published prompt and not a re-serialization of it, or the baseline Run stops being comparable with the rows
    # upstream recorded in `results/paper/` and the whole study loses the line it is measured against.
    assert baseline == upstream
    assert baseline["sha256"] == UPSTREAM_SHA256
    # Choosing Examples is not a change to the file: they travel as the `examples` argument of `predict`.
    assert Context(version=1, example_ids=(4, 9)).to_prompt(upstream["text"])["sha256"] == UPSTREAM_SHA256


def test_a_playbook_changes_the_hash_and_both_questions_point_at_it() -> None:
    upstream = load_prompt(UPSTREAM_JEV)
    curated = Context(version=1, rules=RULES, parent=0, note="two rules").to_prompt(upstream["text"])
    body: dict[str, Any] = json.loads(curated["text"])

    assert curated["sha256"] != UPSTREAM_SHA256
    assert body["state"]["playbook"] == [rule.text for rule in RULES]
    # A `state.playbook` no question names is inert: the clause is what makes the curator's Rules reachable at all.
    assert [question["instructions"].endswith(PLAYBOOK_CLAUSE) for question in body["questions"].values()] == [True, True]
    assert "playbook" in body["questions"]["is_attack"]["instructions"]
    # Neutral wording: a clause that named a Verdict would raise the alert rate by itself and confound every Round.
    assert "attack" not in PLAYBOOK_CLAUSE
    assert "normal" not in PLAYBOOK_CLAUSE


def test_the_same_context_always_hashes_the_same_and_a_different_one_does_not() -> None:
    first = Context(version=1, rules=RULES).to_prompt(TEMPLATE)
    again = Context(version=1, rules=RULES).to_prompt(TEMPLATE)
    other = Context(version=2, rules=RULES[:1]).to_prompt(TEMPLATE)
    assert first == again
    assert first["sha256"] != other["sha256"]
    # The version itself is not part of the prompt: two versions with one playbook are one prompt and one hash.
    assert Context(version=9, rules=RULES).to_prompt(TEMPLATE)["sha256"] == first["sha256"]


def test_the_rendered_prompt_is_what_a_detector_takes() -> None:
    prompt = Context(version=4, rules=RULES).to_prompt(TEMPLATE)
    assert prompt.keys() == {"text", "sha256"}
    detector = JevDetector(prompt)
    assert (detector.model, detector.prompt_hash) == ("jev-1.13.0", prompt["sha256"])


@pytest.mark.parametrize("missing", ["state", "questions"])
def test_a_template_without_the_protocol_is_refused(missing: str) -> None:
    body: dict[str, Any] = json.loads(TEMPLATE)
    del body[missing]
    with pytest.raises(ValueError, match="`state` and `questions`"):
        baseline_context().to_prompt(json.dumps(body))


def test_a_context_survives_a_round_trip_through_json() -> None:
    context = Context(version=2, rules=RULES, example_ids=(11, 4), parent=1, note="warezmaster kept slipping through")
    restored = context_from_dict(json.loads(json.dumps(context.to_dict())))
    assert restored == context
    assert context.to_dict()["rules"][1] == {"id": "r2", "text": RULES[1].text, "added_round": 3}


def test_a_child_changes_one_thing_keeps_the_other_and_leaves_its_parent_alone() -> None:
    parent = Context(version=2, rules=RULES, example_ids=(11, 4), parent=1, note="a start")
    shorter = parent.with_rules(RULES[:1], version=3, note="r2 never fired")
    chosen = parent.with_examples([7], version=4, note="a clearer probe")

    assert (shorter.version, shorter.parent, shorter.note) == (3, 2, "r2 never fired")
    assert (shorter.rules, shorter.example_ids) == (RULES[:1], (11, 4))
    assert (chosen.version, chosen.parent) == (4, 2)
    assert (chosen.rules, chosen.example_ids) == (RULES, (7,))
    # Two proposals of one Round descend from the same version, which is why the Arena numbers them and the Context does not.
    assert (shorter.parent, chosen.parent) == (2, 2)
    assert parent.rules == RULES and parent.example_ids == (11, 4)
