"""The curator: the defence's learning step, and the only thing about a Detector that changes between Rounds.

In reading order:

- `Observation` and `Candidate`: one labeled Flow a curator learns from, and one Pool Flow it may choose as an Example.
- `Evidence`: everything one Round is allowed to tell a curator.
- `Proposal`: the whole new playbook and the chosen Examples, what a curator answers with.
- `Limits`: the two caps of `[curator]` every Proposal is held to.
- `RuleEdit`, `Edits` and `Answer`: the JSON an LLM curator must answer (Agno's `output_schema`).
- `instructions` and `message`: `prompts/arena/curator.md` with the limits filled in, and the Evidence rendered under it.
- `playbook_lines`, `one_observation`, `observation_lines` and `candidate_lines`: the parts of that message.
- `collapse`, `shorten`, `next_index`, `rule_text`, `remove`, `apply_edits`, `chosen_examples`, `compose`: the repairs an answer takes.
- `resolve`: those repairs together, one Proposal from one untrusted set of edits.
- `LLMCurator`: the curator under study; one Agno Agent per call, stateless.
- `missed_flows` and `lesson_ids`: what a Round got wrong, and the Examples one draw of the baseline would answer it with.
- `HeuristicCurator`: the no-intelligence baseline; Examples drawn from the misses, and not one rule.
- `make_model`: the Agno model of a provider, with its determinism knobs.
- `Curator`: the two of them, what the round loop holds.

A curator reads what the last Round produced and proposes a better Context: a few more short rules for Jev's `state`, and which Pool Flows
to show as Examples. That is the novel part of this project, a Detector whose prompt improves each Round instead of a model that retrains,
and `HeuristicCurator` is what keeps the claim honest: if adding the missed Flows as Examples does as well as the LLM's reasoning, there
was no reasoning to report.

Two boundaries hold this module in place. The first is the truth: `Evidence` has no field for a Flow's real Category and none for whether
a label was tampered with, and nothing here imports `arena.analyst`, so a curator cannot reach the truth even by accident. The analyst's
reported label is all it gets, which is what makes a poisoned label a threat rather than a nuisance. The second is trust: an LLM's answer
is data from outside, so `resolve` repairs what it can, discards what it cannot, and writes the loss into the Proposal's `note`; no
unchecked Rule and no invented row_id ever reaches a Context.

Nothing here reads a file or the config module: the round loop loads the prompt through `run.load_prompt`, adapts `[curator]` into
`Limits`, and builds the `Evidence` from the projection `analyst.for_curator` returns joined with the Flows it names.
"""

import os
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from agno.agent import Agent
from agno.models.deepseek import DeepSeek
from agno.models.ollama import Ollama
from agno.models.openai import OpenAIChat
from agno.run.agent import RunOutput
from agno.run.base import RunStatus
from pydantic import BaseModel

from jev_ids.arena.context import Context, Rule

# The provider's model id when `[curator] model` is empty; the same ids `detectors.llm` defaults to, plus Agno's own Ollama default.
DEFAULT_MODEL = {"deepseek": "deepseek-flash", "openai": "gpt-5.6-luna", "ollama": "llama3.1"}
# Where an Ollama server is looked for when `OLLAMA_HOST` says nothing.
DEFAULT_OLLAMA_HOST = "http://localhost:11435"
# A rule is one sentence of advice the Detector reads before every Flow, so a long one is both a lie about the format and a cost paid on
# every call for the rest of the Run. Anything longer is cut here rather than refused, because the first sentence is usually the advice.
MAX_RULE_TEXT = 200
# The note goes into the Round record for a human to read, not to a Detector; long enough for a reason, short enough to stay a reason.
MAX_NOTE_TEXT = 400
# Shuffles `HeuristicCurator` may spend per Proposal it was asked for before it accepts that the shortlist has no further distinct answer.
DRAWS_PER_PROPOSAL = 4


@dataclass(frozen=True)
class Observation:
    """One labeled Flow a curator learns from: what the analyst reported, what the Detector said, and the Flow's own values.

    Frozen, as a Flow is: one Round's Evidence is built once and read by every curator and every Proposal of that Round.

    There is deliberately no field for the Flow's real Category. The analyst's `label` is the curator's only ground truth, so a tampered
    label teaches a blind spot instead of being quietly corrected, and the label budget keeps meaning what it says.

    Attributes:
        row_id: the Flow the analyst looked at.
        label: the Category the analyst reported, which is not always the truth.
        detector_verdict: what the Detector said about it, 1 for an alert.
        p_attack: the Detector's p_attack, or None when the call failed.
        attributes_csv: the Flow's feature values in Card order, so a rule can be written about a value and not about a verdict.
    """

    row_id: int
    label: str
    detector_verdict: int
    p_attack: float | None
    attributes_csv: str


@dataclass(frozen=True)
class Candidate:
    """One Pool Flow the round loop offers as an Example, and the only Flows a Proposal may choose from.

    Attributes:
        row_id: the Pool Flow, what a Context's `example_ids` holds.
        attributes_csv: its feature values in Card order.
        category: its Category; a Pool label is known to everyone and is not the analyst's to report.
    """

    row_id: int
    attributes_csv: str
    category: str


@dataclass(frozen=True)
class Evidence:
    """Everything one Round is allowed to tell a curator.

    The shape is the boundary. `true_category` and `poisoned` have no field here, so the leak that would make THREAT A2 harmless is not
    forbidden by a comment but impossible to write: a round loop that wanted to pass the truth would have nowhere to put it.

    Attributes:
        round_index: the Round being learned from; a new Rule is stamped with it.
        columns: the Card's feature names in order, the vocabulary a rule may name.
        categories: the Card's Categories and what each one means, as the Detector's own prompt describes them.
        benign: which of those Categories is the benign one.
        observations: the labeled Flows of the Round, in the order the analyst reviewed them.
        candidates: the Pool Flows offered as Examples this Round; the round loop should keep the Context's current Examples among them,
            or no curator can choose to keep them.
        misses: attack Flows the Detector did not alert on, as the Round measured it.
        false_alarms: benign Flows it did alert on.
    """

    round_index: int
    columns: str
    categories: Mapping[str, str]
    benign: str
    observations: tuple[Observation, ...] = ()
    candidates: tuple[Candidate, ...] = ()
    misses: int = 0
    false_alarms: int = 0


@dataclass(frozen=True)
class Proposal:
    """One candidate Context: the whole new playbook, the chosen Examples, and why.

    The playbook is the result and not the edits that produced it, because the caller applies it with `Context.child` and a Context is a
    version and not a patch; the edits are how the model thinks, and they stop at `resolve`. The three fields are what `child` asks for,
    so a Proposal is applied in one call and a Round never leaves a half-applied Context behind.

    Attributes:
        rules: the full playbook the Detector would read, in the order it reads it.
        example_ids: the Pool Flows to show as Examples; empty means the Arena draws k per Category itself.
        note: why, for the Round record, with whatever `resolve` had to repair appended to it.
    """

    rules: tuple[Rule, ...]
    example_ids: tuple[int, ...]
    note: str


@dataclass(frozen=True)
class Limits:
    """The two caps of `[curator]` a Proposal is held to; a parameter bundle the round loop fills from the TOML config.

    No defaults: `configs/arena.toml` states every number once, and a second copy here would be the one that silently disagrees with it.

    Attributes:
        max_rules: how long the playbook may grow.
        max_examples: how many Pool Flows a Context may choose as Examples.
    """

    max_rules: int
    max_examples: int


class RuleEdit(BaseModel):
    """One change to the playbook, as the model states it.

    A curator answers in edits and not in a finished playbook, so that a rule which still holds is left alone and keeps its id; `resolve`
    is what turns the edits back into the whole thing.

    Attributes:
        action: `add` a rule, `rewrite` the text of one, or `drop` one.
        id: the rule to rewrite or drop; ignored for `add`, whose id is minted here so the model cannot reuse a retired one.
        text: the new sentence, for `add` and `rewrite`.
    """

    action: Literal["add", "rewrite", "drop"]
    id: str = ""
    text: str = ""


class Edits(BaseModel):
    """One candidate Context as the model states it: what to change, what to show, and why.

    Attributes:
        edits: the changes to the playbook in force.
        example_ids: the Pool Flows to show as Examples, taken from the shortlist.
        note: one sentence on what the Evidence shows and why these edits answer it.
    """

    edits: list[RuleEdit] = []
    example_ids: list[int] = []
    note: str = ""


class Answer(BaseModel):
    """What one curator call must return: several alternative Contexts for the gate to choose between.

    All of them in one call, and not one call per Proposal: at temperature 0 the same Evidence asked twice gives the same answer twice, so
    asking once for alternatives is the only way to get a real choice, and it costs the budget one call per Round instead of several.
    """

    proposals: list[Edits] = []


def instructions(template: str, limits: Limits, count: int) -> str:
    """`prompts/arena/curator.md` with the limits and the number of Proposals filled in.

    The wording lives in the file so its sha256 lands in the Round record like every other prompt of this project; only the numbers, which
    come from the config, are filled in here.
    """
    return (
        template.replace("{max_rules}", str(limits.max_rules))
        .replace("{max_examples}", str(limits.max_examples))
        .replace("{proposals}", str(count))
    )


def playbook_lines(rules: Sequence[Rule]) -> str:
    """The playbook in force, one rule per line with the id the model edits it by."""
    if not rules:
        return " none yet.\n"
    return "\n" + "".join(f"- {rule.id}: {rule.text}\n" for rule in rules)


def one_observation(item: Observation) -> str:
    """One labeled Flow as its line of the message.

    The reported label and nothing beside it: this line is the whole of what a curator is told about what a Flow really was.
    """
    verdict = "attack" if item.detector_verdict else "normal"
    score = "n/a" if item.p_attack is None else f"{item.p_attack:.2f}"
    return f"{item.row_id} | {item.label} | {verdict} | {score} | {item.attributes_csv}\n"


def observation_lines(observations: Sequence[Observation]) -> str:
    """The Round's labeled Flows, one per line: the reported label, the Detector's verdict, its p_attack and the record.

    The record's values travel with every line because a rule that discriminates has to name a column and a value; a curator given only
    verdicts can write nothing sharper than advice about being careful.
    """
    if not observations:
        return " none.\n"
    head = "row_id | analyst label | detector verdict | p_attack | record\n"
    return "\n" + head + "".join(one_observation(item) for item in observations)


def candidate_lines(candidates: Sequence[Candidate]) -> str:
    """The Pool Flows on offer as Examples, one per line; the only row_ids a Proposal may name."""
    if not candidates:
        return " none.\n"
    head = "row_id | category | record\n"
    return "\n" + head + "".join(f"{item.row_id} | {item.category} | {item.attributes_csv}\n" for item in candidates)


def message(context: Context, evidence: Evidence) -> str:
    """The Evidence as the text one curator call is given, under the instructions.

    Rendered in Python and not in the prompt file: the file is the wording, which is read and reviewed by a human, and this is the data,
    which changes every Round. Only what `Evidence` holds can appear here, which is the whole point of that dataclass.
    """
    categories = "".join(f"- `{name}`: {text}\n" for name, text in evidence.categories.items())
    return (
        f"Round {evidence.round_index}.\n\n"
        f"Columns of a record, in order:\n{evidence.columns}\n\n"
        f"Categories:\n{categories}\n"
        f"Playbook in force:{playbook_lines(context.rules)}\n"
        f"Examples the Context shows today: {', '.join(str(row_id) for row_id in context.example_ids) or 'none, the Arena draws them'}\n\n"
        f"The Round: misses {evidence.misses}, false alarms {evidence.false_alarms}.\n\n"
        f"Labeled observations:{observation_lines(evidence.observations)}\n"
        f"Shortlist of candidate examples:{candidate_lines(evidence.candidates)}"
    )


def collapse(text: str) -> str:
    """The text on one line, its runs of whitespace reduced to single spaces.

    A rule with a newline in it would break the playbook into two lines, and the second one would read to a Detector as a rule nobody
    wrote; the same goes for a note in the Round record.
    """
    return " ".join(text.split())


def shorten(text: str, limit: int) -> str:
    """The text on one line and at most `limit` characters long, the rest cut off."""
    return collapse(text)[:limit]


def next_index(rules: Sequence[Rule]) -> int:
    """The highest `r<n>` number the playbook already uses, so the next minted id is higher than every one of them.

    Counted over the playbook as it arrived and never over what is left after a drop: an id that named a rule in an earlier Round must
    never name a different one later, or the Rounds of a Run can no longer be read side by side.
    """
    used = [int(rule.id[1:]) for rule in rules if rule.id.startswith("r") and rule.id[1:].isdigit()]
    return max(used, default=0)


def rule_text(edit: RuleEdit) -> tuple[str, list[str]]:
    """The sentence an `add` or a `rewrite` carries, collapsed and capped, and what that cost.

    An empty sentence returns nothing at all, so the edit is discarded: a rule with no text would be a blank line in the playbook, which
    reads to a Detector as advice it failed to understand.
    """
    named = edit.id or "new rule"
    text = collapse(edit.text)
    if not text:
        return "", [f"{edit.action} {named}: empty rule text"]
    if len(text) > MAX_RULE_TEXT:
        return text[:MAX_RULE_TEXT], [f"{edit.action} {named}: text cut to {MAX_RULE_TEXT} characters"]
    return text, []


def remove(kept: dict[str, Rule], rule_id: str) -> list[str]:
    """Take the rule `rule_id` names out of `kept`, or say why it could not be taken out."""
    return [] if kept.pop(rule_id, None) is not None else [f"drop {rule_id!r}: no such rule"]


def apply_edits(rules: Sequence[Rule], edits: Sequence[RuleEdit], round_index: int) -> tuple[list[Rule], list[str]]:
    """The edits resolved against the playbook in force, and what had to be discarded on the way.

    Ids are the point of doing it this way. A rewritten rule keeps its id and the Round it was added in, so the playbook of Round 7 can be
    read against the playbook of Round 3 rule by rule; a dropped or rewritten id the playbook does not have is discarded rather than
    invented; and only `add` mints an id, counting from the highest the playbook ever used so a retired id is never handed to a new rule.

    Args:
        rules: the playbook in force, in the order the Detector reads it.
        edits: what the model asked for, untrusted.
        round_index: the Round to stamp a newly added Rule with.

    Returns:
        The resulting playbook, kept rules in their old order and new ones appended, and one line per discarded or repaired edit.
    """
    kept = {rule.id: rule for rule in rules}
    repairs: list[str] = []
    minted = next_index(rules)
    for edit in edits:
        if edit.action == "drop":
            repairs.extend(remove(kept, edit.id))
            continue
        text, cost = rule_text(edit)
        repairs.extend(cost)
        if not text:
            continue
        if edit.action == "add":
            minted += 1
            kept[f"r{minted}"] = Rule(id=f"r{minted}", text=text, added_round=round_index)
        elif edit.id in kept:
            # A rewrite keeps the Round the rule was added in: what changed is the wording, not the age of the idea.
            kept[edit.id] = Rule(id=edit.id, text=text, added_round=kept[edit.id].added_round)
        else:
            repairs.append(f"rewrite {edit.id!r}: no such rule")
    return list(kept.values()), repairs


def chosen_examples(example_ids: Sequence[int], allowed: frozenset[int], max_examples: int) -> tuple[list[int], list[str]]:
    """The Example row_ids a Proposal may keep, and what had to be discarded.

    A row_id the loop never offered is discarded and never passed on: a Context carrying an id the Pool does not have would fail when the
    Arena went to fetch the Flow, and a model that invents one is guessing at Flows it has not seen. Duplicates are dropped because the
    cap counts Examples and not lines.
    """
    unique = list(dict.fromkeys(example_ids))
    kept = [row_id for row_id in unique if row_id in allowed]
    invented = [row_id for row_id in unique if row_id not in allowed]
    repairs = [f"examples {invented}: not on the shortlist"] if invented else []
    if len(kept) > max_examples:
        repairs.append(f"examples cut to the {max_examples} allowed")
    return kept[:max_examples], repairs


def compose(note: str, repairs: Sequence[str]) -> str:
    """The model's reason with the repairs appended, so the Round record shows what was thrown away and not only what was kept."""
    said = shorten(note, MAX_NOTE_TEXT) or "no reason given"
    return f"{said} [repaired: {'; '.join(repairs)}]" if repairs else said


def resolve(proposed: Edits, context: Context, evidence: Evidence, limits: Limits) -> Proposal:
    """One untrusted set of edits as a Proposal that is safe to hand to `Context.child`.

    Every cap is enforced here rather than trusted to the prompt. An answer that names no Example at all keeps the Context's current ones:
    saying nothing about the Examples is not the same as asking for them to be thrown away, and treating it as such would make the
    playbook and the Examples drift together for no stated reason.

    Args:
        proposed: the edits, the Example row_ids and the note the model answered.
        context: the Context in force, whose playbook the edits are resolved against.
        evidence: the Round's Evidence; its candidates are the row_ids an Example may name.
        limits: the caps from `[curator]`.

    Returns:
        The full playbook, the Examples that survived, and a note carrying every repair.
    """
    rules, repairs = apply_edits(context.rules, proposed.edits, evidence.round_index)
    if len(rules) > limits.max_rules:
        # The overflow is always at the end, where the new rules were appended, so a full playbook has to be pruned before it can grow.
        # Cutting the head instead would throw away the rules that survived the most Rounds, which are the ones the gate already kept.
        repairs.append(f"playbook cut to the {limits.max_rules} rules allowed, {len(rules) - limits.max_rules} of the new ones dropped")
        rules = rules[: limits.max_rules]
    # The Context's own Examples are allowed beside the shortlist: they are Pool Flows the Detector is already being shown, so keeping one
    # is never an invented id, and without this a Context could not hold an Example for two Rounds in a row.
    allowed = frozenset({item.row_id for item in evidence.candidates} | set(context.example_ids))
    examples, dropped = chosen_examples(proposed.example_ids, allowed, limits.max_examples)
    repairs.extend(dropped)
    return Proposal(rules=tuple(rules), example_ids=tuple(examples or context.example_ids), note=compose(proposed.note, repairs))


class LLMCurator:
    """Proposes Contexts with an LLM through an Agno Agent: one call per Round, no tools, no memory between Rounds."""

    def __init__(self, prompt: dict[str, Any], provider: str, limits: Limits, *, model_id: str | None = None) -> None:
        """Keep the prompt and the caps, and build the Agno model once.

        Args:
            prompt: `run.load_prompt` of `prompts/arena/curator.md`.
            provider: `deepseek`, `openai` or `ollama`.
            limits: the caps every Proposal of this curator is held to.
            model_id: the provider's model id; None means the provider default.
        """
        self.template: str = prompt["text"]
        self.prompt_hash: str = prompt["sha256"]
        self.provider = provider
        self.limits = limits
        self.model = model_id or DEFAULT_MODEL[provider]
        self.name = f"llm:{provider}"
        # The model object holds the HTTP client, so it is built once; an Agent is cheap and built per call.
        self.agno_model: Any = make_model(provider, self.model)
        # What went wrong on the last call, for the Round record; None when the call worked. A failed call has nowhere else to say so,
        # because it answers with no Proposal at all.
        self.last_error: str | None = None

    def propose(self, context: Context, evidence: Evidence, count: int) -> list[Proposal]:
        """`count` candidate Contexts from one Round's Evidence, or none at all when the provider failed.

        DeepSeek has no native `json_schema` mode, so there the schema is enforced by parsing; OpenAI and Ollama both answer the schema
        natively and keep Agno's default. Agno's own retries and telemetry are off, as everywhere else in this project.

        A provider error is never raised and never a silently empty playbook: it returns no Proposal, the Round keeps the Context already
        in force, and `last_error` says what happened. agno 3.0.10 does not raise on a failed non-streaming run either, it returns a
        `RunOutput` with `status == error` and the message in `content`, so the status is checked as well as the exception.

        Args:
            context: the Context in force, the playbook the edits are resolved against.
            evidence: what the Round is allowed to tell the curator.
            count: how many alternative Contexts to ask for; extra ones the model volunteers are ignored.

        Returns:
            Up to `count` Proposals, each already repaired and within the limits; an empty list when the call failed or was unparseable.
        """
        # `Any` because Agno's `run` overloads are partially untyped for pyright.
        agent: Any = Agent(
            model=self.agno_model,
            instructions=instructions(self.template, self.limits, count),
            output_schema=Answer,
            use_json_mode=self.provider == "deepseek",
            markdown=False,
            retries=0,
            telemetry=False,
        )
        self.last_error = None
        try:
            run: RunOutput = agent.run(message(context, evidence))
        except Exception as exc:  # every provider error is recorded, not raised
            self.last_error = f"{type(exc).__name__}: {exc}"[:500]
            return []
        content: Any = run.content
        if run.status == RunStatus.error or not isinstance(content, Answer):
            self.last_error = f"{'provider' if run.status == RunStatus.error else 'parse'}: {content!s}"[:500]
            return []
        return [resolve(proposed, context, evidence, self.limits) for proposed in content.proposals[:count]]


def missed_flows(evidence: Evidence) -> tuple[list[Observation], list[Observation]]:
    """The Round's misses, and the ones among them the analyst reported as an attack.

    The second list is the lesson proper: a Flow the Detector let past that the analyst then called an attack is the one thing a Round can
    teach without any reasoning at all.
    """
    missed = [item for item in evidence.observations if not item.detector_verdict]
    return missed, [item for item in missed if item.label != evidence.benign]


def lesson_ids(context: Context, evidence: Evidence, rng: random.Random) -> list[int]:
    """The Example row_ids one draw of the heuristic would show, best first.

    The misses the loop happens to offer as candidates come first, then Pool Flows of the Categories the analyst reported for those
    misses, then whatever the Context already shows. The shuffle is where the draw enters: a tie between candidates of the same Category
    is broken by `rng` and not by Pool order, which correlates with how the Dataset was collected.
    """
    missed, attacks = missed_flows(evidence)
    wanted = {item.label for item in attacks}
    offered = {item.row_id for item in evidence.candidates}
    shuffled = list(evidence.candidates)
    rng.shuffle(shuffled)
    ids = [item.row_id for item in (*attacks, *missed) if item.row_id in offered]
    ids += [item.row_id for item in shuffled if item.category in wanted]
    return list(dict.fromkeys([*ids, *context.example_ids])) if ids else []


class HeuristicCurator:
    """The no-intelligence baseline: no model, no key, no rule; it only chooses which Pool Flows to show as Examples.

    It answers the question the LLM curator cannot answer about itself: would adding the Flows the Detector missed as Examples have done
    the same? Without a baseline that spends no reasoning, a gain measured over the Rounds cannot be attributed to any reasoning.

    It answers with as many Proposals as it is asked for, because the gate keeps the best proposal of a Round and two draws at a gate are
    two chances to clear its bars. A baseline handing in one Proposal against an LLM's two would lose part of every Round to the sample
    size and not to the reasoning, which is the one comparison this class exists to make.
    """

    def __init__(self, limits: Limits, *, seed: int = 0) -> None:
        """Keep the caps and the Run's seed.

        Args:
            limits: the caps every Proposal of this curator is held to.
            seed: the seed of the draws it makes, which tie it breaks between equally good candidate Examples.
        """
        self.limits = limits
        self.seed = seed
        self.name = "heuristic"
        # No provider and no model id: the baseline exists precisely so that a Run can be read with this column empty.
        self.model = ""
        self.prompt_hash: str | None = None

    def propose(self, context: Context, evidence: Evidence, count: int) -> list[Proposal]:
        """`count` Proposals that differ from one another, or fewer when the shortlist cannot tell that many apart.

        The lesson of a Round is what got past the Detector, so every draw chooses its Examples from the misses; the playbook is handed
        back untouched, which is what makes this the baseline. Every difference it can make is a difference made by Examples alone, so the
        Examples are also the only axis the draws vary along: draw `index` shuffles the shortlist under `(seed, index)`, which gives a
        different subset when the shortlist is richer than `max_examples` and a different order when it is not.

        Each draw's stream is built from the seed and the index alone, never carried from `__init__`, so a Proposal is a function of
        `(seed, count)`, the Context and the Evidence: the baseline must not depend on how many Rounds were played before this one.

        Duplicates are never returned as padding. A shortlist that admits one set of Examples yields one Proposal however many were asked
        for, and the `note` says so, so a Round record shows the arm ran short instead of showing the gate a Context twice.

        Args:
            context: the Context in force, whose playbook is kept and whose Examples fill any room left over.
            evidence: what the Round is allowed to tell the curator.
            count: how many Proposals the Round wants; below one asks for nothing.

        Returns:
            Up to `count` Proposals, no two of them alike; none when the Round offers no Example to learn from.
        """
        drawn: list[tuple[int, ...]] = []
        # A bounded number of draws, so a shortlist with fewer distinct answers than `count` ends the search instead of spinning; the
        # bound is a multiple of `count`, which keeps the result a function of `(seed, count)` and of nothing else.
        for index in range(max(count, 0) * DRAWS_PER_PROPOSAL):
            rng = random.Random(f"{self.seed}:{index}")  # noqa: S311  # seeded, not secret
            chosen = tuple(lesson_ids(context, evidence, rng)[: self.limits.max_examples])
            if chosen and chosen not in drawn:
                drawn.append(chosen)
            if len(drawn) == count:
                break
        missed, attacks = missed_flows(evidence)
        note = f"heuristic: {len(missed)} missed records, {len(attacks)} of them reported as attacks; Examples only, no rule"
        if drawn and len(drawn) < count:
            note += f"; only {len(drawn)} of the {count} Proposals asked for differ, the shortlist admits no more"
        return [Proposal(rules=context.rules, example_ids=ids, note=note) for ids in drawn]


def make_model(provider: str, model_id: str) -> Any:
    """The Agno model of a provider, with its determinism knobs.

    DeepSeek thinks by default and then silently ignores `temperature`, so thinking is off and the temperature is 0. GPT-5.x documents no
    temperature at all and runs at `reasoning_effort="none"`, the lowest available, so setting one would be rejected by the API rather
    than honoured. Ollama takes its sampling knobs in `options` and its server from `OLLAMA_HOST`, which is where a local model is reached
    without a key of any kind; that is the provider to run the loop on when the budget, and not the quality, is what is being tested.

    Raises:
        KeyError: the provider is not one this curator can build.
    """
    if provider == "deepseek":
        return DeepSeek(id=model_id, temperature=0.0, use_thinking=False)
    if provider == "ollama":
        return Ollama(id=model_id, host=os.getenv("OLLAMA_HOST") or DEFAULT_OLLAMA_HOST, options={"temperature": 0.0})
    if provider == "openai":
        return OpenAIChat(id=model_id, reasoning_effort="none")
    raise KeyError(f"curator provider {provider!r} is not implemented: use {', '.join(sorted(DEFAULT_MODEL))}")


# What the round loop holds, as `run.Detector` is: a union and not a base class, so a curator is a class with `name`, `model` and
# `propose(context, evidence, count)` and nothing it has to inherit.
Curator = LLMCurator | HeuristicCurator
