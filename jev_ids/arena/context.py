"""The Context: the playbook and the chosen Examples the curator rewrites between Rounds.

In reading order:

- `Rule`: one sentence of the playbook, with the Round it was added in.
- `Context`: one version of the playbook and the chosen Examples, and how it renders to a prompt, to a dict and to its children.
- `baseline_context`: version 0, the Context every Arena starts from.
- `context_from_dict`: a Context back from the dict `Context.to_dict` wrote.

A Context is everything about a Detector the curator is allowed to change. It holds a playbook, a few short sentences of advice, and the
row_ids of the Pool Flows it wants shown as Examples; `state.instructions`, `state.columns`, `state.categories` and the wording of both
`questions` belong to the protocol, and no Context may touch them.
"""

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

# Appended to both questions' `instructions` whenever a playbook is inserted, and never otherwise. The rule is that the CURATOR may not
# write question text; this clause is the renderer's, fixed and identical for every version that has rules, so it cancels out of every
# comparison between two Contexts. It has to exist: the questions name the state paths they read in backticks, so a `state.playbook` no
# question names is inert, and a curator whose Rules were never read would look harmless when it had simply never been heard. The wording
# stays neutral on purpose. A clause that leaned toward `attack` would raise the alert rate on its own and confound every Round.
PLAYBOOK_CLAUSE = "  Take `playbook` into account as well."


@dataclass(frozen=True)
class Rule:
    """One sentence of a playbook, with the Round the curator added it in.

    Frozen because a Rule is shared by every Context descended from the one that introduced it.

    Attributes:
        id: `r1`, `r2`, ..., stable across versions, so a Rule can be followed through the Rounds.
        text: the advice itself, one short sentence, the only part a Detector ever sees.
        added_round: the Round the curator wrote it in.
    """

    id: str
    text: str
    added_round: int


@dataclass(frozen=True)
class Context:
    """One version of what a curator may change: the playbook and the chosen Examples.

    Frozen because versions are kept side by side: a rejected proposal stays readable next to the Context it was measured against.

    Attributes:
        version: 0 is the baseline, the Context an Arena starts from; the Arena numbers the rest.
        rules: the playbook, in the order the Detector reads it.
        example_ids: the row_ids of the Pool Flows this Context chooses as Examples; empty means the Arena draws k per Category itself.
        parent: the version this one was proposed from; None for the baseline.
        note: why the curator made it, for the reader of the Round record.
    """

    version: int
    rules: tuple[Rule, ...] = ()
    example_ids: tuple[int, ...] = ()
    parent: int | None = None
    note: str = ""

    def to_prompt(self, template: str) -> dict[str, Any]:
        """This Context rendered onto `template`, in the shape `run.load_prompt` returns: `text` and its `sha256`.

        A Context renders to a prompt file so the original traceability machinery keeps working unchanged: `JevDetector(ctx.to_prompt(t))`
        just works, and every Prediction row carries that version's `prompt_hash`, so a row can always be traced to the exact Context that
        produced it. The serialization is deterministic (`indent=2, sort_keys=True`), so the same Context always hashes the same.

        The playbook goes to `state.playbook` as plain sentences: the rule ids and the Round numbers are the curator's bookkeeping and
        leaking them would tell the Detector how old a piece of advice is. Both questions then gain `PLAYBOOK_CLAUSE`, the one fixed
        sentence that makes the new state path readable; nothing else about them changes.

        Args:
            template: the request template, `prompts/<dataset>/jev.json` as text.

        Returns:
            `{"text": the rendered JSON, "sha256": the hash of its bytes}`.

        Raises:
            ValueError: the template has no `state` or no `questions`, the two parts a Context may never invent.
        """
        body: dict[str, Any] = json.loads(template)
        if "state" not in body or "questions" not in body:
            raise ValueError("the template needs a `state` and `questions`: a Context may change neither and cannot supply them")
        if not self.rules:
            # An empty playbook renders the file itself and not a re-serialization of it, so version 0 hashes to what the committed
            # template hashes to and the baseline Run stays comparable with the published ones in `results/paper/`. The parse above is
            # only the guard; its result is thrown away here. `example_ids` change nothing: chosen Examples travel as the `examples`
            # argument of `predict`, never through the template.
            return {"text": template, "sha256": hashlib.sha256(template.encode("utf-8")).hexdigest()}
        body["state"]["playbook"] = [rule.text for rule in self.rules]
        for question in body["questions"].values():
            question["instructions"] += PLAYBOOK_CLAUSE
        text = json.dumps(body, indent=2, sort_keys=True)
        return {"text": text, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}

    def to_dict(self) -> dict[str, Any]:
        """This Context as JSON-ready data, the form the Round record keeps it in."""
        return {
            "version": self.version,
            "rules": [{"id": rule.id, "text": rule.text, "added_round": rule.added_round} for rule in self.rules],
            "example_ids": list(self.example_ids),
            "parent": self.parent,
            "note": self.note,
        }

    def with_rules(self, rules: Sequence[Rule], version: int, note: str) -> "Context":
        """A child of this Context with another playbook; the chosen Examples are kept.

        The Arena hands in the version rather than counting from this one, because a Round may propose several children of the same parent
        and they must not share a number.
        """
        return replace(self, version=version, rules=tuple(rules), parent=self.version, note=note)

    def with_examples(self, example_ids: Sequence[int], version: int, note: str) -> "Context":
        """A child of this Context with other chosen Examples; the playbook is kept."""
        return replace(self, version=version, example_ids=tuple(example_ids), parent=self.version, note=note)


def baseline_context() -> Context:
    """Version 0: no playbook and no chosen Examples, so the Detector reads the committed template unchanged.

    Every Arena measures its Rounds against this one, so it has no parent and nothing to explain.
    """
    return Context(version=0, note="baseline")


def context_from_dict(data: Mapping[str, Any]) -> Context:
    """A Context back from the dict `Context.to_dict` wrote."""
    rules: Sequence[Mapping[str, Any]] = data["rules"]
    return Context(
        version=data["version"],
        rules=tuple(Rule(id=rule["id"], text=rule["text"], added_round=rule["added_round"]) for rule in rules),
        example_ids=tuple(data["example_ids"]),
        parent=data["parent"],
        note=data["note"],
    )
