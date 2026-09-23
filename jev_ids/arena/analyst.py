"""The simulated analyst: the only labels the curator ever learns from, and the channel an adversary can poison.

In reading order:

- `Feedback`: one labeled observation the curator may learn from, and whether that label was tampered with.
- `AnalystParams`: what one pass of the analyst costs and how wrong it is.
- `report`: the Category the analyst writes down for one Prediction, right or, with `label_noise`, wrong.
- `review`: one pass over one Round's Predictions, the alert queue down to the budget plus a share of the quiet Flows.
- `delay`: the Feedback a curator at a given Round is allowed to see.
- `poison`: THREAT A2, an adversary who relabels attack Feedback as benign.
- `for_curator`: the projection every curator reads the Feedback through, and the only one it may.

A real SOC labels a fraction of what it sees, and that scarcity is what makes the loop adversarial: the curator only learns from what the
analyst looked at. Reviewing the alerts and nothing else would close the loop into an echo chamber in which an attack the Detector missed
can never be learned, so a `sample_rate` share of the non-alerting Flows is reviewed too; that is the single channel through which a miss
becomes knowledge.

Nothing here reads a file or a config module: the round loop adapts the TOML config into an `AnalystParams` and passes the Run's random
stream. Every draw goes through that `random.Random`, never the global `random`, so a Run replays exactly from its seed.
"""

import random
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any

from jev_ids import metrics
from jev_ids.records import Prediction


@dataclass(frozen=True)
class Feedback:
    """One labeled observation the curator may learn from.

    Frozen, as a Flow is: the history of a Run is carried from Round to Round and `poison` rewrites it by building new entries, never by
    mutating the ones the analyst wrote.

    Attributes:
        row_id: the Flow the analyst looked at.
        observed_round: the Round whose Predictions this came from; `delay` reads it.
        true_category: the Flow's real Category, kept so the experiment can score the analyst; not what the curator is told.
        detector_verdict: the Verdict the Detector gave that Flow, 1 for an alert.
        p_attack: the Detector's p_attack, or None when the call failed.
        label: the Category the analyst reports, which is not always the truth.
        poisoned: whether this label was tampered with; for measurement only, and kept from the curator by `for_curator`.
    """

    row_id: int
    observed_round: int
    true_category: str
    detector_verdict: int
    p_attack: float | None
    label: str
    poisoned: bool = False


@dataclass(frozen=True)
class AnalystParams:
    """What one pass of the analyst costs and how wrong it is; a parameter bundle, nothing more.

    Attributes:
        categories: the Card's Categories, the alphabet a wrong label is drawn from.
        alert_budget: how many alerts the analyst of one Round can review.
        sample_rate: the share of the non-alerting Flows reviewed anyway.
        label_noise: the probability that a reviewed Flow is reported as another Category.
    """

    categories: tuple[str, ...]
    alert_budget: int
    sample_rate: float
    label_noise: float = 0.0


def report(prediction: Prediction, params: AnalystParams, rng: random.Random) -> str:
    """The Category the analyst writes down: the truth, or with probability `label_noise` another Category drawn uniformly.

    The coin is tossed for every reviewed Flow whatever `label_noise` is, so the stream of draws keeps its shape and two Runs that differ
    only in the noise level stay comparable Flow by Flow. A Card with a single Category has no other one to report, so the truth stands.

    Two limitations of this model, both left in on purpose and both to be read with the results:

    - The draw is uniform over the other Categories, and real analyst confusion is not: in NSL-KDD an r2l Flow looks like a normal
      session and is mistaken for one far more often than a dos Flow is mistaken for a u2r. A uniform confusion matrix therefore
      understates the mistakes that matter and spreads them over pairs an analyst would rarely confuse.
    - Some of those wrong labels land on the benign Category, so noise on an attack Flow is a weaker version of what `poison` does on
      purpose. With `label_noise` above zero the two are confounded and the unpoisoned arm of the poisoning experiment is not clean;
      the default of 0.0 keeps them apart, and a Run that raises both should report the noise level beside every poisoning number.
    """
    true_category: str = prediction["category_true"]
    others = [category for category in params.categories if category != true_category]
    if rng.random() >= params.label_noise or not others:
        return true_category
    return rng.choice(others)


def review(predictions: Sequence[Prediction], round_index: int, params: AnalystParams, rng: random.Random) -> list[Feedback]:
    """One analyst pass over one Round's Predictions: the alert queue down to the budget, plus a share of the quiet Flows.

    An alert queue is ranked by score, so when the alerts outnumber `alert_budget` the analyst reaches the highest-p_attack ones and the
    tail of the queue is never looked at; that truncation, and not a random subset of the alerts, is what a scarce SOC actually does. A
    Prediction whose call failed carries no Verdict and counts as `normal`, the fail-open of `metrics.verdict`, so it falls among the
    quiet Flows.

    An exact `sample_rate` share of those quiet Flows is drawn without replacement, rather than a coin tossed per Flow: a SOC budgets a
    fixed slice of the queue, and a fixed count keeps the Feedback volume of two Runs comparable.

    Args:
        predictions: every Prediction of the Round, alerts and misses alike.
        round_index: the Round these Predictions come from; it is stamped on each Feedback for `delay`.
        params: the budget, the sampling share and the noise of this analyst.
        rng: the Run's random stream.

    Returns:
        The reviewed Flows as Feedback: the alerts first, highest p_attack first, then the sampled quiet Flows in Round order.
    """
    alerts = [p for p in predictions if metrics.verdict(p) == 1]
    quiet = [p for p in predictions if metrics.verdict(p) == 0]
    # Stable sort: two alerts with the same p_attack keep the order of the Round, so the truncation is reproducible.
    ranked = sorted(alerts, key=lambda p: p.get("p_attack") or 0.0, reverse=True)
    drawn = rng.sample(range(len(quiet)), min(len(quiet), round(params.sample_rate * len(quiet))))
    reviewed = [*ranked[: params.alert_budget], *(quiet[index] for index in sorted(drawn))]
    return [
        Feedback(
            row_id=prediction["row_id"],
            observed_round=round_index,
            true_category=prediction["category_true"],
            detector_verdict=metrics.verdict(prediction),
            p_attack=prediction.get("p_attack"),
            label=report(prediction, params, rng),
            poisoned=False,  # the analyst is careless, never hostile; `poison` is the hostile one
        )
        for prediction in reviewed
    ]


def delay(feedback: Sequence[Feedback], current_round: int, delay_rounds: int) -> list[Feedback]:
    """The Feedback a curator at `current_round` may use: nothing observed after `current_round - delay_rounds`.

    Labeling takes time. A curator that already sees the Round it is about to react to has been told the answer, which flatters the
    defence and hides how much ground the attacker gains while the queue is worked; `delay_rounds = 0` is that instant curator, kept only
    as the optimistic baseline the realistic settings are read against.
    """
    horizon = current_round - delay_rounds
    return [item for item in feedback if item.observed_round <= horizon]


def poison(feedback: Sequence[Feedback], fraction: float, benign: str, rng: random.Random) -> list[Feedback]:
    """THREAT A2: relabel a `fraction` of the Feedback on attack Flows as benign, and mark those entries `poisoned`.

    An adversary who reaches the labeling channel, an insider or a false-positive complaint process the defender trusts, never has to
    touch the Detector: teaching the curator that an attack was benign writes the blind spot into the Context itself, where it survives
    every later Round.

    The draw runs over the Feedback whose Flow really is an attack, whatever the analyst reported, because that is what an adversary aims
    at. The flag exists so the experiment can measure the damage, in the gate's numbers and in the report; `for_curator` is what keeps it
    from reaching the curator, which could otherwise drop the tampered entries and leave the threat no threat at all.

    Args:
        feedback: the analyst's Feedback, already delayed if the Run delays it.
        fraction: the share of the attack Feedback to flip, rounded to a whole number of entries.
        benign: the Card's benign Category, what a flipped entry is reported as.
        rng: the Run's random stream.

    Returns:
        A new list in the same order; the drawn entries are new Feedback relabeled benign and marked, the rest are the given ones.
    """
    attacks = [index for index, item in enumerate(feedback) if item.true_category != benign]
    flipped = set(rng.sample(attacks, min(len(attacks), round(fraction * len(attacks)))))
    return [replace(item, label=benign, poisoned=True) if index in flipped else item for index, item in enumerate(feedback)]


def for_curator(feedback: Sequence[Feedback]) -> list[dict[str, Any]]:
    """What a curator is allowed to know about the Feedback: the Flow, the label it was given, and what the Detector said about it.

    The projection is the boundary and not a convention. `true_category` never crosses it, or a curator would quietly learn from a truth
    the analyst never reported and the label budget would stop meaning anything; `poisoned` never crosses it either, or a curator could
    drop the tampered entries and THREAT A2 would be no threat at all. Every curator reads the Feedback through this function, so the
    leak is impossible to write rather than forbidden by a comment.

    Args:
        feedback: the Feedback the Run has finished with, delayed and poisoned as the Run asks.

    Returns:
        One plain dict per Feedback, in the same order, holding `row_id`, `label`, `detector_verdict` and `p_attack` and nothing else.
    """
    return [
        {"row_id": item.row_id, "label": item.label, "detector_verdict": item.detector_verdict, "p_attack": item.p_attack}
        for item in feedback
    ]
