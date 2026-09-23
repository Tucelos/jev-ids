"""The acceptance gate: whether the Context a curator proposed replaces the one in force.

In reading order:

- `Measured`: the numbers one Context's Predictions give the gate.
- `Discordance`: the attack Flows the two Contexts disagreed on, and the exact test over them.
- `GatePolicy` and `DEFAULT_POLICY`: the mode and the four thresholds a Run gates on.
- `GateVerdict`: the decision, why it was taken, and the numbers it was taken on.
- `false_alarm_rate` and `measure`: the share of benign Flows alerted on, and one side's numbers together.
- `pairing` and `discordance`: the two sides matched Flow by Flow, and McNemar's exact test over the attack Flows they split on.
- `chance`, `evidence`, `unmeasurable` and `guard`: the guarded rule itself.
- `integrity`: the one check both modes run.
- `evaluate`: the entry the round loop calls.

The curator proposes and the gate disposes. Recall is the number the loop pushes on, and a Context that raises it by alerting on
everything looks like progress while destroying the system for the legitimate traffic it also alerts on; so recall may be bought only
while the false-alarm cost stays where it was. Rates and not counts, because a Round may judge any number of Flows.

Both Contexts are scored over the held-out `arena-val` split, never over the `arena` split the Rounds and the analyst's Feedback come
from, so acceptance is not measured on what the curator was fitted to. Judging the same Flows twice also makes the comparison paired:
`pairing` matches them on `row_id` and `metrics.mcnemar_exact` asks whether a recall difference is more than a coin toss, so a one-Flow
wobble no longer rolls a Context back. Sides that did not judge the same Flows fall back to the unpaired rule, which `reason` says.

Recall and F1 come from `jev_ids.metrics`, the same code the paper's tables are built from, so the gate cannot drift from the report.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from jev_ids import metrics
from jev_ids.records import Prediction

# How much more benign traffic a new Context may alert on, as an absolute difference of rates: 0.02 is two percentage points.
DEFAULT_FALSE_ALARM_SLACK = 0.02
# How much recall a new Context may give up, as an absolute difference of rates. Zero is the strict rule; the paired test below is what
# keeps that strictness from firing on noise, so the two settings are read together.
DEFAULT_RECALL_SLACK = 0.0
# Under this many attack Flows the two Contexts cannot be told apart at all, and the gate says so instead of pretending to measure.
DEFAULT_MIN_ATTACK_FLOWS = 30
# The share of Predictions whose call failed that still counts as a working Context; see `integrity`.
DEFAULT_MAX_ERROR_RATE = 0.05
# A recall drop is only held against a Context when McNemar's exact test puts it below this p.
RECALL_DROP_ALPHA = 0.05


@dataclass(frozen=True)
class Measured:
    """What one Context's Predictions give the gate.

    Attributes:
        flows: how many Predictions were measured; zero is a Round that judged nothing.
        attack_flows: how many of them were attack Flows, the evidence a recall rests on.
        recall: share of the attack Flows alerted on, or None when no attack Flow was judged.
        false_alarm_rate: share of the benign Flows alerted on, or None when no benign Flow was judged.
        f1: attack-class F1, or None when there was neither an alert nor an attack Flow.
        error_rate: share of the Predictions whose call failed, or None over no Prediction at all.
    """

    flows: int
    attack_flows: int
    recall: float | None
    false_alarm_rate: float | None
    f1: float | None
    error_rate: float | None


@dataclass(frozen=True)
class Discordance:
    """The attack Flows two Contexts judged differently, and how surprising that split is.

    Only the discordant Flows tell two Contexts apart (CONTEXT.md, "Discordant pair"); the ones both alerted on, and the ones both
    missed, carry no information about which is better.

    Attributes:
        candidate_only: attack Flows only the candidate Context alerted on, the recall it gained.
        incumbent_only: attack Flows only the incumbent Context alerted on, the recall it lost.
        mcnemar_p: exact two-sided probability that a split this uneven is a coin toss.
    """

    candidate_only: int
    incumbent_only: int
    mcnemar_p: float


@dataclass(frozen=True)
class GatePolicy:
    """How strict a Run's gate is; a parameter bundle the round loop fills from the TOML config.

    A bundle rather than five arguments on `evaluate`, so a Run records the policy it gated on as one object beside its Verdicts.

    Attributes:
        mode: `guarded`, the rule below, or `none`, which keeps every Context that is not broken.
        recall_slack: how much recall the candidate may give up, as an absolute difference of rates.
        false_alarm_slack: how far the false-alarm rate may rise, as an absolute difference of rates.
        min_attack_flows: the attack Flows the gate needs before it will decide anything at all.
        max_error_rate: the share of failed calls a candidate may have; checked in both modes.
    """

    mode: str = "guarded"
    recall_slack: float = DEFAULT_RECALL_SLACK
    false_alarm_slack: float = DEFAULT_FALSE_ALARM_SLACK
    min_attack_flows: int = DEFAULT_MIN_ATTACK_FLOWS
    max_error_rate: float = DEFAULT_MAX_ERROR_RATE


# What a Run gates on unless it says otherwise; a name and not a `GatePolicy()` in the signature, so the default is one shared object.
DEFAULT_POLICY = GatePolicy()


@dataclass(frozen=True)
class GateVerdict:
    """Whether a candidate Context is kept, in one sentence and the numbers behind it.

    `reason` is written for a human: it goes into the Run record and into the report, and it is the only trace left of why a Round rolled
    back to the Context it already had.

    Attributes:
        accepted: whether the candidate Context replaces the incumbent.
        reason: the rule that fired, with the numbers that fired it.
        candidate_recall: recall of the proposed Context over its attack Flows.
        incumbent_recall: recall of the Context in force over its attack Flows.
        candidate_false_alarm_rate: share of benign Flows the proposed Context alerted on.
        incumbent_false_alarm_rate: share of benign Flows the Context in force alerted on.
        candidate_f1: attack-class F1 of the proposed Context, reported but never decided on.
        incumbent_f1: attack-class F1 of the Context in force, reported but never decided on.
        candidate_error_rate: share of the proposed Context's calls that failed; the one number both modes check.
        incumbent_error_rate: share of the Context in force's calls that failed, reported for the record.
        mcnemar_p: the paired test's p over the discordant attack Flows, or None when the two sides were not pairable.
        candidate_only_hits: attack Flows only the candidate alerted on, or None when not pairable.
        incumbent_only_hits: attack Flows only the incumbent alerted on, or None when not pairable.
    """

    accepted: bool
    reason: str
    candidate_recall: float | None
    incumbent_recall: float | None
    candidate_false_alarm_rate: float | None
    incumbent_false_alarm_rate: float | None
    candidate_f1: float | None
    incumbent_f1: float | None
    candidate_error_rate: float | None
    incumbent_error_rate: float | None
    mcnemar_p: float | None
    candidate_only_hits: int | None
    incumbent_only_hits: int | None


def false_alarm_rate(predictions: Sequence[Prediction]) -> float | None:
    """Share of the benign Flows alerted on, or None when no benign Flow was judged.

    `metrics.rate` is the share of the rows it is given that raised an alert, so over the benign Flows alone it is the false-alarm rate.
    A Prediction whose call failed counts as `normal` there and is therefore not a false alarm, the fail-open of `metrics.verdict`; that
    is exactly the hole `integrity` closes.
    """
    return metrics.rate([p for p in predictions if p["is_attack"] == 0])


def measure(predictions: Sequence[Prediction]) -> Measured:
    """Recall over the attack Flows, false alarms over the benign ones, F1 and the error rate of one Context's Round."""
    scored = metrics.scores(predictions)
    return Measured(
        flows=len(predictions),
        attack_flows=sum(p["is_attack"] == 1 for p in predictions),
        recall=scored["recall"],
        false_alarm_rate=false_alarm_rate(predictions),
        f1=scored["f1"],
        error_rate=scored["error_rate"],
    )


def pairing(candidate: Sequence[Prediction], incumbent: Sequence[Prediction]) -> list[metrics.PredictionPair] | None:
    """The two sides matched Flow by Flow, or None when they did not judge the very same Flows once each.

    Set equality and not containment: a candidate judged over a subset would have its recall taken over one population and the
    incumbent's over another, which is the unpaired comparison this function exists to avoid. Anything else falls back to that unpaired
    rule rather than to a paired test that is not entitled to the name.
    """
    incumbent_by_flow = {p["row_id"]: p for p in incumbent}
    candidate_flows = {p["row_id"] for p in candidate}
    judged_once = len(candidate_flows) == len(candidate) and len(incumbent_by_flow) == len(incumbent)
    if not candidate or not judged_once or candidate_flows != set(incumbent_by_flow):
        return None
    return [(p, incumbent_by_flow[p["row_id"]]) for p in candidate]


def discordance(pairs: Sequence[metrics.PredictionPair]) -> Discordance:
    """McNemar's exact test over the attack Flows the two Contexts split on.

    Over an attack Flow, alerting is being right, so the counts `metrics.mcnemar_exact` wants are the attack Flows each side alone
    caught. A candidate that lost six attack Flows and gained none is a real drop (p = 0.031); one that lost four and gained none is what
    the same Contexts would do again by chance (p = 0.125), and rolling a Context back over it would be chasing noise.
    """
    attacks = [(proposed, in_force) for proposed, in_force in pairs if proposed["is_attack"] == 1]
    candidate_only = sum(metrics.verdict(proposed) > metrics.verdict(in_force) for proposed, in_force in attacks)
    incumbent_only = sum(metrics.verdict(proposed) < metrics.verdict(in_force) for proposed, in_force in attacks)
    return Discordance(candidate_only, incumbent_only, metrics.mcnemar_exact(candidate_only, incumbent_only))


def chance(paired: Discordance | None) -> bool:
    """Whether the paired test calls the recall difference a coin toss; without a pairing nothing can be called one."""
    return paired is not None and paired.mcnemar_p >= RECALL_DROP_ALPHA


def evidence(paired: Discordance | None) -> str:
    """How the recall difference was tested, for the reason line and so the record never hides which rule ran."""
    if paired is None:
        return "unpaired: the two sides judged different Flows, so the difference could not be tested"
    return f"paired: McNemar p={paired.mcnemar_p:.3f} over {paired.candidate_only} gained and {paired.incumbent_only} lost attack Flows"


def unmeasurable(candidate: Measured, incumbent: Measured, min_attack_flows: int) -> str | None:
    """Why the two Contexts cannot be compared at all, or None when they can.

    Too thin a Round is a refusal and not an acceptance: a gate that waves a Context through on five attack Flows has measured nothing
    and would let the loop drift on noise for as many Rounds as the attacker cares to run.
    """
    if not candidate.flows or not incumbent.flows:
        return f"nothing to compare: {candidate.flows} candidate and {incumbent.flows} incumbent Predictions"
    attack_flows = min(candidate.attack_flows, incumbent.attack_flows)
    if attack_flows < min_attack_flows:
        return f"only {attack_flows} attack Flows judged, under the {min_attack_flows} the gate needs to tell two Contexts apart"
    return None


def guard(candidate: Measured, incumbent: Measured, paired: Discordance | None, policy: GatePolicy) -> tuple[bool, str]:
    """The guarded rule: hold recall, and spend no more than `false_alarm_slack` of new false alarms.

    A recall drop is held against the candidate only when it is both larger than `recall_slack` and more than the paired test can put
    down to chance; with the default slack of zero and a significant drop that is the strict rule, and a wobble of one or two Flows is
    no longer enough to roll a Context back. An unpaired comparison cannot call anything chance, so it falls back to the slack alone.

    Every case it cannot measure is a rejection and never a silent acceptance: a Context whose recall or whose false-alarm cost could
    not be measured has not been shown to be safe, and the cheapest safe move is to keep the Context already in force.
    """
    refused = unmeasurable(candidate, incumbent, policy.min_attack_flows)
    if refused is not None:
        return False, refused
    if candidate.recall is None or incumbent.recall is None:
        return False, "no attack Flow on one of the two sides: recall is unmeasured, so the candidate Context is not kept"
    if candidate.false_alarm_rate is None or incumbent.false_alarm_rate is None:
        return False, "no benign Flow on one of the two sides: the false-alarm cost is unmeasured, so the candidate Context is not kept"
    drop = incumbent.recall - candidate.recall
    if drop > policy.recall_slack and not chance(paired):
        return False, (
            f"recall fell from {incumbent.recall:.3f} to {candidate.recall:.3f}, {drop:.3f} past the "
            f"{policy.recall_slack:.3f} slack ({evidence(paired)})"
        )
    excess = candidate.false_alarm_rate - incumbent.false_alarm_rate
    if excess > policy.false_alarm_slack:
        return False, (
            f"false alarms rose from {incumbent.false_alarm_rate:.3f} to {candidate.false_alarm_rate:.3f}, "
            f"{excess:.3f} over the {policy.false_alarm_slack:.3f} allowed"
        )
    return True, (
        f"recall {incumbent.recall:.3f} -> {candidate.recall:.3f} ({evidence(paired)}), false alarms "
        f"{incumbent.false_alarm_rate:.3f} -> {candidate.false_alarm_rate:.3f}, within the {policy.false_alarm_slack:.3f} allowed"
    )


def integrity(candidate: Measured, max_error_rate: float) -> str | None:
    """Why the candidate Context is not a working Context at all, or None when it is.

    A Prediction whose call failed counts as `normal` (fail-open), so a Context that makes the calls themselves fail, by running past
    the model's context window or by provoking refusals, buys a perfect false-alarm rate by answering nothing. This is an integrity
    check and not a quality trade-off, so it runs in `mode="none"` as well: the poisoning experiment compares what a gate costs, not
    what a broken Context does, and a Round that stopped answering is not a result either arm should carry.
    """
    if candidate.error_rate is not None and candidate.error_rate > max_error_rate:
        return f"{candidate.error_rate:.3f} of the candidate's calls failed, over the {max_error_rate:.3f} allowed"
    return None


def evaluate(
    candidate_predictions: Sequence[Prediction], incumbent_predictions: Sequence[Prediction], *, policy: GatePolicy = DEFAULT_POLICY
) -> GateVerdict:
    """Whether the candidate Context replaces the incumbent, and why.

    `mode="guarded"` accepts only a candidate that does not lose recall it cannot be shown to have lost by chance, and does not raise
    the false-alarm rate by more than `false_alarm_slack`; anything else is rejected and the Round rolls back to the incumbent Context.

    `mode="none"` accepts everything the integrity check passes. It is not a convenience switch: the poisoning experiment replays the
    same Rounds with the gate off, so what the gate was buying is read as the difference between the two modes rather than asserted.

    Both Contexts are meant to be judged over the same held-out split, which makes the comparison paired; sides that turn out not to
    have judged the same Flows are still compared, by the slack alone, and `reason` says which rule ran.

    Args:
        candidate_predictions: the held-out Predictions under the Context the curator proposed.
        incumbent_predictions: the held-out Predictions under the Context in force.
        policy: the mode and the four thresholds to gate on; `DEFAULT_POLICY` is the guarded rule at its documented defaults.

    Returns:
        The decision, its reason and every number it was taken on; the numbers are filled in both modes, so a Run with the gate off
        still records what a guarded gate would have seen.

    Raises:
        ValueError: when the policy's mode is neither `guarded` nor `none`.
    """
    if policy.mode not in ("guarded", "none"):
        raise ValueError(f"gate mode {policy.mode!r} is not implemented: use 'guarded' or 'none'")
    candidate, incumbent = measure(candidate_predictions), measure(incumbent_predictions)
    pairs = pairing(candidate_predictions, incumbent_predictions)
    paired = None if pairs is None else discordance(pairs)
    broken = integrity(candidate, policy.max_error_rate)
    if broken is not None:
        accepted, reason = False, broken
    elif policy.mode == "none":
        accepted, reason = True, "gate off (mode=none): the candidate Context is kept whatever it measured"
    else:
        accepted, reason = guard(candidate, incumbent, paired, policy)
    return GateVerdict(
        accepted=accepted,
        reason=reason,
        candidate_recall=candidate.recall,
        incumbent_recall=incumbent.recall,
        candidate_false_alarm_rate=candidate.false_alarm_rate,
        incumbent_false_alarm_rate=incumbent.false_alarm_rate,
        candidate_f1=candidate.f1,
        incumbent_f1=incumbent.f1,
        candidate_error_rate=candidate.error_rate,
        incumbent_error_rate=incumbent.error_rate,
        mcnemar_p=None if paired is None else paired.mcnemar_p,
        candidate_only_hits=None if paired is None else paired.candidate_only,
        incumbent_only_hits=None if paired is None else paired.incumbent_only,
    )
