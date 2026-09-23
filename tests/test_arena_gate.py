"""The acceptance gate over synthetic Predictions: the Contexts it keeps, the ones it rolls back, and the noise it no longer chases."""

import pytest

from jev_ids import metrics
from jev_ids.arena import gate
from jev_ids.records import Prediction
from tests.helpers import make_prediction

# A held-out Round shaped like `arena-val`: more benign Flows than attack ones, and enough attack Flows to clear `min_attack_flows`.
ATTACK_FLOWS = 40
BENIGN_FLOWS = 60


def benign_p_attack(index: int, false_alarms: int, failures: int) -> float | None:
    """p_attack of one benign Flow: a false alarm, a call that failed, or quiet traffic."""
    if index < false_alarms:
        return 0.9
    if index >= BENIGN_FLOWS - failures:
        return None
    return 0.1


def benign_flow(row_id: int, p_attack: float | None, *, fail_closed: bool) -> Prediction:
    """One benign Flow's Prediction; a call that failed carries an `error`, and under fail-closed it is recorded as an alert."""
    if p_attack is not None:
        return make_prediction(row_id, 0, p_attack)
    failed = make_prediction(row_id, 0, None, error="HTTP 429")
    if fail_closed:
        failed["classification_verdict"] = 1  # THREAT A3's fail-closed arm: no answer is treated as an alert
    return failed


def judged(attack_hits: int, false_alarms: int = 0, failures: int = 0, shift: int = 0, fail_closed: bool = False) -> list[Prediction]:
    """One Context's Round over the same hundred Flows, so two of them pair Flow by Flow.

    The first `attack_hits` attack Flows are alerted on and the rest missed; `false_alarms` benign Flows are alerted on and `failures`
    of them come back from a failed call, fail-open unless `fail_closed`. `shift` moves every row_id, which is how a test makes two
    Rounds unpairable.
    """
    attacks = [make_prediction(shift + index, 1, 0.9 if index < attack_hits else 0.1) for index in range(ATTACK_FLOWS)]
    benign = [
        benign_flow(shift + ATTACK_FLOWS + index, benign_p_attack(index, false_alarms, failures), fail_closed=fail_closed)
        for index in range(BENIGN_FLOWS)
    ]
    return attacks + benign


INCUMBENT = judged(20)  # recall 0.5, no false alarm, no failed call


def test_evaluate_accepts_a_context_that_finds_more_attacks_at_the_same_cost() -> None:
    verdict = gate.evaluate(judged(30), INCUMBENT)
    assert verdict.accepted
    assert (verdict.candidate_recall, verdict.incumbent_recall) == (0.75, 0.5)
    assert (verdict.candidate_false_alarm_rate, verdict.incumbent_false_alarm_rate) == (0.0, 0.0)
    assert verdict.candidate_f1 == pytest.approx(2 * 30 / (30 + 40))
    assert verdict.incumbent_f1 == pytest.approx(2 * 20 / (20 + 40))
    assert (verdict.candidate_only_hits, verdict.incumbent_only_hits) == (10, 0)
    assert verdict.mcnemar_p == pytest.approx(2 / 2**10)
    assert "paired: McNemar" in verdict.reason
    # Recall that merely holds is enough; the gate asks for no improvement, only for no loss it can prove.
    assert gate.evaluate(INCUMBENT, INCUMBENT).accepted


def test_evaluate_rejects_a_recall_drop_the_paired_test_calls_real() -> None:
    # Six attack Flows lost and none gained: p = 0.031, past the 0.05 the gate calls chance.
    verdict = gate.evaluate(judged(20), judged(26))
    assert not verdict.accepted
    assert (verdict.candidate_only_hits, verdict.incumbent_only_hits) == (0, 6)
    assert verdict.mcnemar_p == pytest.approx(2 / 2**6)
    assert verdict.reason.startswith("recall fell from 0.650 to 0.500")
    assert "paired: McNemar p=0.031 over 0 gained and 6 lost attack Flows" in verdict.reason


def test_a_recall_wobble_inside_the_noise_no_longer_rolls_a_context_back() -> None:
    # Four attack Flows lost and none gained: the same two Contexts would do this again by chance (p = 0.125), so it is not held
    # against the candidate even though recall fell and the slack is zero.
    verdict = gate.evaluate(judged(20), judged(24))
    assert verdict.accepted
    assert (verdict.candidate_recall, verdict.incumbent_recall) == (0.5, 0.6)  # recall really did fall
    assert verdict.mcnemar_p == pytest.approx(2 / 2**4)
    assert "recall 0.600 -> 0.500" in verdict.reason


def test_recall_slack_buys_a_drop_the_paired_test_does_call_real() -> None:
    lost_six = (judged(20), judged(26))  # a drop of 0.15 at p = 0.031
    assert not gate.evaluate(*lost_six).accepted
    assert not gate.evaluate(*lost_six, policy=gate.GatePolicy(recall_slack=0.1)).accepted
    assert gate.evaluate(*lost_six, policy=gate.GatePolicy(recall_slack=0.2)).accepted


def test_evaluate_rejects_the_context_that_alerts_on_everything() -> None:
    # The failure mode the gate exists for: recall 1.0 looks like progress, and every legitimate Flow is now an alert.
    verdict = gate.evaluate(judged(ATTACK_FLOWS, false_alarms=BENIGN_FLOWS), INCUMBENT)
    assert not verdict.accepted
    assert (verdict.candidate_recall, verdict.candidate_false_alarm_rate) == (1.0, 1.0)
    assert "false alarms rose from 0.000 to 1.000" in verdict.reason
    assert "over the 0.020 allowed" in verdict.reason


def test_evaluate_spends_the_false_alarm_slack_and_no_more() -> None:
    # Three false alarms among sixty benign Flows: five percentage points, with recall untouched.
    candidate = judged(20, false_alarms=3)
    assert gate.evaluate(candidate, INCUMBENT).candidate_false_alarm_rate == 0.05
    assert not gate.evaluate(candidate, INCUMBENT).accepted
    # The rule is "by more than the slack", so the rise that exactly fills it is still bought.
    assert gate.evaluate(candidate, INCUMBENT, policy=gate.GatePolicy(false_alarm_slack=0.05)).accepted
    assert gate.evaluate(candidate, INCUMBENT, policy=gate.GatePolicy(false_alarm_slack=0.10)).accepted


def test_a_context_whose_calls_fail_is_refused_in_both_modes() -> None:
    # Six of the hundred calls come back without a Verdict. Fail-open counts them as `normal`, so they cost the candidate nothing on
    # recall or on false alarms; only the integrity check sees them.
    broken = judged(20, failures=6)
    assert gate.evaluate(broken, INCUMBENT).candidate_error_rate == 0.06
    assert gate.evaluate(broken, INCUMBENT).candidate_false_alarm_rate == 0.0
    for verdict in (gate.evaluate(broken, INCUMBENT), gate.evaluate(broken, INCUMBENT, policy=gate.GatePolicy(mode="none"))):
        assert not verdict.accepted
        assert verdict.reason == "0.060 of the candidate's calls failed, over the 0.050 allowed"
    # Under the bar it is a working Context again, and a wider bar lets this one through.
    assert gate.evaluate(judged(20, failures=4), INCUMBENT).accepted
    assert gate.evaluate(broken, INCUMBENT, policy=gate.GatePolicy(max_error_rate=0.1)).accepted
    # A Round where nothing failed is untouched by the check.
    assert gate.measure(INCUMBENT).error_rate == 0.0
    assert gate.evaluate(INCUMBENT, INCUMBENT).accepted


def test_a_fail_closed_context_whose_calls_fail_is_caught_by_the_error_field() -> None:
    # THREAT A3's fail-closed arm records a failed call as an alert, so the Verdict is there and `metrics.scores` sees no error at all.
    # Counting the missing Verdict would let a Context that answers nothing through the gate in the arm built to study that.
    broken = judged(20, failures=6, fail_closed=True)
    assert metrics.scores(broken)["error_rate"] == 0.0
    assert gate.measure(broken).error_rate == 0.06
    for verdict in (gate.evaluate(broken, INCUMBENT), gate.evaluate(broken, INCUMBENT, policy=gate.GatePolicy(mode="none"))):
        assert not verdict.accepted
        assert verdict.reason == "0.060 of the candidate's calls failed, over the 0.050 allowed"
    # Fail-closed turns the six failures into false alarms too, but integrity runs first and names the real cause.
    assert gate.measure(broken).false_alarm_rate == 0.1


def test_predictions_without_an_error_field_fall_back_to_the_missing_verdict() -> None:
    legacy = [make_prediction(index, 0, None if index < 3 else 0.1) for index in range(10)]
    for row in legacy:
        del row["error"]
    assert gate.measure(legacy).error_rate == 0.3
    # With the field present and empty the field wins: these rows carry no error, so they really did answer.
    assert gate.measure([make_prediction(index, 0, None) for index in range(10)]).error_rate == 0.0


def test_too_few_attack_flows_is_a_refusal_rather_than_a_measurement() -> None:
    thin_candidate = [make_prediction(index, int(index < 4), 0.9) for index in range(10)]
    thin_incumbent = [make_prediction(index, int(index < 4), 0.9) for index in range(10)]
    verdict = gate.evaluate(thin_candidate, thin_incumbent)
    assert not verdict.accepted
    assert verdict.reason == "only 4 attack Flows judged, under the 30 the gate needs to tell two Contexts apart"
    # An experiment that knows its Round is small can lower the bar and be measured on it.
    assert gate.evaluate(thin_candidate, thin_incumbent, policy=gate.GatePolicy(min_attack_flows=4)).accepted


def test_sides_that_judged_different_flows_fall_back_to_the_unpaired_rule() -> None:
    verdict = gate.evaluate(judged(20, shift=1000), judged(26))
    assert not verdict.accepted
    assert (verdict.mcnemar_p, verdict.candidate_only_hits, verdict.incumbent_only_hits) == (None, None, None)
    assert "unpaired: the two sides judged different Flows" in verdict.reason
    # Without the test, the wobble the paired rule forgave is rejected on the slack alone.
    assert not gate.evaluate(judged(20, shift=1000), judged(24)).accepted
    # A candidate judged over a subset of the incumbent's Flows is unpaired too: the two recalls would span two populations.
    assert gate.evaluate(judged(20)[:50], INCUMBENT).mcnemar_p is None


def test_mode_none_keeps_the_context_the_guarded_gate_rolls_back() -> None:
    candidate = judged(ATTACK_FLOWS, false_alarms=BENIGN_FLOWS)
    verdict = gate.evaluate(candidate, INCUMBENT, policy=gate.GatePolicy(mode="none"))
    assert verdict.accepted
    assert "mode=none" in verdict.reason
    # The numbers are still measured with the gate off, so the damage is on the record either way.
    assert (verdict.candidate_recall, verdict.candidate_false_alarm_rate) == (1.0, 1.0)
    assert verdict.mcnemar_p is not None
    # Even an empty Round is kept: that is what the poisoning experiment is comparing against.
    assert gate.evaluate([], [], policy=gate.GatePolicy(mode="none")).accepted


def test_evaluate_rejects_rather_than_guess_when_a_side_judged_nothing() -> None:
    empty = gate.evaluate([], INCUMBENT)
    assert not empty.accepted
    assert empty.reason == "nothing to compare: 0 candidate and 100 incumbent Predictions"
    assert (empty.candidate_recall, empty.candidate_false_alarm_rate, empty.candidate_f1) == (None, None, None)
    assert (empty.candidate_error_rate, empty.incumbent_error_rate) == (None, 0.0)
    assert not gate.evaluate(INCUMBENT, []).accepted


def test_evaluate_rejects_a_round_without_an_attack_flow_or_without_a_benign_one() -> None:
    benign_only = [make_prediction(index, 0, 0.1) for index in range(40)]
    # With the bar in place a Round of nothing but benign Flows is refused for want of evidence; drop the bar and the precise reason
    # surfaces, because recall over no attack Flow is not a recall.
    assert gate.evaluate(benign_only, benign_only).reason.startswith("only 0 attack Flows judged")
    no_attack = gate.evaluate(benign_only, benign_only, policy=gate.GatePolicy(min_attack_flows=0))
    assert not no_attack.accepted
    assert no_attack.reason.startswith("no attack Flow on one of the two sides")
    assert no_attack.candidate_recall is None
    attack_only = [make_prediction(index, 1, 0.9) for index in range(40)]
    no_benign = gate.evaluate(attack_only, attack_only)
    assert not no_benign.accepted
    assert no_benign.reason.startswith("no benign Flow on one of the two sides")
    assert (no_benign.candidate_recall, no_benign.candidate_false_alarm_rate) == (1.0, None)
    # One side alone is enough to leave the comparison unmeasured.
    assert not gate.evaluate(attack_only, INCUMBENT).accepted
    assert not gate.evaluate(benign_only, INCUMBENT).accepted


def test_an_unknown_mode_is_refused_rather_than_read_as_one_of_the_two() -> None:
    with pytest.raises(ValueError, match="gate mode 'lenient' is not implemented"):
        gate.evaluate(INCUMBENT, INCUMBENT, policy=gate.GatePolicy(mode="lenient"))


def test_a_failed_call_is_not_a_false_alarm() -> None:
    # A Prediction without a Verdict counts as `normal`: fail-open, so it costs the benign Flows nothing, and `integrity` is the only
    # thing standing between that and a Context that scores well by answering nothing.
    failed = [make_prediction(index, 0, None, error="boom") for index in range(10)]
    assert gate.false_alarm_rate(failed) == 0.0
    assert gate.false_alarm_rate([]) is None
    assert gate.measure(failed).flows == 10
    assert gate.measure(failed).error_rate == 1.0
    assert gate.measure(failed).attack_flows == 0
