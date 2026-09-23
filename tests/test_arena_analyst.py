"""The simulated analyst over synthetic Predictions: what it reaches, what it reports, what a delay hides, what poisoning flips."""

import random

from jev_ids.arena import analyst
from jev_ids.arena.analyst import AnalystParams, Feedback
from tests.helpers import make_prediction

CATEGORIES = ("normal", "dos", "probe")


def stream(seed: int) -> random.Random:
    """The Run's random stream, as the round loop would hand it over: seeded, never the global `random`."""
    return random.Random(seed)  # noqa: S311  # seeded, not secret


def params(alert_budget: int = 100, sample_rate: float = 0.0, label_noise: float = 0.0) -> AnalystParams:
    """An analyst over the three Categories of the test card, generous unless a test narrows it."""
    return AnalystParams(categories=CATEGORIES, alert_budget=alert_budget, sample_rate=sample_rate, label_noise=label_noise)


def observed(row_id: int, observed_round: int, category: str = "dos") -> Feedback:
    """One Feedback as `review` would have written it for a reviewed alert: honest, untouched, and right."""
    return Feedback(row_id=row_id, observed_round=observed_round, true_category=category, detector_verdict=1, p_attack=0.9, label=category)


def test_review_reaches_the_highest_scoring_alerts_and_drops_the_tail_of_the_queue() -> None:
    alerts = [make_prediction(index, 1, p_attack) for index, p_attack in enumerate([0.6, 0.95, 0.75, 0.55])]
    feedback = analyst.review(alerts, 0, params(alert_budget=2), stream(0))
    # A queue ranked by score: the budget buys 0.95 and 0.75, and 0.6 and 0.55 are never looked at.
    assert [item.row_id for item in feedback] == [1, 2]
    assert [item.detector_verdict for item in feedback] == [1, 1]
    assert [item.p_attack for item in feedback] == [0.95, 0.75]
    # A budget wider than the queue reviews every alert; an empty Round gives nothing.
    assert len(analyst.review(alerts, 0, params(), stream(0))) == 4
    assert analyst.review([], 0, params(), stream(0)) == []


def test_review_samples_a_share_of_the_flows_the_detector_stayed_quiet_on() -> None:
    # Ten attack Flows the Detector missed: without the sampling channel the curator would never hear of any of them.
    missed = [make_prediction(index, 1, 0.1) for index in range(10)]
    feedback = analyst.review(missed, 0, params(sample_rate=0.4), stream(7))
    assert len(feedback) == 4
    assert {item.detector_verdict for item in feedback} == {0}
    assert {item.true_category for item in feedback} == {"dos"}
    # The same stream replays the same draw; another stream reaches other Flows.
    replayed = analyst.review(missed, 0, params(sample_rate=0.4), stream(7))
    assert [item.row_id for item in replayed] == [item.row_id for item in feedback]
    other = analyst.review(missed, 0, params(sample_rate=0.4), stream(8))
    assert [item.row_id for item in other] != [item.row_id for item in feedback]
    # Without the channel the loop is an echo chamber: the alerts alone, and here there are none.
    assert analyst.review(missed, 0, params(), stream(7)) == []


def test_review_treats_a_failed_call_as_a_quiet_flow_and_stamps_the_round() -> None:
    rows = [make_prediction(0, 1, None), make_prediction(1, 1, 0.9), make_prediction(2, 0, 0.1)]
    feedback = {item.row_id: item for item in analyst.review(rows, 3, params(sample_rate=1.0), stream(0))}
    assert len(feedback) == 3
    # No Verdict is `normal` (fail-open), so the failed call is reviewed through the sampling channel, not the alert queue.
    assert (feedback[0].detector_verdict, feedback[0].p_attack) == (0, None)
    assert (feedback[1].detector_verdict, feedback[1].p_attack) == (1, 0.9)
    assert (feedback[2].true_category, feedback[2].label) == ("normal", "normal")
    assert {item.observed_round for item in feedback.values()} == {3}
    assert not any(item.poisoned for item in feedback.values())


def test_label_noise_reports_another_category_and_replays_from_the_seed() -> None:
    alerts = [make_prediction(index, 1, 0.9) for index in range(40)]
    noisy = params(label_noise=0.5)
    first = analyst.review(alerts, 0, noisy, stream(11))
    second = analyst.review(alerts, 0, noisy, stream(11))
    assert [item.label for item in first] == [item.label for item in second]
    wrong = [item for item in first if item.label != item.true_category]
    # Forty coins at one half: a count outside this band would be a broken draw, not bad luck.
    assert 8 < len(wrong) < 32
    assert {item.true_category for item in first} == {"dos"}
    assert {item.label for item in wrong} <= {"normal", "probe"}
    # Without noise the analyst reports the truth of every Flow it reviewed.
    honest = analyst.review(alerts, 0, params(), stream(11))
    assert all(item.label == item.true_category for item in honest)


def test_label_noise_has_nothing_to_report_on_a_card_of_one_category() -> None:
    alerts = [make_prediction(index, 1, 0.9) for index in range(5)]
    single = AnalystParams(categories=("dos",), alert_budget=5, sample_rate=0.0, label_noise=1.0)
    assert all(item.label == "dos" for item in analyst.review(alerts, 0, single, stream(0)))


def test_delay_hides_the_feedback_a_curator_could_not_have_had_yet() -> None:
    history = [observed(index, index) for index in range(5)]
    assert [item.observed_round for item in analyst.delay(history, 4, 0)] == [0, 1, 2, 3, 4]
    assert [item.observed_round for item in analyst.delay(history, 4, 2)] == [0, 1, 2]
    # Early on, a curator two Rounds behind has nothing at all to learn from.
    assert analyst.delay(history, 1, 2) == []
    assert analyst.delay([], 4, 1) == []


def test_poison_flips_only_the_attack_feedback_and_leaves_the_given_entries_alone() -> None:
    history = [*(observed(index, 0) for index in range(4)), observed(4, 0, "normal"), observed(5, 0, "normal")]
    tampered = analyst.poison(history, 0.5, "normal", stream(3))
    flipped = [item for item in tampered if item.poisoned]
    assert len(flipped) == 2  # half of the four attack entries
    assert {item.label for item in flipped} == {"normal"}
    assert {item.true_category for item in flipped} == {"dos"}
    # The benign Feedback is of no use to the adversary and is left as it was.
    assert [item.poisoned for item in tampered[4:]] == [False, False]
    # Order is kept, so a Feedback history stays aligned with the Rounds it came from, and the given entries are untouched.
    assert [item.row_id for item in tampered] == [item.row_id for item in history]
    assert not any(item.poisoned for item in history)
    assert {item.label for item in history} == {"dos", "normal"}


def test_poison_of_nothing_changes_nothing_and_a_full_fraction_flips_every_attack() -> None:
    history = [observed(0, 0), observed(1, 0), observed(2, 0, "normal")]
    assert analyst.poison(history, 0.0, "normal", stream(0)) == history
    whole = analyst.poison(history, 1.0, "normal", stream(0))
    assert [item.poisoned for item in whole] == [True, True, False]
    assert [item.label for item in whole] == ["normal", "normal", "normal"]
    # The truth survives the flip, which is how the experiment measures the damage the curator cannot see.
    assert [item.true_category for item in whole] == ["dos", "dos", "normal"]
    assert analyst.poison([], 1.0, "normal", stream(0)) == []


def test_for_curator_hands_over_the_label_and_keeps_the_truth_and_the_tampering_back() -> None:
    poisoned = analyst.poison([observed(0, 0), observed(1, 0, "normal")], 1.0, "normal", stream(0))
    shown = analyst.for_curator(poisoned)
    # Exactly four keys, the same ones for every entry: neither the truth the analyst never reported nor the fact of the tampering.
    assert [set(entry) for entry in shown] == [{"row_id", "label", "detector_verdict", "p_attack"}] * 2
    assert all("poisoned" not in entry and "true_category" not in entry for entry in shown)
    assert "dos" not in str(shown)  # the poisoned entry really is a dos Flow, and nothing in what is handed over says so
    assert shown[0] == {"row_id": 0, "label": "normal", "detector_verdict": 1, "p_attack": 0.9}
    # Order and length are kept, so the curator sees exactly the Feedback the Run decided it may have.
    assert [entry["row_id"] for entry in shown] == [0, 1]
    assert analyst.for_curator([]) == []
