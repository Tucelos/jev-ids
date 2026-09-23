"""The Budget: what it books, what it refuses, and what it tells the Run record."""

import pytest

from jev_ids.arena.budget import Budget, BudgetExhausted


def test_spending_moves_one_counter_and_leaves_the_other() -> None:
    budget = Budget(max_detector_calls=10, max_curator_calls=2)
    budget.spend_detector(4)
    budget.spend_detector()
    budget.spend_curator()
    assert budget.remaining == {"detector_calls": 5, "curator_calls": 1}


def test_a_cap_may_be_reached_exactly_and_not_passed() -> None:
    budget = Budget(max_detector_calls=3, max_curator_calls=1)
    budget.spend_detector(3)
    assert budget.remaining["detector_calls"] == 0
    with pytest.raises(BudgetExhausted, match="detector_calls: 3 of 3 spent, 1 more asked"):
        budget.spend_detector()


def test_a_batch_that_does_not_fit_is_refused_whole() -> None:
    budget = Budget(max_detector_calls=10, max_curator_calls=10)
    budget.spend_detector(8)
    with pytest.raises(BudgetExhausted, match="8 of 10 spent, 3 more asked"):
        budget.spend_detector(3)
    # The attacker asked for three probes and got none: a half-spent batch would leave the Round counting calls it never made.
    assert budget.remaining["detector_calls"] == 2
    budget.spend_detector(2)
    assert budget.remaining["detector_calls"] == 0


def test_the_curator_has_its_own_wall() -> None:
    budget = Budget(max_detector_calls=100, max_curator_calls=2)
    budget.spend_curator(2)
    with pytest.raises(BudgetExhausted, match="curator_calls"):
        budget.spend_curator()
    assert budget.remaining["detector_calls"] == 100


def test_the_snapshot_holds_both_caps_and_what_went_against_them() -> None:
    budget = Budget(max_detector_calls=20000, max_curator_calls=200)
    budget.spend_detector(1350)
    budget.spend_curator(4)
    assert budget.snapshot() == {
        "detector_calls": 1350,
        "max_detector_calls": 20000,
        "curator_calls": 4,
        "max_curator_calls": 200,
    }


def test_two_budgets_do_not_share_credits() -> None:
    # No module-level counter: two Runs in one process must not eat each other's calls.
    first, second = Budget(5, 5), Budget(5, 5)
    first.spend_detector(5)
    second.spend_detector(1)
    assert (first.remaining["detector_calls"], second.remaining["detector_calls"]) == (0, 4)
