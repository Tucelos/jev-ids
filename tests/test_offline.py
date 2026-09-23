"""The offline Detector: the forest underneath, and the Context's hash it carries on every row."""

import pytest

from jev_ids.arena.context import Context, Rule, baseline_context
from jev_ids.detectors import random_forest
from jev_ids.detectors.offline import OfflineDetector
from tests.helpers import CONFIG, JEV_PROMPT, make_flow

TEMPLATE: str = JEV_PROMPT["text"]
# Two Flows per Category, each Category at its own value, so a forest fitted on them separates the three.
POOL = [
    make_flow(0, "normal", value="0"),
    make_flow(1, "normal", value="1"),
    make_flow(2, "dos", value="8"),
    make_flow(3, "dos", value="9"),
    make_flow(4, "probe", value="4"),
    make_flow(5, "probe", value="5"),
]
VOCABULARY = random_forest.vocabulary(POOL, CONFIG)


@pytest.fixture
def detector() -> OfflineDetector:
    """A Detector under the baseline Context."""
    return OfflineDetector(baseline_context().to_prompt(TEMPLATE), VOCABULARY, CONFIG["benign"])


def test_it_looks_like_every_other_detector_to_the_run_loop(detector: OfflineDetector) -> None:
    prompt = baseline_context().to_prompt(TEMPLATE)
    assert detector.name == "offline"
    assert detector.model == f"offline-random-forest-{random_forest.N_ESTIMATORS}"
    assert detector.prompt_hash == prompt["sha256"]


def test_it_judges_a_flow_the_way_the_random_forest_does(detector: OfflineDetector) -> None:
    normal = detector.predict(POOL[0], POOL)
    attack = detector.predict(POOL[2], POOL)
    assert set(normal) == {"p_attack", "category_pred", "latency_ms", "train_time_ms", "prompt_hash"}
    assert 0.0 <= normal["p_attack"] < 0.5 < attack["p_attack"] <= 1.0
    assert attack["category_pred"] == "dos"
    assert normal["latency_ms"] > 0


def test_every_row_carries_the_hash_of_the_context_in_force() -> None:
    playbook = (Rule(id="r1", text="Nine bytes in every column is a denial of service.", added_round=1),)
    baseline = OfflineDetector(baseline_context().to_prompt(TEMPLATE), VOCABULARY, CONFIG["benign"])
    curated = OfflineDetector(Context(version=1, rules=playbook).to_prompt(TEMPLATE), VOCABULARY, CONFIG["benign"])

    before = baseline.predict(POOL[2], POOL)
    after = curated.predict(POOL[2], POOL)

    # The Context reaches the row, which is the whole point of this Detector; what it does not reach is the answer, because a forest
    # cannot read a playbook and this Detector therefore measures nothing.
    assert before["prompt_hash"] != after["prompt_hash"]
    assert before["p_attack"] == after["p_attack"]


def test_the_forest_underneath_is_fitted_once_per_examples_list(detector: OfflineDetector) -> None:
    examples = list(POOL)
    detector.predict(POOL[0], examples)
    detector.predict(POOL[4], examples)
    assert detector.forest.fit_count == 1
    detector.predict(POOL[0], list(POOL))
    assert detector.forest.fit_count == 2


def test_it_needs_examples_like_the_forest_it_wraps(detector: OfflineDetector) -> None:
    with pytest.raises(ValueError, match="k >= 1"):
        detector.predict(POOL[0], [])
