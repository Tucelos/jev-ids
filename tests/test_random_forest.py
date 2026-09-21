"""Random Forest detector: vocabulary by index, vectors, fitting once, predictions."""

import pytest

from somids.dataset import Flow
from somids.detectors import random_forest as rf
from somids.run import sample_examples
from tests.helpers import CONFIG

CATEGORIES: list[str] = CONFIG["categories"]


def flow(row_id: int, category: str, symbolic: str, bytes_: str) -> Flow:
    """A Flow of CONFIG: `a` is bytes_, `b` (symbolic) is symbolic, `c` is 0."""
    return Flow(row_id, f"{bytes_},{symbolic},0", category, category != "normal")


TRAIN = [
    flow(0, "normal", "tcp", "300"),
    flow(1, "normal", "tcp", "250"),
    flow(2, "dos", "tcp", "0"),
    flow(3, "dos", "udp", "0"),
    flow(4, "probe", "icmp", "8"),
    flow(5, "probe", "udp", "1"),
]
VOCABULARY = rf.vocabulary(TRAIN, CONFIG)


def test_vocabulary_and_vector_shape() -> None:
    assert VOCABULARY == {1: ("icmp", "tcp", "udp")}
    # The two numeric features in order, then one column per known value of `b`.
    assert rf.feature_vector(TRAIN[4], VOCABULARY) == [8.0, 0.0, 1.0, 0.0, 0.0]
    unseen = rf.feature_vector(flow(99, "normal", "sctp", "1"), VOCABULARY)
    assert unseen == [1.0, 0.0, 0.0, 0.0, 0.0]


def test_predict_fits_once_per_examples_object_and_derives_p_attack() -> None:
    detector = rf.RandomForestDetector(VOCABULARY, "normal")
    examples = sample_examples(TRAIN, 2, 0, CATEGORIES)

    normal = detector.predict(TRAIN[0], examples)
    attack = detector.predict(TRAIN[2], examples)
    second = detector.predict(TRAIN[4], examples)

    assert detector.fits == 1
    assert (detector.name, detector.model) == ("rf", f"sklearn-random-forest-{rf.N_ESTIMATORS}")
    assert detector.prompt_hash is None
    assert set(normal) == {"p_attack", "category_pred", "latency_ms", "train_time_ms"}
    assert 0.0 <= normal["p_attack"] < 0.5 < attack["p_attack"] <= 1.0
    assert attack["category_pred"] == "dos"
    assert normal["train_time_ms"] == second["train_time_ms"] > 0
    assert normal["latency_ms"] > 0
    detector.predict(TRAIN[0], sample_examples(TRAIN, 1, 1, CATEGORIES))
    assert detector.fits == 2


def test_fit_rejects_zero_shot() -> None:
    detector = rf.RandomForestDetector(VOCABULARY, "normal")
    with pytest.raises(ValueError, match="k >= 1"):
        detector.predict(TRAIN[0], [])
