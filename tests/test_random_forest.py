"""Random Forest detector: vocabulary, vectors, fitting once and outcomes."""

from __future__ import annotations

import pytest

from somids import dataset
from somids.detectors import random_forest as rf

BASE = ["0"] * len(dataset.COLUMNS)


def flow(
    row_id: int, name: str, symbolic: tuple[str, str, str], bytes_: str
) -> dataset.Flow:
    values = list(BASE)
    values[1:4] = list(symbolic)
    values[4] = bytes_
    return dataset.Flow(
        row_id=row_id, text=",".join(values), attack_name=name, difficulty=1
    )


TRAIN = [
    flow(0, "normal", ("tcp", "http", "SF"), "300"),
    flow(1, "normal", ("tcp", "http", "SF"), "250"),
    flow(2, "neptune", ("tcp", "private", "S0"), "0"),
    flow(3, "neptune", ("tcp", "private", "REJ"), "0"),
    flow(4, "satan", ("icmp", "eco_i", "SF"), "8"),
    flow(5, "satan", ("udp", "other", "SF"), "1"),
    flow(6, "guess_passwd", ("tcp", "telnet", "SF"), "120"),
    flow(7, "guess_passwd", ("tcp", "telnet", "RSTO"), "130"),
    flow(8, "perl", ("tcp", "telnet", "SF"), "1500"),
    flow(9, "perl", ("tcp", "telnet", "SF"), "1600"),
]


def test_vocabulary_and_vector_shape() -> None:
    vocabulary = rf.Vocabulary.from_flows(TRAIN)
    assert vocabulary.values["protocol_type"] == ("icmp", "tcp", "udp")
    assert vocabulary.width == 38 + 3 + 5 + 4
    vector = vocabulary.vector(TRAIN[4])
    assert len(vector) == vocabulary.width
    assert vector[:2] == [0.0, 8.0]
    assert vector[38:41] == [1.0, 0.0, 0.0]
    unseen = vocabulary.vector(flow(99, "normal", ("sctp", "http", "SF"), "1"))
    assert unseen[38:41] == [0.0, 0.0, 0.0]


def test_predict_fits_once_per_examples_object_and_derives_p_attack() -> None:
    detector = rf.RandomForestDetector(rf.Vocabulary.from_flows(TRAIN), n_estimators=10)
    examples = dataset.sample_examples(TRAIN, 2, seed=0)

    first = detector.predict([TRAIN[0], TRAIN[2]], examples)
    second = detector.predict([TRAIN[8]], examples)

    assert detector.fits == 1
    assert detector.model == "sklearn-random-forest-10"
    normal, attack = first
    assert normal.probabilities is not None
    assert sum(normal.probabilities.values()) == pytest.approx(1.0)
    assert normal.p_attack == pytest.approx(1.0 - normal.probabilities["normal"])
    assert attack.p_attack is not None and attack.p_attack > 0.5
    assert attack.category_pred == "dos"
    assert normal.train_time_ms == second[0].train_time_ms
    assert normal.latency_e2e_ms is not None
    assert normal.cost_usd is None
    assert normal.request_id == attack.request_id != second[0].request_id
    detector.predict([TRAIN[0]], dataset.sample_examples(TRAIN, 1, seed=1))
    assert detector.fits == 2


def test_fit_rejects_zero_shot() -> None:
    detector = rf.RandomForestDetector(rf.Vocabulary.from_flows(TRAIN))
    with pytest.raises(ValueError, match="k >= 1"):
        detector.predict([TRAIN[0]], [])
