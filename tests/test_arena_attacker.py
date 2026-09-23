"""The evasive attacker over synthetic Pools: what it may copy, what it may never touch, and what it is allowed to know.

The Card and the constraint model are the committed ones, so the roles, the lever bounds and the admissible symbolic combinations under
test are the real ones. The Flows are synthetic and tiny: the Pool is gitignored, and a donor only has to be a real-shaped record here, not
a real one.

No network and no key: the Judge is a stand-in that alerts until a condition the test names.
"""

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from random import Random
from typing import Any

import pytest

from jev_ids import ROOT
from jev_ids.arena import attacker
from jev_ids.arena.attacker import Donors, Evasion, MimicryAttacker, Strategy
from jev_ids.dataset import Flow, load_config
from jev_ids.records import Prediction

CARD = load_config(ROOT / "data" / "nsl-kdd" / "dataset.json")
CONSTRAINTS = attacker.load_constraints(CARD)
FEATURES: tuple[str, ...] = tuple(CARD["features"])
POSITIONS = {name: index for index, name in enumerate(FEATURES)}

DERIVED_R2L = CONSTRAINTS.derived_features("r2l")
MOVED_R2L = CONSTRAINTS.transplanted("r2l")
FIXED_R2L = tuple(name for name in FEATURES if CONSTRAINTS.role(name, "r2l") == "fixed")
# The transplanted features a donor below carries a per-donor marker in, so one emitted block can be traced back to one donor. The four
# the buckets and the filters read are pinned to fixed values instead, and `flag` has to stay a flag the Pool has seen.
MARKED = tuple(name for name in MOVED_R2L if name not in ("count", "srv_count", "same_srv_rate", "srv_diff_host_rate", "flag"))


def seeded(seed: int) -> Random:
    """The generator one call to `apply` draws its donor with; every draw in these tests replays from its seed."""
    return Random(seed)  # noqa: S311  # seeded, not secret


def csv_of(values: Mapping[str, str]) -> str:
    """One Flow's 41 attributes in Card order; anything unnamed is `0`."""
    return ",".join(values.get(name, "0") for name in FEATURES)


def attack_flow(row_id: int = 1, category: str = "r2l", **overrides: str) -> Flow:
    """A guess_passwd-shaped attack Flow: telnet over tcp, one failed login, a reply from the server, saturated host windows.

    `dst_host_count` and `dst_host_srv_count` sit at 255 because every arena r2l Flow does, and the donors below have to fit under them.
    """
    values = {
        "protocol_type": "tcp",
        "service": "telnet",
        "flag": "RSTO",
        "duration": "0",
        "src_bytes": "126",
        "dst_bytes": "1200",
        "hot": "1",
        "num_failed_logins": "1",
        "count": "5",
        "srv_count": "5",
        "same_srv_rate": "1.00",
        "srv_diff_host_rate": "0.00",
        "dst_host_count": "255",
        "dst_host_srv_count": "255",
        **overrides,
    }
    return Flow(row_id=row_id, attributes_csv=csv_of(values), category=category, is_attack=category != "normal")


def donor_flow(row_id: int, marker: str, **overrides: str) -> Flow:
    """A benign Flow whose whole transplantable block carries `marker`, except the values the buckets and the filters read.

    The service is the attack Flow's own, because a donor that does not share it is not a candidate at all.
    """
    values = dict.fromkeys(DERIVED_R2L, marker)
    values.update(
        {
            "protocol_type": "tcp",
            "service": "telnet",
            "flag": "SF",
            "count": "1",
            "srv_count": "1",
            "same_srv_rate": "1.00",
            "srv_diff_host_rate": "0.00",
        }
    )
    values.update(overrides)
    return Flow(row_id=row_id, attributes_csv=csv_of(values), category="normal", is_attack=False)


def block_of(flow: Flow, category: str = "r2l") -> tuple[str, ...]:
    """The block of one Flow that travels from a donor as one bundle."""
    values = flow.attribute_values
    return tuple(values[POSITIONS[name]] for name in CONSTRAINTS.transplanted(category))


def value_of(flow: Flow, feature: str) -> str:
    """One feature of one Flow, by name."""
    return flow.attribute_values[POSITIONS[feature]]


def donors_of(*flows: Flow) -> Donors:
    """The donors a handful of benign Flows make, under the committed constraint model."""
    return attacker.build_donors(flows, CARD, CONSTRAINTS)


def bucket_of(flow: Flow) -> str:
    """The bucket one donor Flow falls in."""
    return attacker.bucket_of(flow.attribute_values, POSITIONS)


class FakeJudge:
    """A Detector that alerts on every Flow until `quiet` says otherwise, and remembers every Flow it was shown."""

    def __init__(self, quiet: Callable[[Flow], bool] | None = None, p_attack: Callable[[Flow], float] | None = None) -> None:
        """Keep the two rules and start the log; both rules default to "always an alert, plainly"."""
        self.seen: list[Flow] = []
        self._quiet = quiet
        self._p_attack = p_attack

    def __call__(self, flow: Flow) -> Prediction:
        """Judge one probe: the Verdict comes from `quiet` alone, so p_attack can be moved without moving the Verdict."""
        self.seen.append(flow)
        calm = self._quiet(flow) if self._quiet else False
        p_attack = self._p_attack(flow) if self._p_attack else (0.2 if calm else 0.9)
        return {"p_attack": p_attack, "classification_verdict": int(not calm)}

    @property
    def probed(self) -> list[str]:
        """Every probe's attributes, the sequence a search is pinned by."""
        return [flow.attributes_csv for flow in self.seen]


# Three donors in three different behaviour buckets, all quiet enough for the attack Flows above to reach.
DONOR_SAME = donor_flow(101, "11", srv_diff_host_rate="0.00")
DONOR_SOME = donor_flow(102, "22", srv_diff_host_rate="0.40")
DONOR_MANY = donor_flow(103, "33", srv_diff_host_rate="1.00")
DONORS = donors_of(DONOR_SAME, DONOR_SOME, DONOR_MANY)


def evade(judge: FakeJudge, flow: Flow | None = None, observes: str = "verdict", max_queries: int = 30) -> Evasion:
    """One attacker's whole search over one Flow, with the three donors above."""
    return MimicryAttacker(DONORS, observes=observes, seed=0).evade(flow or attack_flow(), judge, max_queries)


def test_a_strategy_transfers_to_a_different_flow_deterministically() -> None:
    found = evade(FakeJudge()).strategy
    assert found is not None
    # The gate replays the finding on Flows the curator never saw; a Flow with a different row_id, a different window and a different
    # payload is the point of the exercise.
    held_out = attack_flow(row_id=77, count="9", srv_count="9", src_bytes="300", hot="2")
    once = attacker.apply(held_out, found, DONORS, seeded(7))
    twice = attacker.apply(held_out, found, DONORS, seeded(7))
    assert once.attributes_csv == twice.attributes_csv
    assert once.row_id == 77  # the gate pairs on row_id, so a mutation may never renumber a Flow
    assert once.category == "r2l"
    # What transferred is the bucket, not the donor: the held-out Flow gets its own draw from the same behaviour.
    assert found.bucket != attacker.NO_DONOR
    assert block_of(once) in [block_of(donor.flow) for donor in DONORS.buckets[found.bucket]]


def test_fixed_features_are_never_altered() -> None:
    flow = attack_flow()
    mutated = attacker.apply(flow, Strategy(bucket_of(DONOR_MANY), 4000, 30), DONORS, seeded(1))
    for name in FIXED_R2L:
        assert value_of(mutated, name) == value_of(flow, name), name
    # The three that carry the whole meaning of the attack, named rather than left to the loop above.
    assert (value_of(mutated, "service"), value_of(mutated, "protocol_type")) == ("telnet", "tcp")
    assert value_of(mutated, "num_failed_logins") == "1"
    assert block_of(mutated) != block_of(flow)  # something did move


def test_the_derived_block_comes_from_exactly_one_donor() -> None:
    # One bucket, three donors with three different blocks: whichever is drawn, the emitted block must be one of them verbatim and never
    # a mixture, which is the whole reason the block is copied rather than computed.
    crowd = donors_of(donor_flow(201, "11"), donor_flow(202, "22"), donor_flow(203, "33"))
    bucket = crowd.order[0]
    seen: set[tuple[str, ...]] = set()
    for draw in range(40):
        mutated = attacker.apply(attack_flow(), Strategy(bucket, 0, 0), crowd, seeded(draw))
        marks = {value_of(mutated, name) for name in MARKED}
        assert len(marks) == 1, marks
        seen.add(block_of(mutated))
    assert seen == {block_of(donor.flow) for donor in crowd.buckets[bucket]}


def test_a_verdict_that_flips_ends_the_search_and_names_the_bucket_that_did_it() -> None:
    # The Detector calms down as soon as it sees the widely spread donor's block.
    judge = FakeJudge(quiet=lambda flow: value_of(flow, "srv_diff_host_rate") == "1.00")
    evasion = evade(judge)
    assert evasion.evaded
    assert evasion.strategy == Strategy(bucket=bucket_of(DONOR_MANY), padding_bytes=0, added_seconds=0)
    assert evasion.queries == len(judge.seen)
    assert evasion.queries <= 4  # the baseline probe and at most one per bucket; nothing is spent lowering p_attack further
    assert evasion.start_p_attack == 0.9
    assert evasion.final_p_attack == 0.2


@pytest.mark.parametrize("max_queries", [0, 1, 2, 3, 7, 30])
def test_max_queries_is_never_exceeded(max_queries: int) -> None:
    judge = FakeJudge()
    evasion = evade(judge, max_queries=max_queries)
    assert evasion.queries <= max_queries
    assert len(judge.seen) == evasion.queries


def test_no_query_at_all_means_no_strategy_and_no_claim() -> None:
    judge = FakeJudge()
    evasion = evade(judge, max_queries=0)
    assert evasion == Evasion(row_id=1, evaded=False, strategy=None, queries=0, start_p_attack=None, final_p_attack=None)
    assert judge.seen == []


def test_an_attack_flow_that_cannot_be_evaded_reports_the_best_strategy_tried() -> None:
    judge = FakeJudge()  # alerts on everything, whatever it is shown
    evasion = evade(judge, observes="p_attack")
    assert not evasion.evaded
    assert evasion.strategy is not None
    assert evasion.queries > 1  # it did try


def test_with_p_attack_the_climb_starts_from_the_bucket_that_scored_best() -> None:
    # Only the widely spread donor's block lowers p_attack, and the Verdict stays an alert throughout, so nothing evades and the best
    # Strategy tried must still name that bucket.
    judge = FakeJudge(p_attack=lambda flow: 0.45 if value_of(flow, "srv_diff_host_rate") == "1.00" else 0.9)
    evasion = evade(judge, observes="p_attack")
    assert not evasion.evaded
    assert evasion.strategy is not None
    assert evasion.strategy.bucket == bucket_of(DONOR_MANY)
    assert evasion.start_p_attack == 0.9
    # A Verdict of `attack` beside a p_attack under the threshold: the search reads the Verdict, not the number.
    assert evasion.final_p_attack == 0.45


def test_observing_only_the_verdict_never_branches_on_p_attack() -> None:
    # Two Detectors that return the SAME Verdicts and different p_attack. An attacker allowed only the Verdict must walk the identical
    # path through both; one that peeked at p_attack would not.
    flat = FakeJudge(p_attack=lambda _flow: 0.9)
    graded = FakeJudge(p_attack=lambda flow: 0.45 if value_of(flow, "srv_diff_host_rate") == "1.00" else 0.9)
    assert evade(flat).strategy == evade(graded).strategy
    assert flat.probed == graded.probed
    # And the same two Detectors do separate an attacker that is allowed the number, so the assertion above has teeth.
    peeking, peeking_graded = FakeJudge(p_attack=lambda _flow: 0.9), FakeJudge(p_attack=graded._p_attack)  # pyright: ignore[reportPrivateUsage]
    evade(peeking, observes="p_attack")
    evade(peeking_graded, observes="p_attack")
    assert peeking.probed != peeking_graded.probed


def test_a_donor_the_attacker_could_not_have_reached_is_never_used() -> None:
    # Both donors sit in the same rate band, and only the quieter one is reachable from a Flow whose own windows hold one connection.
    near, far = donor_flow(301, "11", count="1", srv_count="1"), donor_flow(302, "22", count="2", srv_count="2")
    pool = donors_of(near, far)
    flow = attack_flow(count="1", srv_count="1")
    bucket = bucket_of(near)
    assert bucket_of(far) == bucket
    assert [donor.flow.row_id for donor in attacker.candidates(pool, flow, bucket)] == [301]
    for draw in range(25):
        assert block_of(attacker.apply(flow, Strategy(bucket, 0, 0), pool, seeded(draw))) == block_of(near)
    # A whole bucket out of reach leaves the Flow's own block in place rather than raising; the technique simply did not transfer.
    busy = donors_of(donor_flow(303, "44", count="9", srv_count="9"))
    quiet = attack_flow(count="1", srv_count="1")
    assert attacker.candidates(busy, quiet, busy.order[0]) == ()
    assert block_of(attacker.apply(quiet, Strategy(busy.order[0], 0, 0), busy, seeded(0))) == block_of(quiet)


def test_a_donor_claiming_connections_the_attacker_never_made_is_never_used() -> None:
    # The host-based counts are the last hundred connections to the victim. An attacker cannot assert prior connections it did not make,
    # so a donor may not bring more of them than the attack Flow already has.
    thin = donor_flow(311, "11", dst_host_count="40", dst_host_srv_count="40")
    thick = donor_flow(312, "22", dst_host_count="200", dst_host_srv_count="40")
    srv_thick = donor_flow(313, "33", dst_host_count="40", dst_host_srv_count="200")
    pool = donors_of(thin, thick, srv_thick)
    flow = attack_flow(dst_host_count="100", dst_host_srv_count="100")
    bucket = bucket_of(thin)
    assert {bucket_of(thick), bucket_of(srv_thick)} == {bucket}  # the bound is not the bucket doing the work
    assert [donor.flow.row_id for donor in attacker.candidates(pool, flow, bucket)] == [311]
    for draw in range(25):
        assert value_of(attacker.apply(flow, Strategy(bucket, 0, 0), pool, seeded(draw)), "dst_host_count") == "40"
    # The move that is genuinely available survives: a saturated attack Flow can still take a thinner host history, which lowers it.
    saturated = attack_flow()  # dst_host_count 255, as every arena r2l Flow has
    assert len(attacker.candidates(pool, saturated, bucket)) == 3
    assert value_of(attacker.apply(saturated, Strategy(bucket, 0, 0), pool, seeded(0)), "dst_host_count") in ("40", "200")


def test_dst_bytes_stays_with_the_attack_because_the_victim_writes_it() -> None:
    # The model calls `dst_bytes` derived, and it is -- by the target server, which does not answer differently because the attacker
    # waited longer. Copying a donor's value would claim a reply that never happened.
    assert CONSTRAINTS.role("dst_bytes", "r2l") == "derived"
    assert "dst_bytes" in DERIVED_R2L
    assert "dst_bytes" not in MOVED_R2L
    flow = attack_flow(dst_bytes="1200")
    mutated = attacker.apply(flow, Strategy(bucket_of(DONOR_MANY), 0, 0), DONORS, seeded(0))
    assert value_of(mutated, "dst_bytes") == "1200"
    assert value_of(mutated, "dst_host_count") == "33"  # the rest of the block did travel


def test_a_donor_whose_profile_the_attacks_protocol_cannot_carry_is_never_used() -> None:
    # Sheatsley et al.'s failure case: udp carries neither the service `http` nor the flag `S0`, so neither donor's block could have
    # been produced by a udp connection, however benign it looks. `wrong_flag` runs the attack's own service, so only the protocol-level
    # flag check can refuse it.
    wrong_service = donor_flow(401, "11", protocol_type="tcp", service="http", flag="SF")
    wrong_flag = donor_flow(402, "22", protocol_type="tcp", service="private", flag="S0")
    fine = donor_flow(403, "33", protocol_type="udp", service="private", flag="SF")
    pool = donors_of(wrong_service, wrong_flag, fine)
    flow = attack_flow(protocol_type="udp", service="private")
    bucket = bucket_of(fine)
    assert {bucket_of(wrong_service), bucket_of(wrong_flag)} == {bucket}
    assert [donor.flow.row_id for donor in attacker.candidates(pool, flow, bucket)] == [403]
    for draw in range(25):
        assert block_of(attacker.apply(flow, Strategy(bucket, 0, 0), pool, seeded(draw))) == block_of(fine)


def test_a_donor_running_another_service_is_never_used() -> None:
    # Half the block is computed over same-service windows, so an http donor's block is not what a telnet connection would have
    # generated. Both donors here are perfectly admissible on tcp; only the attack's own service makes one of them a candidate.
    other = donor_flow(411, "11", service="http")
    same = donor_flow(412, "22", service="telnet")
    pool = donors_of(other, same)
    flow = attack_flow(service="telnet")
    bucket = bucket_of(same)
    assert bucket_of(other) == bucket
    assert "http" in CONSTRAINTS.services["tcp"]  # nothing is wrong with the donor itself
    assert [donor.flow.row_id for donor in attacker.candidates(pool, flow, bucket)] == [412]
    for draw in range(25):
        assert block_of(attacker.apply(flow, Strategy(bucket, 0, 0), pool, seeded(draw))) == block_of(same)
    # A service the Pool is too thin in yields no candidate at all, and the Strategy degrades to the levers, as an empty bucket does.
    rare = attack_flow(service="pop_2")
    assert attacker.candidates(pool, rare, bucket) == ()
    levered = attacker.apply(rare, Strategy(bucket, 500, 0), pool, seeded(0))
    assert block_of(levered) == block_of(rare)
    assert value_of(levered, "src_bytes") == "626"


def test_the_levers_only_ever_add_and_never_pass_the_hard_ceiling() -> None:
    flow = attack_flow()  # src_bytes 126, duration 0
    padded = attacker.apply(flow, Strategy(attacker.NO_DONOR, 1000, 90), DONORS, seeded(0))
    assert (value_of(padded, "src_bytes"), value_of(padded, "duration")) == ("1126", "90")
    assert block_of(padded) == block_of(flow)  # `NO_DONOR` substitutes nothing
    # r2l's hard ceilings are 5,135,678 bytes and 15,168 seconds; a Strategy fitted elsewhere is trimmed, never allowed through.
    maxed = attacker.apply(flow, Strategy(attacker.NO_DONOR, 10**9, 10**9), DONORS, seeded(0))
    assert (value_of(maxed, "src_bytes"), value_of(maxed, "duration")) == ("5135678", "15168")
    # A Split comes from KDDTest+, which the model was not fitted on, so a Flow can start out past the wall. Padding must not lower it.
    over = attack_flow(src_bytes="9999999")
    assert value_of(attacker.apply(over, Strategy(attacker.NO_DONOR, 5000, 0), DONORS, seeded(0)), "src_bytes") == "9999999"
    # Only what the model calls a direct lever has rungs at all; nothing else is the attacker's to write.
    assert attacker.lever_rungs(DONORS, flow, "service") == ()


def test_a_strategy_refuses_a_lever_that_would_take_bytes_or_seconds_away() -> None:
    with pytest.raises(ValueError, match="increase-only"):
        Strategy("b", -1, 0)
    with pytest.raises(ValueError, match="increase-only"):
        Strategy("b", 0, -1)


def test_dos_keeps_the_block_the_model_pins_for_it_and_has_no_latency_to_add() -> None:
    flow = attack_flow(row_id=5, category="dos", protocol_type="tcp", service="private", flag="S0", serror_rate="1.00", count="5")
    pool = donors_of(donor_flow(601, "33", service="private", srv_diff_host_rate="1.00"))
    # The model records duration p99 = 0 for dos: added latency is not a lever a dos attacker has on this Dataset.
    assert attacker.lever_rungs(pool, flow, attacker.LATENCY) == ()
    assert attacker.lever_rungs(pool, flow, attacker.PADDING) != ()
    mutated = attacker.apply(flow, Strategy(pool.order[0], 0, 0), pool, seeded(0))
    # `role_by_category` pins dos's whole time-based block and its flag, so only the host-based block may travel.
    for name in ("flag", "count", "srv_count", "serror_rate", "same_srv_rate", "srv_diff_host_rate"):
        assert value_of(mutated, name) == value_of(flow, name), name
    assert value_of(mutated, "dst_host_count") == "33"
    assert CONSTRAINTS.transplanted("dos") == tuple(name for name in FEATURES if name.startswith("dst_host_"))


def test_a_category_the_model_writes_no_override_for_needs_no_special_case() -> None:
    # `[attacker] categories` gains probe, for which `mutations.json` has no `role_by_category` entry at all: every role falls back to
    # the default, and the levers come from `direct_levers.by_category.probe` like any other Category's.
    flow = attack_flow(row_id=8, category="probe", service="private", count="30", srv_count="30")
    pool = donors_of(donor_flow(701, "44", service="private", count="8", srv_count="8", srv_diff_host_rate="1.00"))
    assert CONSTRAINTS.transplanted("probe") == MOVED_R2L  # no override, so the same block travels as for r2l
    assert attacker.lever_rungs(pool, flow, attacker.LATENCY) == (4014, 10036, 20071, 40142)  # probe's own p99, 40,142 s
    judge = FakeJudge(quiet=lambda probe: value_of(probe, "srv_diff_host_rate") == "1.00")
    evasion = MimicryAttacker(pool, observes="verdict", seed=0).evade(flow, judge, 30)
    assert evasion.evaded
    assert value_of(judge.seen[-1], "dst_host_count") == "44"
    # Spreading out is what probe is for, and the host window it lands in is the donor's, which the bound keeps under the attack's own.
    assert attacker.candidates(pool, attack_flow(category="probe", service="private", count="0", srv_count="0"), pool.order[0]) == ()


def test_a_call_that_failed_counts_as_an_alert() -> None:
    assert attacker.alerted({"p_attack": None, "classification_verdict": None})
    assert attacker.alerted({"error": "timeout"})
    assert attacker.alerted({"p_attack": 0.5})
    assert not attacker.alerted({"p_attack": 0.49})
    assert not attacker.alerted({"p_attack": 0.99, "classification_verdict": 0})  # a filled Verdict wins over the number


def test_donors_come_from_benign_flows_and_the_busiest_buckets_are_tried_first() -> None:
    pool = donors_of(
        attack_flow(row_id=9),  # an attack Flow is not something to hide inside
        donor_flow(501, "11", srv_diff_host_rate="0.00"),
        donor_flow(502, "22", srv_diff_host_rate="0.00"),
        donor_flow(503, "33", srv_diff_host_rate="1.00"),
    )
    assert sum(len(bucket) for bucket in pool.buckets.values()) == 3
    assert pool.order == (bucket_of(donor_flow(0, "0")), bucket_of(donor_flow(0, "0", srv_diff_host_rate="1.00")))
    assert pool.order[0] == "rate=quiet|hosts=same|srv=one"


def test_a_pool_and_a_card_are_all_the_loop_needs_to_hand_over() -> None:
    # The round loop holds the Pool and the Card and nothing else, and a bare list of Flows cannot say which features the sensor owns.
    pool = attacker.donors_from_pool([attack_flow(row_id=9), DONOR_SAME, DONOR_MANY], CARD)
    assert sum(len(bucket) for bucket in pool.buckets.values()) == 2
    assert pool.constraints.role("count", "dos") == "fixed"
    assert pool.features == FEATURES


def test_the_bucket_names_the_behaviour_and_not_the_flow() -> None:
    assert bucket_of(donor_flow(0, "0", count="1", srv_count="1")) == "rate=quiet|hosts=same|srv=one"
    # The two windows are parallel and not nested (findings §1.2), so the busier of them names the band.
    assert bucket_of(donor_flow(0, "0", count="1", srv_count="80")) == "rate=mid|hosts=same|srv=one"
    assert bucket_of(donor_flow(0, "0", count="400", srv_count="1", srv_diff_host_rate="0.90")) == "rate=busy|hosts=many|srv=one"
    assert bucket_of(donor_flow(0, "0", count="15", srv_diff_host_rate="0.30", same_srv_rate="0.10")) == "rate=low|hosts=some|srv=many"
    assert bucket_of(donor_flow(0, "0", same_srv_rate="0.50")) == "rate=quiet|hosts=same|srv=mixed"


def test_the_attacker_refuses_to_observe_something_it_cannot_see() -> None:
    with pytest.raises(ValueError, match="observes"):
        MimicryAttacker(DONORS, observes="everything")


def model_with(tmp_path: Path, **tweaks: Any) -> dict[str, str | Path]:
    """A card-shaped dict pointing at a minimal constraint model, with `tweaks` merged over its two blocks."""
    lever: dict[str, Any] = {
        "direction": "increase_only",
        "plausible_ceiling": "p99",
        "hard_ceiling": "max",
        "by_category": {"r2l": {"p99": 10.0, "max": 20.0}},
    }
    model: dict[str, Any] = {
        "features": {"duration": {"role": "direct"}, "src_bytes": {"role": "direct"}},
        "direct_levers": {"duration": dict(lever), "src_bytes": dict(lever)},
        "symbolic_combinations": {
            "by_protocol_type": {"tcp": {"service": {"common": {"http": 1}, "rare": {}}, "flag": {"common": {"SF": 1}, "rare": {}}}}
        },
    }
    model.update(tweaks)
    (tmp_path / attacker.MODEL_FILE).write_text(json.dumps(model), encoding="utf-8")
    return {"dir": tmp_path}


def test_the_committed_model_gives_the_attacker_exactly_what_it_moves() -> None:
    assert CONSTRAINTS.role("num_failed_logins", "r2l") == "fixed"
    assert CONSTRAINTS.role("count", "r2l") == "derived"
    assert CONSTRAINTS.role("count", "dos") == "fixed"  # the per-Category override wins
    assert CONSTRAINTS.levers[attacker.LATENCY]["dos"] == attacker.Lever(ceiling=0, wall=14)
    assert "tftp_u" in CONSTRAINTS.services["udp"]  # three Flows in the whole Pool, and still a combination the sensor emitted
    assert CONSTRAINTS.flags["udp"] == frozenset({"SF"})
    assert len(DERIVED_R2L) == 21  # the nineteen time- and host-based features, plus `flag` and `dst_bytes`
    assert len(MOVED_R2L) == 20  # less `dst_bytes`; the number the module docstring holds against its own results


def test_a_model_that_disagrees_with_the_code_is_refused(tmp_path: Path) -> None:
    decreasing = model_with(tmp_path / "a", direct_levers={"duration": {"direction": "decrease_only"}})
    with pytest.raises(ValueError, match="only ever adds"):
        attacker.load_constraints(decreasing)
    not_direct = model_with(tmp_path / "b", features={"duration": {"role": "direct"}, "src_bytes": {"role": "derived"}})
    with pytest.raises(ValueError, match="src_bytes"):
        attacker.load_constraints(not_direct)
    assert attacker.load_constraints(model_with(tmp_path / "c")).levers[attacker.PADDING]["r2l"].wall == 20


@pytest.fixture(autouse=True)
def _make_tmp_dirs(tmp_path: Path) -> None:
    """The three model directories `model_with` writes into; a fixture so each test gets its own."""
    for name in "abc":
        (tmp_path / name).mkdir(exist_ok=True)
