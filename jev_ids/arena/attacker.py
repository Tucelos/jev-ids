"""The evasive attacker: constrained mimicry by donor substitution.

In reading order:

- `Judge` and `alerted`: what the round loop lends the attacker, and how one probe's answer is read.
- `Strategy` and `Evasion`: what transfers to a held-out Flow, and what the search achieved on one attack Flow.
- `Lever`, `Constraints` and `load_constraints`: `data/<dataset>/mutations.json` as the attacker reads it.
- `Donor`, `bucket_of`, `Donors`, `build_donors` and `donors_from_pool`: the benign Pool Flows a derived block is taken from, grouped by
  the behaviour they show.
- `reachable`, `admissible`, `candidates` and `choose_donor`: the two filters a donor must pass, and the seeded draw between the survivors.
- `lever_rungs` and `apply`: the settings the two direct levers may take, and one attack Flow plus one Strategy as a mutated Flow.
- `MimicryAttacker`: the search, hill-climbing over donor buckets and then over the levers.

**Why donors and not a parametric behaviour model.** The first design turned behaviour knobs (slower, more spread out) and computed the
nineteen time-based and host-based features from them. `dev-docs/empirical-constraints-findings.md` killed it: three of the four coupling
identities such a model would have to respect are contradicted by the Pool (§1), and NSL-KDD carries no timestamps and no connection
ordering, so no causal model of the derived features can be validated on it at all (§7). Synthesised derived values would be numbers whose
joint consistency nobody can check, and a reviewer would be right to throw them out.

So this attacker never writes a derived feature value. It takes the whole derived block from a single real benign Flow -- a donor, a record
the sensor actually emitted -- and keeps the attack's own fixed features, the ones that make a guess_passwd a guess_passwd. Whatever the
true couplings are, a real block satisfies them by construction: `flag` arrives beside the error rates it pins (findings §1.5), and
`same_srv_rate` beside the `count` and `srv_count` it is a share of (§1.4). This is Pierazzi et al.'s problem-space projection, with the
side-effect features arriving as one bundle from a real observation instead of being picked one at a time.

The block comes from ONE donor and is never mixed, because two donors spliced together rebuild exactly the inconsistency the whole design
avoids. Three things narrow which donor may be used, each closing a way to emit a Flow the sensor could not have produced: the donor must
run the attack's own `service`, since half the block is computed over same-service windows (`admissible`); none of its four connection
counts may exceed the attack's, since an attacker cannot assert connections it never made (`reachable`); and `dst_bytes` stays with the
attack however the model classifies it, since the victim writes it (`VICTIM_WRITES`). Only the two `direct` levers are written by hand,
increase-only and inside the bounds the model measured (Apruzzese et al.: added latency, junk bytes).

**What none of that fixes, and a reader should hold against the results.** Twenty of the forty-one features arrive from somebody else's
record. After the three narrowings the block is service-matched, victim-consistent and count-bounded, but it is still another host's
traffic worn as a disguise, and the evasion rate this attacker reports is partly a statement about how much of the feature vector is
handed over rather than about how skilful the attacker is. A Detector that leans on the derived block will flip; one that leans on
`service`, `src_bytes` and the content block will not. That is a property of the method, it is not argued away here, and any reading of
the evasion rate should say so.

What the attacker returns is a `Strategy`, not a Flow: the gate replays it on held-out Flows the curator never saw
(`dev-docs/arena-loop-design.md`), so a single mutated Flow would answer nothing. A Strategy names a donor BUCKET and two lever settings,
all three of which mean something on a Flow this search never touched.

The feature names below are NSL-KDD's because the constraint model is NSL-KDD's; another Dataset needs its own `mutations.json` and its own
bucket axes before any of this means anything for it.
"""

import json
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from jev_ids.dataset import Config, Flow
from jev_ids.records import VERDICT_THRESHOLD, Prediction

# The constraint model beside the card; `scripts/fit_mutations.py` writes it and `dev-docs/empirical-constraints-findings.md` reads it.
MODEL_FILE = "mutations.json"

# The features this module reads by name. They are the Card's, but the roles and the bounds that give them meaning are the model's.
PROTOCOL = "protocol_type"
SERVICE = "service"
FLAG = "flag"
COUNT = "count"
SRV_COUNT = "srv_count"
SAME_SRV_RATE = "same_srv_rate"
SRV_DIFF_HOST_RATE = "srv_diff_host_rate"
DST_HOST_COUNT = "dst_host_count"
DST_HOST_SRV_COUNT = "dst_host_srv_count"
# The two direct levers, in the order `Strategy` names them: junk bytes and added latency.
PADDING = "src_bytes"
LATENCY = "duration"

# The features the model calls `derived` that the attacker still may not take from a donor, because the sensor is not who writes them: the
# VICTIM is. `dst_bytes` is how much the target server answered, and a telnet server's reply to one login attempt does not change because
# the attacker waited longer between attempts, so a donor's value would claim a reply that never happened. The model's three-value role
# vocabulary cannot say "derived, but by the victim rather than by the attacker" -- `dev-docs/empirical-constraints-findings.md` §6 and §7
# record `dst_bytes` as exactly that forced fit -- so the distinction is made here instead, where it has a consequence.
VICTIM_WRITES = ("dst_bytes",)

# The bucket id of a Strategy that substitutes no donor at all: the attack Flow with its own derived block and nothing but the levers
# moved. The search starts here, so "do nothing" is a setting the hill climb can honestly report as its best.
NO_DONOR = "none"

# The three behaviour axes a donor is bucketed on, each a coarse grid of round numbers rather than a fitted split: the bucket only has to
# name a behaviour well enough to transfer, and quantiles read off the Pool would make the attacker's own vocabulary depend on the Split it
# is attacking. Edges are upper bounds, inclusive; anything past the last edge takes the trailing name.
RATE_BANDS: tuple[tuple[float, str], ...] = ((2, "quiet"), (20, "low"), (100, "mid"))
RATE_BUSY = "busy"
HOST_SPREAD_BANDS: tuple[tuple[float, str], ...] = ((0.0, "same"), (0.5, "some"))
HOST_SPREAD_WIDE = "many"
SERVICE_SPREAD_BANDS: tuple[tuple[float, str], ...] = ((0.3, "many"), (0.9, "mixed"))
SERVICE_SPREAD_ONE = "one"

# The rungs of each lever, as fractions of the headroom between the Flow's own value and its Category's plausible ceiling.
LEVER_RUNGS = (0.1, 0.25, 0.5, 1.0)
# The share of one Flow's query budget the bucket phase may spend, so the lever climb always gets a turn. The real Pool fills a few dozen
# buckets and `attacker.max_queries_per_flow` is 30 by default, so without this the levers would never be reached.
BUCKET_SHARE = 0.6

# The loop owns the Detector, the Context and the Budget; the attacker is lent one call and sees nothing else.
type Judge = Callable[[Flow], Prediction]


def alerted(prediction: Prediction) -> bool:
    """Whether the Detector alerted on one probe.

    Reads `classification_verdict` when the caller filled it and falls back to `p_attack` at `VERDICT_THRESHOLD`, so a bare Detector dict
    and a completed Prediction row are both understood.

    A call that failed carries neither and counts as an alert. An attacker that read a broken call as a win would manufacture evasion
    successes out of the Detector's downtime, and `threats.failure_rate` exists precisely to create that downtime.

    Args:
        prediction: what the Judge returned for one probe.

    Returns:
        True when the Flow was alerted on, or when nothing came back to say otherwise.
    """
    verdict = prediction.get("classification_verdict")
    if verdict is not None:
        return bool(verdict)
    p_attack = prediction.get("p_attack")
    return p_attack is None or float(p_attack) >= VERDICT_THRESHOLD


@dataclass(frozen=True)
class Strategy:
    """What the attacker found, in a form that means something on a Flow it never touched.

    A Strategy names a donor bucket rather than a donor: the donor itself is drawn per Flow, because which donors are reachable and
    admissible depends on the attack Flow being mutated. That is exactly what makes the gate's generalisation test possible -- the same
    Strategy applied to a held-out Flow is the same behaviour, not the same feature vector.

    Attributes:
        bucket: the donor bucket's id, or `NO_DONOR` for a Strategy that substitutes no derived block.
        padding_bytes: junk bytes added to `src_bytes`; zero or more, never less.
        added_seconds: latency added to `duration`; zero or more, never less.
    """

    bucket: str
    padding_bytes: int
    added_seconds: int

    def __post_init__(self) -> None:
        """Refuse a lever that would take bytes or seconds away.

        Both levers are increase-only (Apruzzese et al., TETCI 2020): an attacker can pad a request and dawdle, and cannot un-send bytes
        or finish a connection before it started.

        Raises:
            ValueError: either lever is negative.
        """
        if self.padding_bytes < 0 or self.added_seconds < 0:
            raise ValueError(f"{self}: both levers are increase-only, so neither may be negative")


# The Strategy every search starts from: no donor, no padding, no added latency, so its probe judges the attack Flow untouched.
BASELINE = Strategy(bucket=NO_DONOR, padding_bytes=0, added_seconds=0)


@dataclass(frozen=True)
class Evasion:
    """What one attack Flow's search achieved.

    `start_p_attack` and `final_p_attack` are recorded for the experiment whatever `observes` allows: the Round record is written by the
    loop, which sees everything. They are not what the search branched on -- see `MimicryAttacker`.

    Attributes:
        row_id: the attack Flow's row_id, unchanged by mutation so the gate can pair on it.
        evaded: whether some Strategy flipped the Verdict to `normal`.
        strategy: the Strategy that evaded, or the best one tried; None only when no query could be spent at all.
        queries: Detector calls spent, never more than the `max_queries` given.
        start_p_attack: p_attack of the untouched Flow, or None when the first call failed or none was made.
        final_p_attack: p_attack of the last probe, or None when that call failed or none was made.
    """

    row_id: int
    evaded: bool
    strategy: Strategy | None
    queries: int
    start_p_attack: float | None
    final_p_attack: float | None


@dataclass(frozen=True)
class Lever:
    """The two ceilings one direct lever has in one Category, in that feature's own unit.

    Attributes:
        ceiling: the plausible ceiling, `direct_levers.<lever>.plausible_ceiling` (p99 in the shipped model). It sizes the rungs the
            search proposes, so a probe asks for a value the sensor sees routinely.
        wall: the hard ceiling, `direct_levers.<lever>.hard_ceiling` (max). `apply` never crosses it, so no mutated Flow carries a value
            past the hardest one the sensor ever recorded for its Category.
    """

    ceiling: int
    wall: int


@dataclass(frozen=True)
class Constraints:
    """The constraint model, reduced to what an attacker needs to obey it.

    Attributes:
        roles: every feature's default role, `direct`, `derived` or `fixed`.
        overrides: `role_by_category`, the per-Category role that wins over the default where the model gives one.
        levers: the two direct levers' bounds, by feature and then by Category.
        services: the services the Pool ever carried on each `protocol_type`.
        flags: the flags the Pool ever carried on each `protocol_type`.
    """

    roles: Mapping[str, str]
    overrides: Mapping[str, Mapping[str, str]]
    levers: Mapping[str, Mapping[str, Lever]]
    services: Mapping[str, frozenset[str]]
    flags: Mapping[str, frozenset[str]]

    def role(self, feature: str, category: str) -> str:
        """One feature's role for one Category: the `role_by_category` entry if the model gives one, else the default role.

        The override is what makes a dos Flow different from every other: the model pins its whole time-based block and its `flag`, so a
        dos mutation may only take the host-based block and `dst_bytes` from a donor.
        """
        return self.overrides.get(feature, {}).get(category, self.roles[feature])

    def derived_features(self, category: str) -> tuple[str, ...]:
        """Every feature the model calls `derived` for this Category, in Card order: a faithful reading of the model and nothing more."""
        return tuple(name for name in self.roles if self.role(name, category) == "derived")

    def transplanted(self, category: str) -> tuple[str, ...]:
        """The block that actually travels from a donor: the derived features, less the ones the victim writes.

        The difference between this and `derived_features` is `VICTIM_WRITES`, and it is a deliberate departure from the model rather
        than a reading of it. Everything here is still taken as one piece from one donor, so the couplings among them survive.
        """
        return tuple(name for name in self.derived_features(category) if name not in VICTIM_WRITES)


def _lever_bounds(entry: Mapping[str, Any]) -> dict[str, Lever]:
    """One direct lever's per-Category bounds, reading which quantile the model calls plausible and which it calls hard.

    Raises:
        ValueError: the lever is not increase-only, which is the only direction this attacker knows how to move.
    """
    if entry["direction"] != "increase_only":
        raise ValueError(f"lever direction {entry['direction']!r}: this attacker only ever adds bytes and seconds")
    plausible, hard = entry["plausible_ceiling"], entry["hard_ceiling"]
    bounds: dict[str, Lever] = {}
    for category, stats in entry["by_category"].items():
        bounds[str(category)] = Lever(ceiling=int(stats[plausible]), wall=int(stats[hard]))
    return bounds


def _symbolic_pairs(block: Mapping[str, Any], field: str) -> dict[str, frozenset[str]]:
    """Every value of one symbolic feature the Pool ever carried on each protocol, the common ones and the rare ones together.

    The rare ones are kept: `tftp_u` has three Flows in the whole Pool, and dropping it would make this module claim a combination is
    impossible when the sensor has in fact emitted it.
    """
    by_protocol: dict[str, frozenset[str]] = {}
    for protocol, entry in block["by_protocol_type"].items():
        seen: Mapping[str, Any] = entry[field]
        by_protocol[str(protocol)] = frozenset(seen["common"]) | frozenset(seen["rare"])
    return by_protocol


def load_constraints(config: Config) -> Constraints:
    """The Dataset's `mutations.json`, as the attacker reads it.

    Args:
        config: the Card, as `dataset.load_config` returns it; the model sits beside it in `config["dir"]`.

    Returns:
        The roles, the lever bounds and the admissible symbolic combinations.

    Raises:
        ValueError: a lever is not increase-only, or the model does not give the two levers this module moves the `direct` role. Either
            means the code and the model have drifted apart, and a silent disagreement there would let the attacker write a feature the
            model says the sensor owns.
    """
    model: dict[str, Any] = json.loads((Path(config["dir"]) / MODEL_FILE).read_text(encoding="utf-8"))
    features: Mapping[str, Any] = model["features"]
    roles = {str(name): str(entry["role"]) for name, entry in features.items()}
    overrides = {
        str(name): {str(category): str(role) for category, role in entry.get("role_by_category", {}).items()}
        for name, entry in features.items()
    }
    levers = {str(name): _lever_bounds(entry) for name, entry in model["direct_levers"].items()}
    for lever in (PADDING, LATENCY):
        if roles.get(lever) != "direct" or lever not in levers:
            raise ValueError(f"{lever}: the attacker moves it by hand, so the model must give it the `direct` role and its bounds")
    return Constraints(
        roles=roles,
        overrides=overrides,
        levers=levers,
        services=_symbolic_pairs(model["symbolic_combinations"], "service"),
        flags=_symbolic_pairs(model["symbolic_combinations"], "flag"),
    )


@dataclass(frozen=True)
class Donor:
    """One benign Pool Flow, with the six values the filters and the buckets read off it.

    The Flow itself is kept rather than its split-out values: the derived block is copied only from the one donor a probe actually draws,
    so splitting all 67,343 benign Pool Flows up front would cost a lot of memory to answer a question about one of them.

    Attributes:
        flow: the benign Flow the block comes from; its `row_id` traces the block back to the record the sensor emitted.
        count: its `count`, the same-host 2 s window, read by the reachability filter.
        srv_count: its `srv_count`, the same-service 2 s window, read by the reachability filter.
        dst_host_count: its `dst_host_count`, the 100-connection same-host window, likewise.
        dst_host_srv_count: its `dst_host_srv_count`, the 100-connection same-service window, likewise.
        service: its `service`, read by the admissibility filter, which requires the attack's own.
        flag: its `flag`, read by the admissibility filter; `flag` is itself part of the derived block for every Category but dos.
    """

    flow: Flow
    count: int
    srv_count: int
    dst_host_count: int
    dst_host_srv_count: int
    service: str
    flag: str


def _as_int(text: str) -> int:
    """One CSV cell as an integer, tolerating a value written as a decimal."""
    return int(float(text))


def _band(value: float, edges: Sequence[tuple[float, str]], beyond: str) -> str:
    """The first band whose inclusive upper edge the value fits under, or `beyond` when it fits under none."""
    for edge, name in edges:
        if value <= edge:
            return name
    return beyond


def bucket_of(values: Sequence[str], positions: Mapping[str, int]) -> str:
    """The behaviour bucket one Flow falls in: its rate band, its host spread and its service spread.

    A bucket is what a Strategy carries, so it has to name a behaviour rather than a Flow. The three axes are the ones the model's
    `behaviour_knobs` give a direction to: the rate the attacker connects at (`count` and `srv_count`, the two 2 s windows, taken at their
    busier), how far the same service is spread over hosts (`srv_diff_host_rate`) and how much of the window is one service
    (`same_srv_rate`).

    The two counts are taken at their maximum and not summed or nested, because `dev-docs/empirical-constraints-findings.md` §1.2 shows
    they are two parallel windows: `srv_count > count` in 22 % of the Pool, so neither contains the other.

    Args:
        values: one Flow's feature values in Card order.
        positions: the Card's feature name to column index map.

    Returns:
        The bucket id, `rate=<band>|hosts=<band>|srv=<band>`.
    """
    rate = max(_as_int(values[positions[COUNT]]), _as_int(values[positions[SRV_COUNT]]))
    hosts = float(values[positions[SRV_DIFF_HOST_RATE]])
    services = float(values[positions[SAME_SRV_RATE]])
    return (
        f"rate={_band(rate, RATE_BANDS, RATE_BUSY)}"
        f"|hosts={_band(hosts, HOST_SPREAD_BANDS, HOST_SPREAD_WIDE)}"
        f"|srv={_band(services, SERVICE_SPREAD_BANDS, SERVICE_SPREAD_ONE)}"
    )


@dataclass(frozen=True)
class Donors:
    """The benign Flows a derived block may come from, grouped by the behaviour they show.

    Attributes:
        features: the Card's features in column order.
        positions: each feature's column index, so a value can be read and written by name.
        constraints: the model the filters and the levers obey.
        buckets: the donors of each bucket id.
        order: every bucket id, most populated first and then by id. This is the attacker's prior over what benign traffic usually looks
            like, and it depends on the Pool alone, never on the attack Flow or on anything the Detector said.
    """

    features: tuple[str, ...]
    positions: Mapping[str, int]
    constraints: Constraints
    buckets: Mapping[str, tuple[Donor, ...]]
    order: tuple[str, ...]


def build_donors(flows: Sequence[Flow], config: Config, constraints: Constraints) -> Donors:
    """The benign Flows of the Pool, bucketed by behaviour, ready to donate a derived block.

    Donors come from the Pool and never from the Split under attack: the Pool is what an attacker can study offline, and drawing blocks
    from the very Flows being judged would leak the evaluation into the attack. Attack Flows are dropped here rather than trusted to the
    caller -- a donor is supposed to be the traffic the attacker wants to disappear into.

    Args:
        flows: the Pool's Flows; the attack ones are skipped.
        config: the Card, for the feature order.
        constraints: the model, carried along so a `Donors` is everything `apply` needs.

    Returns:
        The donors, bucketed and ordered.
    """
    features = tuple(str(name) for name in config["features"])
    positions = {name: index for index, name in enumerate(features)}
    grouped: dict[str, list[Donor]] = {}
    for flow in flows:
        if flow.is_attack:
            continue
        values = flow.attribute_values
        donor = Donor(
            flow=flow,
            count=_as_int(values[positions[COUNT]]),
            srv_count=_as_int(values[positions[SRV_COUNT]]),
            dst_host_count=_as_int(values[positions[DST_HOST_COUNT]]),
            dst_host_srv_count=_as_int(values[positions[DST_HOST_SRV_COUNT]]),
            service=values[positions[SERVICE]],
            flag=values[positions[FLAG]],
        )
        grouped.setdefault(bucket_of(values, positions), []).append(donor)
    order = tuple(sorted(grouped, key=lambda bucket: (-len(grouped[bucket]), bucket)))
    return Donors(
        features=features,
        positions=positions,
        constraints=constraints,
        buckets={bucket: tuple(donors) for bucket, donors in grouped.items()},
        order=order,
    )


def donors_from_pool(flows: Sequence[Flow], config: Config) -> Donors:
    """Everything the attacker needs about one Dataset in one call: its model read, its benign Pool Flows bucketed.

    The seam the round loop wants. A bare list of benign Flows is not enough to mutate anything with -- `apply` needs the Card's feature
    order to find a value and the model's roles to know which values are the sensor's to write -- so the Pool and the Card travel together
    from here on as one `Donors`.

    Args:
        flows: the Pool; its attack Flows are dropped by `build_donors`.
        config: the Card, which also says where `mutations.json` lives.

    Returns:
        The donors, bucketed, carrying the constraint model.
    """
    return build_donors(flows, config, load_constraints(config))


@dataclass(frozen=True)
class Target:
    """What the two filters read off the attack Flow a donor is being considered for.

    Attributes:
        protocol: the attack's `protocol_type`, which it keeps: it is `fixed`, and it decides which services and flags exist at all.
        service: the attack's `service`, also `fixed`, and the one a donor must share.
        count: the attack's own `count`, the ceiling the reachability filter puts on a donor's.
        srv_count: the attack's own `srv_count`, likewise.
        dst_host_count: the attack's own `dst_host_count`, likewise.
        dst_host_srv_count: the attack's own `dst_host_srv_count`, likewise.
    """

    protocol: str
    service: str
    count: int
    srv_count: int
    dst_host_count: int
    dst_host_srv_count: int


def target_of(donors: Donors, flow: Flow) -> Target:
    """The attack Flow reduced to what the filters ask about it."""
    values = flow.attribute_values
    read = donors.positions
    return Target(
        protocol=values[read[PROTOCOL]],
        service=values[read[SERVICE]],
        count=_as_int(values[read[COUNT]]),
        srv_count=_as_int(values[read[SRV_COUNT]]),
        dst_host_count=_as_int(values[read[DST_HOST_COUNT]]),
        dst_host_srv_count=_as_int(values[read[DST_HOST_SRV_COUNT]]),
    )


def reachable(donor: Donor, target: Target) -> bool:
    """Whether an attacker could get from this attack Flow's behaviour to this donor's by slowing down and spreading out.

    The rule is that none of the donor's four connection counts may exceed the attack Flow's: `count` and `srv_count` over the 2 s
    windows, `dst_host_count` and `dst_host_srv_count` over the 100-connection ones. The behaviours on the table are lengthening the
    interval between connections and spreading them over more hosts and services, and each of those thins a window; speeding up is not a
    way to hide, and an attacker that could already run at the donor's rate would not need the disguise.

    The two host-based bounds matter for a reason the 2 s ones do not cover. `dst_host_count` is how many of the last hundred connections
    to the victim came from this source, and an attacker cannot assert prior connections it never made: a donor with 255 there would have
    the attack Flow claim a traffic history it does not own. The bound still leaves the move that is genuinely available, because the
    attack Flows start high and the donors sit lower: the median arena r2l Flow is at the saturated 255 (96 of 150, though the tenth
    percentile is 6) against a benign donor median of 156, so for most Flows the transplant *lowers* the value, which is the whole point
    of spreading out. Measured against a stand-in forest, adding these two bounds and the service match below cut the candidate donors per
    Flow from about 13,200 to about 367 and cost two probe Flows their evasion; the attack survives the narrowing almost intact.

    **This filter is an ASSUMPTION and it is the weakest link in the whole model.** It rests on the published derivation semantics -- that
    these are counts inside fixed windows, so a slower and more scattered attacker lands in smaller ones -- and it is untestable on this
    Dataset. NSL-KDD has no timestamps and no connection ordering, so the connection log cannot be replayed and no direction of any
    derived feature can be falsified from the CSV (`dev-docs/empirical-constraints-findings.md` §7, which marks every such direction
    `support: synthesis`). Nothing here proves an attacker can reach a donor's block; the filter only refuses the donors that the stated
    semantics say it certainly cannot.

    Args:
        donor: the candidate benign Flow.
        target: the attack Flow the block would be transplanted onto.

    Returns:
        True when none of the donor's four windows is busier than the attack's own.
    """
    return (
        donor.count <= target.count
        and donor.srv_count <= target.srv_count
        and donor.dst_host_count <= target.dst_host_count
        and donor.dst_host_srv_count <= target.dst_host_srv_count
    )


def admissible(donor: Donor, target: Target, constraints: Constraints) -> bool:
    """Whether the donor's block could have been produced beside the attack's own `protocol_type` and `service`, which it keeps.

    Three checks, an inner one and two outer ones.

    The inner one is equality: **the donor must be running the attack's own service.** Half the derived block is computed over
    same-service windows, so a telnet block is what a telnet connection would have generated and an http block is not. A telnet
    `guess_passwd` wearing an http donor's `srv_count`, `same_srv_rate` and `dst_host_srv_count` is not a Flow any sensor produced, and
    before this check the attacker could emit one. The supply in the Pool carries it: 917 benign telnet donors, 918 ftp, 4,984 ftp_data,
    982 private, 236 auth and 186 pop_3 cover every arena r2l Flow, and 2,604 other and 497 eco_i cover most of the probe ones. Where the
    Pool is thin the attacker simply loses the move: probe's `imap4` has 3 benign donors and its `sunrpc` has none, so those 4 Flows get
    no candidate and the Strategy degrades to the levers alone, exactly as an empty bucket does.

    The two outer ones come from `symbolic_combinations`, which counted every pair the Pool ever carried: the donor's `service` and its
    `flag` must both have been seen on the attack's protocol. The service check is now implied by the equality above -- the attack's own
    pair is by construction one the sensor emitted -- and it is kept because it is the statement being relied on, and because the `flag`
    check is not implied by anything: `flag` is part of the transplanted block for every Category but dos, and UDP and ICMP admit only
    `SF`.

    Together this is Sheatsley et al.'s failure case made unreachable: their unconstrained attack proposed switching a TCP `ftp` Flow to
    the UDP service `tftp_u`, a combination the sensor cannot emit.

    Args:
        donor: the candidate benign Flow.
        target: the attack Flow the block would be transplanted onto.
        constraints: the model holding the admissible combinations.

    Returns:
        True when the donor runs the attack's service and both that service and the donor's flag belong on the attack's protocol.
    """
    if donor.service != target.service:
        return False
    services = constraints.services.get(target.protocol, frozenset())
    flags = constraints.flags.get(target.protocol, frozenset())
    return donor.service in services and donor.flag in flags


def candidates(donors: Donors, flow: Flow, bucket: str) -> tuple[Donor, ...]:
    """Every donor of one bucket whose block this attack Flow could actually wear.

    Computed without the Detector: which donors pass is arithmetic over the Pool the attacker already has, so it costs no query. That is
    what lets the search skip a bucket it could never use instead of spending a probe to find out.
    """
    if bucket == NO_DONOR:
        return ()
    target = target_of(donors, flow)
    pool = donors.buckets.get(bucket, ())
    return tuple(donor for donor in pool if reachable(donor, target) and admissible(donor, target, donors.constraints))


def choose_donor(donors: Donors, flow: Flow, bucket: str, rng: random.Random) -> Donor | None:
    """One donor drawn from a bucket for one attack Flow, or None when the bucket holds nothing this Flow could wear.

    The draw is uniform over the survivors and consumes the `rng` given, so a Run replays its donors exactly from its seed. It is one
    draw and not one per feature: the block is indivisible.
    """
    usable = candidates(donors, flow, bucket)
    if not usable:
        return None
    return rng.choice(usable)  # noqa: S311  # seeded, not secret


def lever_rungs(donors: Donors, flow: Flow, feature: str) -> tuple[int, ...]:
    """The added amounts the search will try for one direct lever, smallest first.

    Rungs are fractions of the headroom between the Flow's own value and its Category's *plausible* ceiling, so a probe asks for a value
    the sensor sees routinely; the hard ceiling bounds the result instead, in `apply`.

    A Category with no headroom gets no rungs at all. For dos the model records `duration` p99 = 0 and max = 14 s, so "add a small
    latency" is essentially not a lever a dos attacker has on this Dataset (`dev-docs/empirical-constraints-findings.md` §4) and the
    search does not pretend otherwise.
    """
    bounds = donors.constraints.levers.get(feature)
    if bounds is None or flow.category not in bounds:
        return ()
    current = _as_int(flow.attribute_values[donors.positions[feature]])
    headroom = max(0, bounds[flow.category].ceiling - current)
    return tuple(sorted({round(fraction * headroom) for fraction in LEVER_RUNGS} - {0}))


def _raise_lever(values: list[str], donors: Donors, category: str, feature: str, added: int) -> None:
    """Add to one direct lever in place, increase-only and never past the Category's hard ceiling.

    The headroom is computed against the wall rather than the value being clamped to it, so a Flow that already sits above everything the
    Pool recorded -- a Split comes from KDDTest+, which the model was not fitted on -- is left alone instead of being quietly lowered. An
    attacker that could *reduce* `src_bytes` by padding it would be a bug pretending to be a result.
    """
    bounds = donors.constraints.levers.get(feature)
    if added <= 0 or bounds is None or category not in bounds:
        return
    position = donors.positions[feature]
    current = _as_int(values[position])
    values[position] = str(current + min(added, max(0, bounds[category].wall - current)))


def apply(flow: Flow, strategy: Strategy, donors: Donors, rng: random.Random) -> Flow:
    """One attack Flow mutated by one Strategy: a donor's whole derived block, the attack's own fixed features, the levers raised.

    This is the free function the gate replays a Strategy with on held-out attack Flows, so it depends on no attacker instance and on
    nothing the search learned. Given the same `rng` state it is deterministic, which is the property the whole generalisation test rests
    on.

    The mutated Flow keeps its parent's `row_id`, `category` and `novel_attack`: the gate pairs on `row_id`
    (`dev-docs/arena-loop-design.md`), and a mutation that relabelled the Flow would be measuring something else entirely.

    A bucket with no donor this Flow could wear degrades to the levers alone rather than raising. That happens for real -- a Strategy
    found on a busy Flow can name a bucket no quiet held-out Flow can reach -- and it is the honest outcome: the technique did not
    transfer, and the gate should see a Flow that says so rather than an exception that hides it.

    Args:
        flow: the attack Flow to mutate.
        strategy: the donor bucket and the two lever settings.
        donors: the bucketed benign Pool Flows, carrying the constraint model.
        rng: the Run's generator; consumed only when a donor is actually drawn.

    Returns:
        A new Flow with the same identity and the mutated attributes.
    """
    values = list(flow.attribute_values)
    donor = choose_donor(donors, flow, strategy.bucket, rng)
    if donor is not None:
        block = donor.flow.attribute_values
        # One donor, the whole block, no mixing: a real block satisfies whatever the true couplings are, and two blocks spliced together
        # satisfy nothing. The roles are read per Category, so a dos Flow keeps the time-based block the model pins for it, and
        # `transplanted` holds back the features the victim writes rather than the sensor.
        for name in donors.constraints.transplanted(flow.category):
            position = donors.positions[name]
            values[position] = block[position]
    _raise_lever(values, donors, flow.category, PADDING, strategy.padding_bytes)
    _raise_lever(values, donors, flow.category, LATENCY, strategy.added_seconds)
    return replace(flow, attributes_csv=",".join(values))


@dataclass
class _Session:
    """One attack Flow's search, and everything it may remember about it.

    Attributes:
        flow: the attack Flow under search.
        judge: the one call the loop lends the attacker.
        donors: the bucketed benign Pool Flows.
        rng: this Flow's generator, seeded from the Run's seed and the row_id.
        observes: `verdict` or `p_attack`, what the attacker is allowed to branch on.
        left: queries still allowed.
        queries: queries spent.
        evaded: whether a probe has flipped the Verdict.
        best: the Strategy that evaded, or the best one tried.
        best_score: the lowest p_attack seen, and None whenever no score may be read.
        start_p_attack: p_attack of the first probe, the untouched Flow.
        last_p_attack: p_attack of the most recent probe.
    """

    flow: Flow
    judge: Judge
    donors: Donors
    rng: random.Random
    observes: str
    left: int
    queries: int = 0
    evaded: bool = False
    best: Strategy | None = None
    best_score: float | None = None
    start_p_attack: float | None = None
    last_p_attack: float | None = None

    @property
    def done(self) -> bool:
        """Whether the search stops here: the Verdict flipped, or the queries ran out.

        It stops on the flip and does not keep pushing p_attack down. That is what an attacker wants -- the alert is gone -- and every
        further query is a Detector call the Budget could have spent elsewhere.
        """
        return self.evaded or self.left <= 0

    def score(self, prediction: Prediction) -> float | None:
        """The one number the search is allowed to rank on, and None whenever it is not allowed one.

        This is the only place `p_attack` can reach the search. With `observes = "verdict"` it returns None unconditionally, so every
        branch downstream sees the same thing whatever the Detector's confidence was. p_attack is still recorded in `Evasion`; recording
        it is the experiment's business, branching on it would be a lie about what the attacker knows.
        """
        if self.observes != "p_attack":
            return None
        p_attack = prediction.get("p_attack")
        return None if p_attack is None else float(p_attack)

    def probe(self, strategy: Strategy) -> None:
        """Spend one query on one Strategy and record what came back; a no-op once the search is done."""
        if self.done:
            return
        prediction = self.judge(apply(self.flow, strategy, self.donors, self.rng))
        self.queries += 1
        self.left -= 1
        p_attack = prediction.get("p_attack")
        self.last_p_attack = None if p_attack is None else float(p_attack)
        if self.queries == 1:
            self.start_p_attack = self.last_p_attack
        if not alerted(prediction):
            self.evaded = True
            self.best = strategy
            return
        self._remember(strategy, self.score(prediction))

    def _remember(self, strategy: Strategy, score: float | None) -> None:
        """Keep the best Strategy tried so far.

        With a score, best means the lowest p_attack. Without one -- `observes = "verdict"`, or a call that failed -- no two failed
        probes can be told apart, so the newest stands: it is the most committed setting the search walked to, and it is the one the
        attacker would carry forward.
        """
        if score is None:
            self.best = strategy
            return
        if self.best_score is None or score < self.best_score:
            self.best, self.best_score = strategy, score

    def climbed(self, strategy: Strategy) -> bool:
        """Probe one rung and say whether the climb goes on: the score fell, or there is no score for it to fall."""
        before = self.best_score
        self.probe(strategy)
        if self.done:
            return False
        return before is None or self.best_score is None or self.best_score < before


class MimicryAttacker:
    """Constrained mimicry by donor substitution, searched by hill-climbing.

    The search is two phases. First one probe per usable donor bucket with the levers at zero, which asks the only question that matters
    at this stage: is there a shape of benign behaviour this attack can hide inside at all? Then the levers are ratcheted from the bucket
    that phase chose, one coordinate at a time, increase-only. Either phase stops the moment the Verdict flips.

    What the two `observes` settings change is which of those moves the attacker may steer:

    - `p_attack`: the bucket phase keeps the lowest p_attack it saw, and each lever rung is kept only while p_attack keeps falling. A
      real hill climb.
    - `verdict`: no failed probe is distinguishable from any other, so there is nothing to steer with. The bucket is the first one in the
      Donors' fixed order that this Flow can use, and the lever ladder is walked in full. It is an enumeration, and saying so is the
      point: an attacker told only "still an alert" has no gradient, and a search that helped itself to p_attack anyway would overstate
      what a black-box attacker can do.
    """

    name = "mimicry"

    def __init__(self, donors: Donors, *, observes: str = "verdict", seed: int = 0) -> None:
        """Hold the donors the attacker studied and the two things that make its search reproducible.

        Args:
            donors: the bucketed benign Pool Flows, from `build_donors`.
            observes: `verdict` or `p_attack`, matching `attacker.observes`.
            seed: the Run's seed; each Flow's generator is seeded from it and the row_id, so one Flow's search replays the same whatever
                order the Flows came in.

        Raises:
            ValueError: `observes` names something the attacker cannot see.
        """
        if observes not in ("verdict", "p_attack"):
            raise ValueError(f"observes = {observes!r}: one of p_attack, verdict")
        self._donors = donors
        self._observes = observes
        self._seed = seed

    def evade(self, flow: Flow, judge: Judge, max_queries: int) -> Evasion:
        """Search for a Strategy this Detector no longer alerts on, spending at most `max_queries` calls.

        Args:
            flow: the attack Flow to hide.
            judge: the loop's Detector call; the loop owns the Context and books the Budget.
            max_queries: the hard cap on Detector calls for this one Flow.

        Returns:
            The Evasion: whether it worked, the Strategy that did it or the best one tried, and what it cost.
        """
        session = _Session(
            flow=flow,
            judge=judge,
            donors=self._donors,
            rng=random.Random(f"{self._seed}:{flow.row_id}"),  # noqa: S311  # seeded, not secret
            observes=self._observes,
            left=max(0, max_queries),
        )
        buckets = self._usable(flow, max_queries)
        session.probe(BASELINE)
        self._hunt(session, buckets)
        self._climb(session, self._start_bucket(session, buckets))
        return Evasion(
            row_id=flow.row_id,
            evaded=session.evaded,
            strategy=session.best,
            queries=session.queries,
            start_p_attack=session.start_p_attack,
            final_p_attack=session.last_p_attack,
        )

    def _usable(self, flow: Flow, max_queries: int) -> tuple[str, ...]:
        """The buckets worth a query for this Flow, in the Donors' fixed order and capped so the levers keep a share of the budget.

        A bucket with no candidate donor is dropped before a query is spent on it: `apply` would hand back the Flow untouched and the
        Detector would repeat what the baseline probe already said.
        """
        usable = [bucket for bucket in self._donors.order if candidates(self._donors, flow, bucket)]
        return tuple(usable[: max(1, int((max_queries - 1) * BUCKET_SHARE))])

    def _hunt(self, session: _Session, buckets: Sequence[str]) -> None:
        """Phase one: one probe per usable bucket, levers at zero, until one evades or the buckets run out."""
        for bucket in buckets:
            if session.done:
                return
            session.probe(Strategy(bucket=bucket, padding_bytes=0, added_seconds=0))

    def _start_bucket(self, session: _Session, buckets: Sequence[str]) -> str:
        """Where the lever climb starts.

        With p_attack visible it is the bucket of the best Strategy tried, which may be `BASELINE` itself when no donor beat the
        untouched Flow -- a legitimate outcome, and one the climb can still improve on with the levers alone.

        With only the Verdict it is the first usable bucket in the Donors' fixed order, a choice that depends on the Pool and on this
        Flow and on nothing the Detector said. This branch is the one the tests pin: two Detectors that return the same Verdicts and
        different p_attack must send this attacker down the identical path.
        """
        if session.observes == "p_attack" and session.best is not None:
            return session.best.bucket
        return buckets[0] if buckets else NO_DONOR

    def _climb(self, session: _Session, bucket: str) -> None:
        """Phase two: ratchet the two levers from one bucket, padding first and then latency, keeping what helps.

        Coordinate-wise and increase-only, so each rung is a setting the attacker could actually hold: more junk in the request, then
        more delay on top of it.
        """
        padding = 0
        for rung in lever_rungs(session.donors, session.flow, PADDING):
            if session.done or not session.climbed(Strategy(bucket=bucket, padding_bytes=rung, added_seconds=0)):
                break
            padding = rung
        for rung in lever_rungs(session.donors, session.flow, LATENCY):
            if session.done or not session.climbed(Strategy(bucket=bucket, padding_bytes=padding, added_seconds=rung)):
                break
