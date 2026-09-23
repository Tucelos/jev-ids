"""Fit the empirical constraint model for an evasive attacker on NSL-KDD and write it as `data/nsl-kdd/mutations.json`.

Run from the repository root, after `scripts/prepare_nsl_kdd.py` has built the Pool:

    uv run python -m scripts.fit_mutations

An attacker cannot write NSL-KDD feature values: the nineteen time-based and host-based features are recomputed by the sensor from the
attacker's connection log, so the attacker is parameterised by behaviour and the derived features move as a joint consequence
(`dev-docs/research-evasion-constraints.md` §4). This script turns that argument into an auditable data file. It never mutates a Flow and
never searches: it measures the Pool, decides which of the report's predicted couplings the data actually supports, and emits the model.

In reading order:

- `Rule`, `FEATURE_RULES`, `ROLE_OVERRIDES`: the role of each of the 41 card features, its one-line justification and its citation.
- `BEHAVIOUR_KNOBS`: what the attacker actually turns, and which features each knob moves in which direction.
- `DEVIATIONS`: where this model departs from the research report, and why.
- `sum_residual`, `capped_ratio_residual`, `order_residual`, `constant_residual`: the four shapes a coupling residual takes.
- `Coupling`, `COUPLINGS`: the identities the report predicts, each with the rounding slack its features' precision allows.
- `read_flows`, `sha256_of`, `quantile`, `spread`, `tally`: reading the CSVs and summarising what they hold.
- `coupling_residuals`, `summarise`, `measure_couplings`: the violation rate and residual distribution of every coupling, on both files.
- `split_by_frequency`, `shared_services`, `measure_symbolic`: which `service` and `flag` values each `protocol_type` admits.
- `measure_errors_by_flag`: how the error-rate family follows `flag`, the one coupling of §4 that is symbolic rather than numeric.
- `measure_levers`: bounds for `duration` and `src_bytes`, per Category, so increase-only perturbation has data-backed ceilings.
- `content_profile`, `attack_signature`, `measure_signatures`: the r2l signature per attack name and the dos content block.
- `measure_constants`: the features that carry no information because the Pool holds one value for them.
- `validate_tables`: refuses to emit a model whose own hand-written tables use a word outside the vocabulary.
- `feature_card`, `provenance`, `build`, `main`: assembling the model and writing it out.
"""

import argparse
import csv
import hashlib
import json
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NamedTuple

from jev_ids.dataset import Config, load_config

SCHEMA_VERSION = "1"

# One Flow as its CSV line has it; the card's features plus `category`, `novel_attack`, `attack_name` and `difficulty`.
Flow = dict[str, str]
Flows = list[Flow]
Residual = Callable[[Mapping[str, str]], float | None]

# The nine time-based and ten host-based features of the KDD Cup 99 task description: the block the sensor recomputes.
TIME_BASED = (
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
)
HOST_BASED = (
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
)
# The twelve content features. IDSGAN Table 1 marks them functional for r2l; in real dos Flows they are near-identically zero.
CONTENT = (
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "is_host_login",
    "is_guest_login",
)

# The three vocabularies, defined once here and emitted verbatim into the model, so the words the file uses and the words it defines cannot
# drift apart. `validate_tables` checks the hand-written tables below against them before anything is written.
ROLE_MEANING = {
    "direct": "The attacker sets it by choosing its own behaviour.",
    "derived": "The sensor recomputes it from the connection log; reachable only as a joint consequence of behaviour.",
    "fixed": "Attack semantics or a definitional invariant pins it; changing it destroys the attack or the plausibility.",
}
# `dilute_toward_background` is the report's §4 point that a *ratio* over a fixed 2 s window is not lowered by slowing down: the attacker's
# share of the window shrinks and the value drifts toward the ambient traffic mix instead.
EFFECT_MEANING = {
    "increase": "The knob raises the feature.",
    "decrease": "The knob lowers the feature.",
    "dilute_toward_background": "A ratio over a fixed 2 s window; slowing down shrinks the attacker's share of it, so the value drifts "
    "toward the ambient traffic mix instead of falling with the rate.",
    "near_invariant": "Computed over a 100-connection window rather than a time span, so slowing down barely moves it.",
    "unchanged": "The knob does not touch it.",
    "unspecified": "The research report's §4 gives no direction and this project will not guess one.",
}
SUPPORT_MEANING = {
    "cited": "The cited work states it.",
    "synthesis": "The research report marks it as its own reasoning.",
}
ROLES = tuple(ROLE_MEANING)
EFFECTS = tuple(EFFECT_MEANING)
SUPPORT = tuple(SUPPORT_MEANING)

# The share above which an error rate dominates its window: the threshold the `flag` coupling is reported at.
MAJORITY = 0.5

KDD_TASK = "KDD Cup 1999 task description (Lee & Stolfo, ACM TISSEC 3(4), 2000)"
APRUZZESE_TETCI = "Apruzzese et al., IEEE TETCI 4(4), 2020, pp. 427-439"
PIERAZZI = "Pierazzi et al., IEEE S&P 2020, pp. 1332-1349"
SHEATSLEY = "Sheatsley et al., arXiv:2011.01183, 2020"
IDSGAN = "Lin, Shi, Xue, IDSGAN, PAKDD 2022, arXiv:1809.02077"


class Rule(NamedTuple):
    """The role one card feature gets in the constraint model, and what that role rests on.

    Attributes:
        role: `direct` (the attacker sets it by choosing its own behaviour), `derived` (the sensor recomputes it from the connection log)
            or `fixed` (attack semantics or a definitional invariant pin it).
        why: one line saying why the feature has that role.
        citation: the work the role rests on.
        support: `cited` when the cited work states it, `synthesis` where the research report marks the claim as its own reasoning.
    """

    role: str
    why: str
    citation: str
    support: str


def _direct(why: str) -> Rule:
    """A lever the attacker turns itself; the citation is always the TETCI paper that perturbs exactly these NetFlow fields."""
    return Rule("direct", why, APRUZZESE_TETCI, "cited")


def _derived(why: str) -> Rule:
    """A feature the sensor recomputes from the connection log; the citation is always the KDD task description."""
    return Rule("derived", why, KDD_TASK, "synthesis")


def _fixed(why: str, citation: str, support: str) -> Rule:
    """A feature that attack semantics or a definitional invariant pins."""
    return Rule("fixed", why, citation, support)


def _content(why: str) -> Rule:
    """A content feature: the r2l payload determines it, so it is fixed by attack semantics."""
    return Rule("fixed", why, f"{IDSGAN} (Table 1, verified)", "cited")


# The role of every one of the 41 card features, in card order. Read this table against the research report's "Proposed feature partition".
FEATURE_RULES: dict[str, Rule] = {
    "duration": _direct("The attacker adds latency; increase-only and bounded by what the sensor ever observed."),
    "protocol_type": _fixed("It decides which services and flags are admissible at all.", SHEATSLEY, "cited"),
    "service": _fixed("Constrained by the protocol, and r2l attacks are service-defined.", SHEATSLEY, "cited"),
    "flag": _derived("TCP termination status is an outcome of the connection, not a field the attacker writes."),
    "src_bytes": _direct("The attacker pads the request with junk data; increase-only and bounded."),
    "dst_bytes": _derived("The r2l victim server decides how much it answers; only a botnet attacker owns both ends."),
    "land": _fixed("Definitional invariant: source host and port equal destination host and port.", KDD_TASK, "cited"),
    "wrong_fragment": _fixed("Definitional for fragmentation dos (teardrop) and zero for r2l.", KDD_TASK, "synthesis"),
    "urgent": _fixed("Settable via the URG pointer, but non-zero values are conspicuous.", PIERAZZI, "synthesis"),
    "hot": _content("The payload decides how many hot indicators the session touches."),
    "num_failed_logins": _content("This is the guess_passwd signal itself; zeroing it removes the attack."),
    "logged_in": _content("Whether the login succeeded follows from the credentials the payload carries."),
    "num_compromised": _content("Counted from compromised-condition indicators the payload triggers."),
    "root_shell": _content("Whether a root shell was obtained is the u2r payload's own result."),
    "su_attempted": _content("Whether `su root` was attempted is part of the payload."),
    "num_root": _content("Counted from root accesses the payload performs."),
    "num_file_creations": _content("Counted from file-creation operations the payload performs."),
    "num_shells": _content("Counted from shell prompts the payload obtains."),
    "num_access_files": _content("Counted from accesses to access-control files the payload performs."),
    "num_outbound_cmds": _fixed("Degenerate: identically zero, so it carries no information to perturb.", KDD_TASK, "synthesis"),
    "is_host_login": _content("Whether the login belongs to the host list is a property of the account used."),
    "is_guest_login": _content("Whether the login is a guest account is a property of the account used."),
    "count": _derived("Connections to the same host in a fixed 2 s window; falls as the attacker slows down."),
    "srv_count": _derived("Connections to the same service in a fixed 2 s window; falls as the attacker slows down."),
    "serror_rate": _derived("SYN-error ratio over the 2 s same-host window; tied to `flag`."),
    "srv_serror_rate": _derived("SYN-error ratio over the 2 s same-service window; tied to `flag`."),
    "rerror_rate": _derived("REJ-error ratio over the 2 s same-host window; tied to `flag`."),
    "srv_rerror_rate": _derived("REJ-error ratio over the 2 s same-service window; tied to `flag`."),
    "same_srv_rate": _derived("Same-service share of the 2 s same-host window; moves only through service spread."),
    "diff_srv_rate": _derived("Different-service share of the 2 s same-host window; moves only through service spread."),
    "srv_diff_host_rate": _derived("Different-host share of the 2 s same-service window; rises with host spread."),
    "dst_host_count": _derived("Counted over 100 connections to the same host, a window built to defeat a slow attacker."),
    "dst_host_srv_count": _derived("Counted over 100 connections to the same service, so slowing down does not move it."),
    "dst_host_same_srv_rate": _derived("Same-service share of the 100-connection host window; moves through service spread."),
    "dst_host_diff_srv_rate": _derived("Different-service share of the 100-connection host window; moves through service spread."),
    "dst_host_same_src_port_rate": _derived("Same-source-port share of the 100-connection host window; falls under randomisation."),
    "dst_host_srv_diff_host_rate": _derived("Different-host share of the 100-connection service window; rises with host spread."),
    "dst_host_serror_rate": _derived("SYN-error ratio over the 100-connection host window; follows from the outcomes."),
    "dst_host_srv_serror_rate": _derived("SYN-error ratio over the 100-connection service window; follows from the outcomes."),
    "dst_host_rerror_rate": _derived("REJ-error ratio over the 100-connection host window; follows from the outcomes."),
    "dst_host_srv_rerror_rate": _derived("REJ-error ratio over the 100-connection service window; follows from the outcomes."),
}

# For dos a high connection rate *is* the attack, so the nine time-based features stop being free consequences of behaviour and become
# attack semantics; `flag=S0` is definitional for neptune. IDSGAN frees the content block for dos, which this model refuses: see DEVIATIONS.
ROLE_OVERRIDES: dict[str, dict[str, str]] = {
    "dos": {"flag": "fixed", **dict.fromkeys(TIME_BASED, "fixed")},
}

# What the attacker actually turns. Directions come from the research report's §4 causal model; only the features it names get a
# direction, the rest stay `unspecified` rather than being guessed.
BEHAVIOUR_KNOBS: dict[str, dict[str, Any]] = {
    "inter_connection_interval": {
        "description": "Seconds between the attacker's successive connections; the report's lambda.",
        "direction": "increase_only",
        "rationale": "Counts over a fixed 2 s window fall with the rate; ratios over the same window do not, they dilute toward the "
        "ambient background; the 100-connection host windows were built precisely to stay invariant to this.",
        "citation": KDD_TASK,
        "support": "synthesis",
        "effects": {
            "count": {"direction": "decrease", "basis": "raw count in a fixed 2 s window"},
            "srv_count": {"direction": "decrease", "basis": "raw count in a fixed 2 s window"},
            "same_srv_rate": {"direction": "dilute_toward_background", "drift": "decrease", "basis": "ratio over the 2 s window"},
            "diff_srv_rate": {"direction": "dilute_toward_background", "drift": "increase", "basis": "ratio over the 2 s window"},
            "serror_rate": {"direction": "dilute_toward_background", "basis": "ratio over the 2 s window"},
            "srv_serror_rate": {"direction": "dilute_toward_background", "basis": "ratio over the 2 s window"},
            "rerror_rate": {"direction": "dilute_toward_background", "basis": "ratio over the 2 s window"},
            "srv_rerror_rate": {"direction": "dilute_toward_background", "basis": "ratio over the 2 s window"},
            "srv_diff_host_rate": {"direction": "unspecified", "basis": "the report's §4 does not give this ratio a direction"},
            **{f: {"direction": "near_invariant", "basis": "window is 100 connections, not a time span"} for f in HOST_BASED},
        },
    },
    "host_spread": {
        "description": "How many distinct destination hosts the attacker's connections are spread over; the report's H.",
        "direction": "increase_only",
        "rationale": "Spreading the same work over more hosts thins every per-host window and raises the different-host shares.",
        "citation": KDD_TASK,
        "support": "synthesis",
        "effects": {
            "count": {"direction": "decrease", "basis": "fewer connections land on any one host"},
            "srv_count": {"direction": "unchanged", "basis": "the same service is still targeted everywhere"},
            "srv_diff_host_rate": {"direction": "increase", "basis": "same-service connections now reach more hosts"},
            "dst_host_count": {"direction": "decrease", "basis": "per-target 100-connection host window thins"},
            "dst_host_srv_count": {"direction": "decrease", "basis": "per-target 100-connection service window thins"},
            "dst_host_srv_diff_host_rate": {"direction": "increase", "basis": "same-service connections now reach more hosts"},
        },
    },
    "service_spread": {
        "description": "How many distinct services or destination ports the attacker touches; the report's S.",
        "direction": "increase_only",
        "rationale": "Touching more services moves weight out of the same-service share and into the different-service share.",
        "citation": KDD_TASK,
        "support": "synthesis",
        "effects": {
            "same_srv_rate": {"direction": "decrease", "basis": "same-service share of the 2 s window"},
            "diff_srv_rate": {"direction": "increase", "basis": "different-service share of the 2 s window"},
            "dst_host_same_srv_rate": {"direction": "decrease", "basis": "same-service share of the 100-connection host window"},
            "dst_host_diff_srv_rate": {"direction": "increase", "basis": "different-service share of the 100-connection host window"},
        },
    },
    "source_port_reuse": {
        "description": "How often the attacker reuses the same source port; lowering it means source-port randomisation.",
        "direction": "decrease_only",
        "rationale": "The 100-connection host window records the same-source-port share, so randomising the port lowers it.",
        "citation": KDD_TASK,
        "support": "synthesis",
        "effects": {
            "dst_host_same_src_port_rate": {"direction": "decrease", "basis": "same-source-port share of the 100-connection host window"},
        },
    },
    "byte_padding": {
        "description": "Junk data appended to the attacker's own request.",
        "direction": "increase_only",
        "rationale": "Adding random junk data does not alter the underlying logic; excessive increases generate anomalous Flows.",
        "citation": APRUZZESE_TETCI,
        "support": "cited",
        "effects": {"src_bytes": {"direction": "increase", "basis": "the attacker writes these bytes itself"}},
        "bounded_by": "direct_levers.src_bytes",
    },
    "added_latency": {
        "description": "Extra delay held inside a single connection.",
        "direction": "increase_only",
        "rationale": "Evasion by increasing flow duration through a small latency; flow collectors cap the maximum duration.",
        "citation": APRUZZESE_TETCI,
        "support": "cited",
        "effects": {"duration": {"direction": "increase", "basis": "the attacker holds the connection open"}},
        "bounded_by": "direct_levers.duration",
    },
}

# Where this model departs from `dev-docs/research-evasion-constraints.md`. A supervisor should be able to find every disagreement here.
DEVIATIONS: list[dict[str, str]] = [
    {
        "subject": "urgent",
        "report": "direct but implausible",
        "model": "fixed",
        "why": "The role vocabulary has no `implausible` value, and the report itself removes the feature by Pierazzi's plausibility "
        "constraint. The Pool agrees: `urgent` is zero in 99.99% of Flows, so any non-zero value is conspicuous.",
    },
    {
        "subject": "dst_bytes",
        "report": "r2l: derived; dos: direct in botnet settings",
        "model": "derived for every Category",
        "why": "The botnet scope condition does not hold in NSL-KDD: dos here targets a third-party victim that decides its own response, "
        "so the attacker does not own the far endpoint.",
    },
    {
        "subject": "content features under dos",
        "report": "IDSGAN Table 1 frees the content block for dos",
        "model": "fixed for every Category",
        "why": "Nine of the twelve content features are identically zero across every dos Flow of the Pool; writing non-zero values there "
        "asserts application-layer activity that never happened. Measured exceptions are recorded under category_signatures.dos.",
    },
    {
        "subject": "coupling identities",
        "report": "§4 predicts four hard couplings from the published definitions",
        "model": "three of the four are rejected on the Pool's own evidence",
        "why": "`count`/`srv_count` and `dst_host_count`/`dst_host_srv_count` are not nested: each pair is computed over two parallel "
        "windows (same host, same service). See couplings for the measured violation rates.",
    },
]


def sum_residual(left: str, right: str) -> Residual:
    """How far `left + right` sits from 1: the residual of a claimed partition of one window."""

    def measure(flow: Mapping[str, str]) -> float | None:
        return abs(float(flow[left]) + float(flow[right]) - 1.0)

    return measure


def capped_ratio_residual(rate: str, numerator: str, denominator: str) -> Residual:
    """How far `rate` sits from `numerator / denominator`, capped at 1 because a stored rate never exceeds it.

    Undefined, so skipped, when the denominator is zero.
    """

    def measure(flow: Mapping[str, str]) -> float | None:
        bottom = int(flow[denominator])
        if bottom == 0:
            return None
        return abs(float(flow[rate]) - min(1.0, int(flow[numerator]) / bottom))

    return measure


def order_residual(smaller: str, larger: str) -> Residual:
    """By how many connections `smaller` exceeds `larger`; zero when the claimed ordering holds."""

    def measure(flow: Mapping[str, str]) -> float | None:
        return float(max(0, int(flow[smaller]) - int(flow[larger])))

    return measure


def constant_residual(name: str, value: float) -> Residual:
    """How far a feature sits from the constant it is claimed to be."""

    def measure(flow: Mapping[str, str]) -> float | None:
        return abs(float(flow[name]) - value)

    return measure


class Coupling(NamedTuple):
    """One identity the research report predicts between derived features, and the slack its features' precision allows.

    Attributes:
        id: stable key for the entry in `mutations.json`.
        statement: the identity in the card's own feature names.
        features: the card features the statement mentions.
        residual: how far one Flow sits from the identity, or None when the identity is undefined for it.
        unit: `rate` for a residual between two two-decimal rates, `connections` for one between two integer counts.
        slack: the largest residual the stored precision alone can produce; the identity is accepted when its p99 residual fits inside it.
        predicted: where the report predicts the identity.
        support: `cited` or `synthesis`, carried over from the report's own marking.
        note: what the measurement means, written after the numbers were in.
    """

    id: str
    statement: str
    features: tuple[str, ...]
    residual: Residual
    unit: str
    slack: float
    predicted: str
    support: str
    note: str


# The four identities the report's §4 predicts, the `num_outbound_cmds` degeneracy it asks to verify, and the two replacements the Pool
# itself suggested once the first round of measurements came back. Rates are stored to two decimals, so a sum of two rounded rates can be
# off by 0.01 and a single rounded rate by 0.005; integer counts have no slack at all.
COUPLINGS: tuple[Coupling, ...] = (
    Coupling(
        "same_srv_partition",
        "same_srv_rate + diff_srv_rate == 1",
        ("same_srv_rate", "diff_srv_rate"),
        sum_residual("same_srv_rate", "diff_srv_rate"),
        "rate",
        0.01,
        "research report §4, hard couplings",
        "synthesis",
        "Rejected. The two rates do not partition one window: `same_srv_rate` is the same-service share of the 2 s same-host window "
        "while `diff_srv_rate` behaves as a count of distinct other services over the same denominator, so the sum is usually far "
        "below 1 and sometimes above it. An attacker model must not treat `diff_srv_rate` as `1 - same_srv_rate`.",
    ),
    Coupling(
        "dst_host_srv_partition",
        "dst_host_same_srv_rate + dst_host_diff_srv_rate == 1",
        ("dst_host_same_srv_rate", "dst_host_diff_srv_rate"),
        sum_residual("dst_host_same_srv_rate", "dst_host_diff_srv_rate"),
        "rate",
        0.01,
        "research report §4, hard couplings",
        "synthesis",
        "Rejected, and more severely than its 2 s twin: the two host-based rates are computed over two different 100-connection "
        "windows (same host, same service), so they have no reason to sum to 1.",
    ),
    Coupling(
        "dst_host_srv_count_ordering",
        "dst_host_srv_count <= dst_host_count",
        ("dst_host_srv_count", "dst_host_count"),
        order_residual("dst_host_srv_count", "dst_host_count"),
        "connections",
        0.0,
        "research report §4, hard couplings",
        "synthesis",
        "Rejected. The two counts are not nested: `dst_host_count` counts inside the last 100 connections to the same host and "
        "`dst_host_srv_count` inside the last 100 connections to the same service. Verified against the raw KDDTrain+ lines.",
    ),
    Coupling(
        "srv_count_ordering",
        "srv_count <= count",
        ("srv_count", "count"),
        order_residual("srv_count", "count"),
        "connections",
        0.0,
        "this project, the 2 s mirror of the ordering the report predicts for the 100-connection windows",
        "synthesis",
        "Rejected, for the same reason as its host-based twin: `count` is a same-host window and `srv_count` a same-service one.",
    ),
    Coupling(
        "dst_host_same_srv_rate_ratio",
        "dst_host_same_srv_rate == min(1, dst_host_srv_count / dst_host_count)",
        ("dst_host_same_srv_rate", "dst_host_srv_count", "dst_host_count"),
        capped_ratio_residual("dst_host_same_srv_rate", "dst_host_srv_count", "dst_host_count"),
        "rate",
        0.01,
        "research report §4, hard couplings",
        "synthesis",
        "Rejected as a hard constraint although it very nearly holds: the residual sits inside the rounding slack for most Flows but "
        "its p99 is two orders of magnitude outside it, again because numerator and denominator come from two different windows.",
    ),
    Coupling(
        "same_srv_rate_ratio",
        "same_srv_rate == min(1, srv_count / count)",
        ("same_srv_rate", "srv_count", "count"),
        capped_ratio_residual("same_srv_rate", "srv_count", "count"),
        "rate",
        0.01,
        "this project, fitted after the report's four predictions were measured",
        "synthesis",
        "Accepted: the only rate identity the Pool supports. It is the usable replacement for the rejected partition, and it is what "
        "forces `same_srv_rate` to move whenever behaviour moves `count` or `srv_count`. Weaker on KDDTest+, see measured.test.",
    ),
    Coupling(
        "num_outbound_cmds_degenerate",
        "num_outbound_cmds == 0",
        ("num_outbound_cmds",),
        constant_residual("num_outbound_cmds", 0.0),
        "connections",
        0.0,
        "research report §4, open question 4",
        "synthesis",
        "Accepted exactly, in the Pool and in KDDTest+. The feature carries no information, so perturbing it is a wasted move.",
    ),
)


def read_flows(path: Path) -> Flows:
    """Every Flow of one CSV in the shared shape, as its columns have it."""
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def sha256_of(path: Path) -> str:
    """The hash of a file's bytes, read in chunks because the Pool is twenty megabytes."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def quantile(ordered: Sequence[float], point: float) -> float:
    """The nearest-rank quantile of an already sorted sequence."""
    return ordered[min(len(ordered) - 1, round(point * (len(ordered) - 1)))]


def spread(values: Sequence[float]) -> dict[str, float]:
    """The p50, p90, p99 and maximum of a sequence, empty when it holds nothing.

    Nearest-rank rather than interpolated, so every reported number is a value the data actually holds.
    """
    if not values:
        return {}
    ordered = sorted(values)
    return {"p50": quantile(ordered, 0.5), "p90": quantile(ordered, 0.9), "p99": quantile(ordered, 0.99), "max": ordered[-1]}


def tally(flows: Flows, name: str) -> list[tuple[str, int]]:
    """Every value of one column with its Flow count, commonest first and ties broken by value so the file is reproducible."""
    counted = Counter(flow[name] for flow in flows)
    return sorted(counted.items(), key=lambda pair: (-pair[1], pair[0]))


def coupling_residuals(coupling: Coupling, flows: Flows) -> list[float]:
    """Every defined residual of one coupling over one file, sorted; a Flow the identity says nothing about is left out."""
    return sorted(value for value in (coupling.residual(flow) for flow in flows) if value is not None)


def summarise(residuals: Sequence[float], total: int, thresholds: Mapping[str, float]) -> dict[str, Any]:
    """The residual distribution of one coupling over one file, plus its violation rate at each named threshold.

    The thresholds are named rather than implied because `slack` and `tolerance` are different numbers and a consumer that confuses them
    would under-report violations.
    """
    if not residuals:
        return {"flows": 0, "skipped_undefined": total}
    measured: dict[str, Any] = {"flows": len(residuals), "skipped_undefined": total - len(residuals)}
    for name, threshold in thresholds.items():
        violations = sum(1 for value in residuals if value > threshold)
        measured[f"violations_above_{name}"] = violations
        measured[f"violation_rate_above_{name}"] = round(violations / len(residuals), 6)
    measured["residual"] = {key: round(value, 6) for key, value in spread(residuals).items()}
    return measured


def measure_couplings(pool: Flows, test: Flows) -> list[dict[str, Any]]:
    """Every coupling measured on the Pool and on the test file, with the verdict the Pool's own evidence forces.

    A coupling is accepted only when its p99 residual on the Pool fits inside the slack its features' stored precision allows. The tolerance
    an accepted coupling ships with is that measured p99 and nothing wider: a tolerance nobody measured is a tolerance nobody can defend.
    """
    entries: list[dict[str, Any]] = []
    for coupling in COUPLINGS:
        on_pool = coupling_residuals(coupling, pool)
        # Rounded to the precision the residual quantiles are reported at, and rounded *before* being used as a threshold, so the
        # violation rate the file quotes is the rate at the tolerance the file ships, not at an unrounded neighbour of it.
        p99 = round(quantile(on_pool, 0.99), 6) if on_pool else 0.0
        accepted = p99 <= coupling.slack
        thresholds = {"slack": coupling.slack, "tolerance": p99} if accepted else {"slack": coupling.slack}
        entries.append(
            {
                "id": coupling.id,
                "statement": coupling.statement,
                "features": list(coupling.features),
                "unit": coupling.unit,
                "rounding_slack": coupling.slack,
                "predicted_by": coupling.predicted,
                "support": coupling.support,
                "verdict": "accepted" if accepted else "rejected",
                "enforce": accepted,
                "tolerance": p99 if accepted else None,
                "note": coupling.note,
                "measured": {
                    "pool": summarise(on_pool, len(pool), thresholds),
                    "test": summarise(coupling_residuals(coupling, test), len(test), thresholds),
                },
            }
        )
    return entries


def split_by_frequency(flows: Flows, column: str, rare_below: int) -> dict[str, dict[str, int]]:
    """Every value of one column with its Flow count, the common ones kept apart from the rare ones.

    Rare is not forbidden: it is kept separate because reaching for a combination the sensor has seen twice is itself conspicuous.
    """
    common: dict[str, int] = {}
    rare: dict[str, int] = {}
    for value, count in tally(flows, column):
        group = common if count >= rare_below else rare
        group[value] = count
    return {"common": common, "rare": rare}


def shared_services(by_protocol: Mapping[str, Any]) -> list[str]:
    """The services more than one protocol carries; almost none do, which is Sheatsley et al.'s point in one line."""
    carriers: Counter[str] = Counter()
    for entry in by_protocol.values():
        for group in entry["service"].values():
            # `.keys()`, not the mapping itself: Counter.update sums a mapping's values, and here each protocol must count once.
            carriers.update(group.keys())
    return sorted(service for service, protocols_seen in carriers.items() if protocols_seen > 1)


def measure_symbolic(pool: Flows, test: Flows, rare_below: int) -> dict[str, Any]:
    """Which `service` and `flag` values occur with each `protocol_type`, common and rare kept apart.

    This is the answer to Sheatsley et al.'s critique: a `service` the protocol never carries yields an infeasible Flow, so a mutation that
    switches one must stay inside this table.
    """
    by_protocol: dict[str, Any] = {}
    for protocol in sorted({flow["protocol_type"] for flow in pool}):
        inside = [flow for flow in pool if flow["protocol_type"] == protocol]
        by_protocol[protocol] = {
            "flows": len(inside),
            "service": split_by_frequency(inside, "service", rare_below),
            "flag": split_by_frequency(inside, "flag", rare_below),
        }
    pool_services = {flow["service"] for flow in pool}
    return {
        "rare_below_flows": rare_below,
        "by_protocol_type": by_protocol,
        "services_on_more_than_one_protocol": shared_services(by_protocol),
        "services_in_test_but_not_in_pool": sorted({flow["service"] for flow in test} - pool_services),
    }


def measure_errors_by_flag(pool: Flows) -> dict[str, Any]:
    """How `serror_rate` and `rerror_rate` follow `flag`: the one coupling of the report's §4 that is symbolic rather than numeric."""
    by_flag: dict[str, Any] = {}
    for flag in sorted({flow["flag"] for flow in pool}):
        inside = [flow for flow in pool if flow["flag"] == flag]
        dominant = {
            f"{rate}_above_half": round(sum(float(flow[rate]) > MAJORITY for flow in inside) / len(inside), 4)
            for rate in ("serror_rate", "rerror_rate")
        }
        by_flag[flag] = {"flows": len(inside), **dominant}
    return {
        "statement": "`flag` fixes the error-rate family: a Flow cannot keep flag=S0 and drop serror_rate, nor keep REJ and drop rerror.",
        "features": ["flag", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate"],
        "support": "synthesis",
        "citation": KDD_TASK,
        "by_flag": by_flag,
    }


def measure_levers(pool: Flows, categories: Sequence[str]) -> dict[str, Any]:
    """Empirical bounds for `duration` and `src_bytes`, per Category, so increase-only perturbation has data-backed ceilings.

    A perturbation that pushes a Flow past what the sensor ever observed for its Category is implausible, so the p99 is the ceiling a
    mutation should respect and the maximum is the hardest wall there is.
    """
    levers: dict[str, Any] = {}
    for name, unit, citation in (("duration", "seconds", APRUZZESE_TETCI), ("src_bytes", "bytes", APRUZZESE_TETCI)):
        by_category: dict[str, Any] = {}
        for category in categories:
            values = [float(flow[name]) for flow in pool if flow["category"] == category]
            by_category[category] = {"flows": len(values), "min": min(values, default=0.0), **spread(values)}
        levers[name] = {
            "direction": "increase_only",
            "unit": unit,
            "citation": citation,
            "support": "cited",
            "plausible_ceiling": "p99",
            "hard_ceiling": "max",
            "by_category": by_category,
        }
    return levers


def content_profile(flows: Flows, names: Sequence[str]) -> dict[str, Any]:
    """For each named content feature, the share of Flows holding a non-zero value and its commonest three values."""
    return {
        name: {
            "nonzero_rate": round(sum(flow[name] != "0" for flow in flows) / len(flows), 4),
            "top_values": [[value, count] for value, count in tally(flows, name)[:3]],
        }
        for name in names
    }


def attack_signature(flows: Flows, content_features: Sequence[str]) -> dict[str, Any]:
    """One attack name's profile: its content features, the symbols it occurs with and the two direct levers."""
    return {
        "flows": len(flows),
        "content": content_profile(flows, content_features),
        "service": [[value, count] for value, count in tally(flows, "service")[:4]],
        "flag": [[value, count] for value, count in tally(flows, "flag")[:3]],
        "duration": spread([float(flow["duration"]) for flow in flows]),
        "src_bytes": spread([float(flow["src_bytes"]) for flow in flows]),
    }


def measure_signatures(pool: Flows) -> dict[str, Any]:
    """The r2l signature per `attack_name` and the dos content block, the two claims the report asks to be checked.

    The r2l entries are what makes `fixed` defensible for the content block: if a content feature is the attack's own signal, zeroing it to
    evade detection also removes the attack.
    """
    named = (
        "num_failed_logins",
        "hot",
        "is_guest_login",
        "logged_in",
        "num_file_creations",
        "num_compromised",
        "root_shell",
        "num_access_files",
    )
    r2l = [flow for flow in pool if flow["category"] == "r2l"]
    by_name = {
        attack: attack_signature([flow for flow in r2l if flow["attack_name"] == attack], named)
        for attack in sorted({flow["attack_name"] for flow in r2l})
    }
    dos = [flow for flow in pool if flow["category"] == "dos"]
    dos_content = content_profile(dos, CONTENT)
    return {
        "r2l": {"flows": len(r2l), "content_features_checked": list(named), "by_attack_name": by_name},
        "dos": {
            "flows": len(dos),
            "content": dos_content,
            "content_features_identically_zero": sorted(name for name, entry in dos_content.items() if entry["nonzero_rate"] == 0.0),
        },
    }


def measure_constants(pool: Flows, features: Sequence[str], near_at: float) -> dict[str, Any]:
    """Which card features are constant in the Pool, and which are near-constant enough to carry almost no information."""
    constant: list[dict[str, Any]] = []
    near_constant: list[dict[str, Any]] = []
    for name in features:
        counted = tally(pool, name)
        value, count = counted[0]
        share = count / len(pool)
        entry = {"feature": name, "value": value, "share": round(share, 6), "distinct_values": len(counted)}
        if len(counted) == 1:
            constant.append(entry)
        elif share >= near_at:
            near_constant.append(entry)
    return {"near_constant_threshold": near_at, "constant": constant, "near_constant": near_constant}


def _feature_offenders() -> list[str]:
    """Entries of the feature table, or of its per-Category overrides, whose role or support marker is not in the vocabulary."""
    offenders = [f"features.{name}" for name, rule in FEATURE_RULES.items() if rule.role not in ROLES or rule.support not in SUPPORT]
    for category, roles in ROLE_OVERRIDES.items():
        offenders += [f"role_overrides.{category}.{name}" for name, role in roles.items() if role not in ROLES]
    return offenders


def _knob_offenders() -> list[str]:
    """Entries of the knob table, or of the coupling table, whose effect or support marker is not in the vocabulary."""
    offenders = [f"couplings.{coupling.id}" for coupling in COUPLINGS if coupling.support not in SUPPORT]
    for knob, entry in BEHAVIOUR_KNOBS.items():
        if entry["support"] not in SUPPORT:
            offenders.append(f"knobs.{knob}.support")
        offenders += [f"knobs.{knob}.{name}" for name, effect in entry["effects"].items() if effect["direction"] not in EFFECTS]
    return offenders


def validate_tables() -> None:
    """Refuse to emit a model whose own hand-written tables use a word outside the vocabulary.

    The feature table has 41 entries and the knob table six; a typo in a role or an effect would otherwise reach `mutations.json` and be
    caught only by the tests, one step later than it should be.

    Raises:
        ValueError: when a role, an effect or a support marker sits outside its vocabulary.
    """
    offenders = _feature_offenders() + _knob_offenders()
    if offenders:
        raise ValueError(f"these entries use a word outside the vocabulary: {offenders}")


def feature_card(features: Sequence[str]) -> dict[str, Any]:
    """The role, justification and citation of every card feature, with the per-Category overrides attached.

    Raises:
        ValueError: when the rule table and the card disagree about which features exist.
    """
    missing = [name for name in features if name not in FEATURE_RULES]
    extra = [name for name in FEATURE_RULES if name not in features]
    if missing or extra:
        raise ValueError(f"rule table does not match the card: missing {missing}, unknown {extra}")
    card: dict[str, Any] = {}
    for name in features:
        rule = FEATURE_RULES[name]
        entry: dict[str, Any] = {"role": rule.role, "why": rule.why, "citation": rule.citation, "support": rule.support}
        overrides = {category: roles[name] for category, roles in ROLE_OVERRIDES.items() if name in roles}
        if overrides:
            entry["role_by_category"] = overrides
        card[name] = entry
    return card


def provenance(dataset: Path, card: Config, pool: Path, test: Path, sizes: tuple[int, int]) -> dict[str, Any]:
    """Where the model came from: the files it was fitted on, their hashes and the date, so the fit can be repeated or refuted."""
    return {
        "fitted_on": datetime.now(UTC).date().isoformat(),
        "script": "scripts/fit_mutations.py",
        "dataset": card["name"],
        "card": {"path": f"{dataset.as_posix()}/dataset.json", "sha256": card["sha256"]},
        "pool": {"path": pool.as_posix(), "sha256": sha256_of(pool), "flows": sizes[0]},
        "test": {"path": test.as_posix(), "sha256": sha256_of(test), "flows": sizes[1]},
        "research_report": "dev-docs/research-evasion-constraints.md",
        "findings": "dev-docs/empirical-constraints-findings.md",
    }


def build(dataset: Path, card: Config, pool: Flows, test: Flows) -> dict[str, Any]:
    """The whole constraint model: vocabulary, feature roles, behaviour knobs, measured constraints and provenance."""
    validate_tables()
    features: list[str] = card["features"]
    return {
        "schema_version": SCHEMA_VERSION,
        "purpose": "The empirical constraint model an evasive attacker on NSL-KDD must obey. It holds no mutation and no search: a "
        "consumer reads the roles, the knobs and the constraints from here and does the moving itself.",
        "vocabulary": {"roles": ROLE_MEANING, "effects": EFFECT_MEANING, "support": SUPPORT_MEANING},
        "features": feature_card(features),
        "feature_groups": {"time_based": list(TIME_BASED), "host_based": list(HOST_BASED), "content": list(CONTENT)},
        "behaviour_knobs": BEHAVIOUR_KNOBS,
        "couplings": measure_couplings(pool, test),
        "symbolic_couplings": {"flag_fixes_error_rates": measure_errors_by_flag(pool)},
        "symbolic_combinations": measure_symbolic(pool, test, rare_below=10),
        "direct_levers": measure_levers(pool, card["categories"]),
        "category_signatures": measure_signatures(pool),
        "information_free_features": measure_constants(pool, features, near_at=0.99),
        "deviations_from_research_report": DEVIATIONS,
        "provenance": provenance(dataset, card, dataset / "pool.csv", dataset / "test.csv", (len(pool), len(test))),
    }


def main() -> None:
    """Fit the model on the Pool and write it next to the card."""
    parser = argparse.ArgumentParser(description="fit the NSL-KDD constraint model")
    parser.add_argument("--dataset", type=Path, default=Path("data/nsl-kdd"), help="folder holding dataset.json, pool.csv and test.csv")
    parser.add_argument("--out", type=Path, default=None, help="where to write the model; <dataset>/mutations.json by default")
    args = parser.parse_args()
    card = load_config(args.dataset / "dataset.json")
    pool = read_flows(args.dataset / "pool.csv")
    test = read_flows(args.dataset / "test.csv")
    model = build(args.dataset, card, pool, test)
    target: Path = args.out or args.dataset / "mutations.json"
    target.write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")
    accepted = [entry["id"] for entry in model["couplings"] if entry["enforce"]]
    print(f"{target}: {len(pool)} pool flows, {len(test)} test flows")
    print(f"couplings accepted {len(accepted)}/{len(COUPLINGS)}: {', '.join(accepted)}")


if __name__ == "__main__":
    main()
