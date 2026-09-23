"""The shipped constraint model, `data/nsl-kdd/mutations.json`, is internally consistent and honest.

These tests read the committed JSON and the committed card only. The Pool is gitignored and absent on a fresh clone, so the one test that
needs it skips itself. The legal role names, the legal effect names and the list of sensor-derived features are written out here rather
than read from the model: a file that grades its own homework proves nothing.
"""

import csv
import json
from typing import Any

import pytest

from jev_ids import ROOT
from jev_ids.dataset import load_config

MODEL_PATH = ROOT / "data" / "nsl-kdd" / "mutations.json"
POOL_PATH = ROOT / "data" / "nsl-kdd" / "pool.csv"

ROLES = {"direct", "derived", "fixed"}
EFFECTS = {"increase", "decrease", "dilute_toward_background", "near_invariant", "unchanged", "unspecified"}
SUPPORT = {"cited", "synthesis"}
KNOB_DIRECTIONS = {"increase_only", "decrease_only"}

# What `dev-docs/research-evasion-constraints.md` classifies as recomputed by the sensor: the nine time-based features, the ten host-based
# ones, `flag` (a TCP termination outcome) and `dst_bytes` (the victim decides how much it answers). None of them may be `direct`.
SENSOR_DERIVED = {
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
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
    "flag",
    "dst_bytes",
}


def reject_duplicates(pairs: list[tuple[Any, Any]]) -> dict[Any, Any]:
    """Build the object, refusing a key that appears twice; json would silently keep the last one."""
    keys = [key for key, _ in pairs]
    repeated = sorted({key for key in keys if keys.count(key) > 1})
    if repeated:
        raise ValueError(f"duplicate keys: {repeated}")
    return dict(pairs)


@pytest.fixture(scope="module")
def model() -> dict[str, Any]:
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


@pytest.fixture(scope="module")
def features() -> list[str]:
    return load_config(ROOT / "data" / "nsl-kdd" / "dataset.json")["features"]


def referenced_names(model: dict[str, Any]) -> set[str]:
    """Every card feature the model names anywhere outside its own feature table."""
    names: set[str] = set()
    for group in model["feature_groups"].values():
        names.update(group)
    for knob in model["behaviour_knobs"].values():
        names.update(knob["effects"])
    for coupling in model["couplings"]:
        names.update(coupling["features"])
    names.update(model["symbolic_couplings"]["flag_fixes_error_rates"]["features"])
    names.update(model["direct_levers"])
    names.update(model["category_signatures"]["r2l"]["content_features_checked"])
    names.update(model["category_signatures"]["dos"]["content"])
    names.update(entry["feature"] for entry in model["information_free_features"]["constant"])
    names.update(entry["feature"] for entry in model["information_free_features"]["near_constant"])
    return names


def test_the_model_carries_every_card_feature_exactly_once(model: dict[str, Any], features: list[str]) -> None:
    # reject_duplicates already refused a repeated key, so matching the card as a list is enough for "exactly once".
    assert list(model["features"]) == features
    assert len(features) == 41


def test_every_role_is_legal_and_every_entry_is_justified(model: dict[str, Any]) -> None:
    for name, entry in model["features"].items():
        assert entry["role"] in ROLES, name
        assert entry["support"] in SUPPORT, name
        assert entry["why"].strip() and entry["citation"].strip(), name
        assert entry["why"].count("\n") == 0, name
        for category, role in entry.get("role_by_category", {}).items():
            assert category in {"dos", "probe", "r2l", "u2r", "normal"}, name
            assert role in ROLES, name


def test_no_sensor_derived_feature_is_ever_direct(model: dict[str, Any]) -> None:
    for name in SENSOR_DERIVED:
        entry = model["features"][name]
        roles = {entry["role"], *entry.get("role_by_category", {}).values()}
        assert "direct" not in roles, f"{name} is sensor-derived but the model lets the attacker write it"


def test_the_direct_levers_are_the_only_direct_features(model: dict[str, Any]) -> None:
    direct = {name for name, entry in model["features"].items() if entry["role"] == "direct"}
    assert direct == set(model["direct_levers"]) == {"duration", "src_bytes"}


def test_every_referenced_feature_name_exists_in_the_card(model: dict[str, Any], features: list[str]) -> None:
    unknown = referenced_names(model) - set(features)
    assert not unknown, f"the model names features the card does not have: {sorted(unknown)}"


def test_every_coupling_tolerance_stays_inside_what_was_measured(model: dict[str, Any]) -> None:
    for coupling in model["couplings"]:
        measured = coupling["measured"]["pool"]["residual"]
        if not coupling["enforce"]:
            assert coupling["tolerance"] is None, coupling["id"]
            assert coupling["verdict"] == "rejected", coupling["id"]
            continue
        assert coupling["verdict"] == "accepted", coupling["id"]
        # A tolerance below the measured p99 would be violated by more Flows than the model admits; one above the measured maximum would
        # be a tolerance the Pool never justified. Both are ways of quietly widening a story until it works.
        assert measured["p99"] <= coupling["tolerance"] <= measured["max"], coupling["id"]
        assert coupling["tolerance"] <= coupling["rounding_slack"], coupling["id"]


def test_every_coupling_is_measured_on_both_files(model: dict[str, Any]) -> None:
    assert len(model["couplings"]) >= 5
    for coupling in model["couplings"]:
        assert coupling["support"] in SUPPORT, coupling["id"]
        assert coupling["unit"] in {"rate", "connections"}, coupling["id"]
        for where in ("pool", "test"):
            measured = coupling["measured"][where]
            assert measured["flows"] > 0, coupling["id"]
            assert 0.0 <= measured["violation_rate_above_slack"] <= 1.0, coupling["id"]
            # An accepted coupling reports its violation rate at the tolerance it ships with, not only at the rounding slack: the two are
            # different numbers and quoting the looser one would understate how often the identity fails.
            assert ("violation_rate_above_tolerance" in measured) == coupling["enforce"], coupling["id"]
            residual = measured["residual"]
            assert residual["p50"] <= residual["p90"] <= residual["p99"] <= residual["max"], coupling["id"]


def test_the_four_couplings_the_report_predicts_are_all_present(model: dict[str, Any]) -> None:
    predicted = {
        "same_srv_partition",
        "dst_host_srv_partition",
        "dst_host_srv_count_ordering",
        "dst_host_same_srv_rate_ratio",
        "num_outbound_cmds_degenerate",
    }
    assert predicted <= {coupling["id"] for coupling in model["couplings"]}


def test_every_behaviour_knob_moves_features_in_a_legal_direction(model: dict[str, Any]) -> None:
    for name, knob in model["behaviour_knobs"].items():
        assert knob["direction"] in KNOB_DIRECTIONS, name
        assert knob["support"] in SUPPORT, name
        assert knob["rationale"].strip() and knob["citation"].strip(), name
        for feature, effect in knob["effects"].items():
            assert effect["direction"] in EFFECTS, f"{name}.{feature}"
            assert effect["basis"].strip(), f"{name}.{feature}"


def test_slowing_down_obeys_the_reports_causal_model(model: dict[str, Any]) -> None:
    effects = model["behaviour_knobs"]["inter_connection_interval"]["effects"]
    # Raw counts over a fixed 2 s window fall with the rate.
    assert effects["count"]["direction"] == effects["srv_count"]["direction"] == "decrease"
    # The rate features over that same window do not fall; they dilute toward the ambient background.
    for rate in ("same_srv_rate", "diff_srv_rate", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate"):
        assert effects[rate]["direction"] == "dilute_toward_background", rate
    # The ten host-based features use a 100-connection window, built precisely to survive an attacker who slows down.
    host_based = model["feature_groups"]["host_based"]
    assert len(host_based) == 10
    for feature in host_based:
        assert effects[feature]["direction"] == "near_invariant", feature


def test_the_dos_override_freezes_the_time_based_block(model: dict[str, Any]) -> None:
    # For dos a high connection rate is the attack itself, so the nine time-based features stop being free consequences of behaviour.
    for feature in model["feature_groups"]["time_based"]:
        assert model["features"][feature]["role_by_category"]["dos"] == "fixed", feature
    assert model["features"]["flag"]["role_by_category"]["dos"] == "fixed"


def test_the_direct_lever_bounds_are_ordered_and_increase_only(model: dict[str, Any]) -> None:
    for name, lever in model["direct_levers"].items():
        assert lever["direction"] == "increase_only", name
        for category, bounds in lever["by_category"].items():
            assert bounds["flows"] > 0, f"{name}.{category}"
            assert bounds["min"] <= bounds["p50"] <= bounds["p90"] <= bounds["p99"] <= bounds["max"], f"{name}.{category}"


def test_the_admissible_symbolic_combinations_cover_the_protocols(model: dict[str, Any]) -> None:
    combinations = model["symbolic_combinations"]
    assert set(combinations["by_protocol_type"]) == {"tcp", "udp", "icmp"}
    for protocol, entry in combinations["by_protocol_type"].items():
        for column in ("service", "flag"):
            common, rare = entry[column]["common"], entry[column]["rare"]
            assert common, f"{protocol}.{column}"
            assert not set(common) & set(rare), f"{protocol}.{column}"
            assert all(count >= combinations["rare_below_flows"] for count in common.values()), f"{protocol}.{column}"
            assert all(count < combinations["rare_below_flows"] for count in rare.values()), f"{protocol}.{column}"
        assert entry["flows"] == sum(entry["service"]["common"].values()) + sum(entry["service"]["rare"].values()), protocol
    # Sheatsley et al.'s point: a service switch the protocol forbids yields an infeasible Flow, so almost nothing spans two protocols.
    assert combinations["services_on_more_than_one_protocol"] == ["other", "private"]


def test_the_model_records_its_provenance_and_its_deviations(model: dict[str, Any]) -> None:
    provenance = model["provenance"]
    assert provenance["script"] == "scripts/fit_mutations.py"
    assert provenance["dataset"] == "nsl-kdd"
    for key in ("pool", "test"):
        assert len(provenance[key]["sha256"]) == 64
        assert provenance[key]["flows"] > 0
    assert len(provenance["card"]["sha256"]) == 64
    assert provenance["fitted_on"].count("-") == 2
    assert model["schema_version"] == "1"
    # Every departure from the research report is named, so a reviewer never has to diff the two documents to find one.
    assert model["deviations_from_research_report"]
    for deviation in model["deviations_from_research_report"]:
        assert {"subject", "report", "model", "why"} == set(deviation)


def test_num_outbound_cmds_is_the_only_constant_feature(model: dict[str, Any]) -> None:
    constant = model["information_free_features"]["constant"]
    assert [entry["feature"] for entry in constant] == ["num_outbound_cmds"]
    assert constant[0]["share"] == 1.0
    assert model["features"]["num_outbound_cmds"]["role"] == "fixed"


@pytest.mark.skipif(not POOL_PATH.exists(), reason="pool.csv is gitignored and absent on a fresh clone")
def test_the_accepted_couplings_still_hold_on_the_pool() -> None:
    # An independent re-derivation: the residuals are recomputed here rather than trusted from the script that wrote the model.
    model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    accepted = {coupling["id"]: coupling for coupling in model["couplings"] if coupling["enforce"]}
    assert set(accepted) == {"same_srv_rate_ratio", "num_outbound_cmds_degenerate"}
    ratio_tolerance = accepted["same_srv_rate_ratio"]["tolerance"]
    violations, measured = 0, 0
    with POOL_PATH.open(encoding="utf-8", newline="") as handle:
        for flow in csv.DictReader(handle):
            assert flow["num_outbound_cmds"] == "0"
            count = int(flow["count"])
            if count == 0:
                continue
            measured += 1
            violations += abs(float(flow["same_srv_rate"]) - min(1.0, int(flow["srv_count"]) / count)) > ratio_tolerance
    on_pool = accepted["same_srv_rate_ratio"]["measured"]["pool"]
    assert measured == on_pool["flows"]
    assert violations / measured == pytest.approx(on_pool["violation_rate_above_tolerance"], abs=1e-6)
