"""The Arena's tables: what each Round did, what a Run answers, and what the baselines say that answer is worth.

In reading order:

- `TRAFFIC`, `BASELINE_VERSION`, `BUDGET_FIELDS`, `MISSING`, `FACETS`, `UNRECORDED`, `PROMPT_LENGTH_CONTROL`: the Prediction stage a
  Round is read from, the Context every Run is measured against, the Budget counters, what two Runs must share before their numbers may
  be put side by side, why a Run that recorded none of it is refused, and the confound no Run-level table can control.
- `read_jsonl`, `read_rounds`, `read_config`, `context_of`, `read_contexts`, `prices`, `run_state`: the Run directory as data.
- `round_key`, `by_seed`: the two orderings every table below uses.
- `prompt_size`, `detection`: mean `input_tokens` beside recall and the false-alarm rate, the pair that is never reported apart.
- `playbook`, `attack_columns`, `analyst_columns`, `curator_columns`, `gate_columns`, `budget_spent`, `round_row`, `summarize_rounds`:
  one row per (seed, Round), the loop's own story.
- `latest_by_flow`, `version_rows`, `paired_rows`, `final_version`, `side_columns`, `trajectory`, `run_rows`, `seed_row`, `final_playbook`,
  `paired_columns`, `loop_columns`, `summarize_run`: one row per seed, the final Context against version 0 over the Flows both judged.
- `dig`, `dig_any`, `comparability`, `refuse_incomparable`, `disagreement`, `describe`, `arm`, `run_label`, `strategies`,
  `final_rows_by_seed`, `reference_bundle`, `comparison_rows`, `compare_runs`: several Runs side by side, or a refusal naming what
  differs.

Three rules hold everywhere here.

**Recall never appears without mean `input_tokens`.** A curated Context is also a LONGER prompt, and longer prompts move a model's
answers on their own, so a table that reports recall without tokens cannot separate "the playbook helped" from "more text helped". Only
the placebo arm of `compare_runs` settles that, and only if both columns are there to read. The tokens are also what the playbook costs:
at list price they are billed on every Flow, which is why `cost_usd_per_1m` stands beside them.

**The evidence is a biased sample with unbiased counts.** `misses` and `false_alarms` are Round-wide while the analyst reviewed
`analyst_reviewed` Flows of them; both stand in the same row, so a Category that looks rare can be told from one the analyst never
reached.

**Runs measured over different Flows are not a comparison.** `compare_runs` refuses a set of Runs that differ on the Card, the Splits,
the attacker, the prompt template, the Detector and its k, or the number of Rounds, and names what differs rather than averaging them.
The Card, the Splits and the prompt are compared by sha256 and never by file name, and a Run that recorded no hash is refused too.

Two things the tables report and cannot fix, which a reader should know before reading a number.

**The arms are not judged on identical traffic.** Each arm's attacker searched for its mutations against that arm's own Context, so two
arms' Predictions about one `row_id` are about two different mutated Flows. Pairing on `row_id` is still the right test — it is the same
parent Flow, and the loop's rule keeps the id — but part of any difference between two arms is their attackers'.
`vs_reference_same_strategies` reports when the two ended on different knob settings, which is the normal case.

**The Budget columns are Run-wide.** `detector_calls` and `curator_calls` are cumulative counters belonging to the whole Run, not to one
seed, so a multi-seed Run repeats the Run's spend at that seed's last Round on every per-seed row. They must not be added up.

**A Run-level comparison cannot separate the playbook's content from its length, by construction**: a placebo playbook is built from the
final curated Context's own shape and so cannot exist until the loop has finished, which makes the final evaluation
(`jev_ids/arena/final.py`), judging the baseline, the curated and the placebo Contexts over the same Flows, the measurement that can.

Nothing here recomputes a score: recall, F1, the error rate, the paired test and the prices all come from `jev_ids.metrics`, the code the
paper's other tables are built from, so the Arena's numbers cannot drift from them. Every function returns `list[dict]` in the shape
`metrics.summarize` uses, so `cli.print_csv` renders it unchanged.
"""

import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from jev_ids import metrics
from jev_ids.records import Prediction, read_predictions

# The Predictions of a Round's observed traffic. The two gate stages judge the held-out Split instead, and what they measured is already
# the gate's own verdict, so a Round's recall is read from the traffic alone.
TRAFFIC = "traffic"

# The Context an Arena starts from: no playbook and no chosen Examples. Everything is measured against it.
BASELINE_VERSION = 0

# The four counters of `arena.budget.Budget.snapshot`, in the order a reader wants them.
BUDGET_FIELDS = ("detector_calls", "max_detector_calls", "curator_calls", "max_curator_calls")

# A key path that resolved to nothing. An object and not None, because None is a value a config may legitimately hold.
MISSING = object()

# What two Runs must agree on before their numbers may be put side by side, as (dimension, facet, candidate key paths into config.json).
# Candidate paths and not one path: this module does not write `config.json` and must read whichever shape the loop wrote.
#
# The Card, the Splits and the prompt template are compared by the sha256 of their bytes and NEVER by their file names. Two Splits both
# called `arena.csv` holding different Flows are two different experiments, and a name that passed the check is exactly the failure
# nobody would ever notice. `arena.rounds` is the configured number of Rounds, the length of the experiment; how many each seed actually
# played is the `rounds` column, which a Run killed by its Budget leaves shorter.
#
# The first path that resolves wins; a facet no Run recorded is not compared, and a dimension no Run recorded at all is a refusal,
# because a check that could not run is not a check that passed.
FACETS: tuple[tuple[str, str, tuple[tuple[str, ...], ...]], ...] = (
    ("card", "card", (("inputs", "dataset"), ("dataset", "sha256"), ("card", "sha256"))),
    ("split", "splits", (("splits",), ("split",))),
    ("split", "learn_split", (("inputs", "learn_split"),)),
    ("split", "gate_split", (("inputs", "gate_split"),)),
    ("split", "eval_split", (("inputs", "eval_split"),)),
    ("attacker", "attacker", (("config", "attacker"), ("attacker",))),
    ("prompt", "prompt", (("inputs", "prompt"), ("prompt_hash",))),
    ("detector", "detector", (("config", "detector", "name"), ("detector",))),
    ("detector", "k", (("config", "detector", "k"), ("k",))),
    ("rounds", "rounds", (("config", "arena", "rounds"), ("arena", "rounds"))),
)

# Why a dimension no Run recorded stops the comparison, one sentence each, written for the person holding the Run directories.
UNRECORDED: dict[str, str] = {
    "card": "No Run recorded the sha256 of its Card, so two Runs naming the same file cannot be shown to have judged the same Dataset.",
    "split": (
        "No Run recorded the sha256 of its Splits: the Run predates the `inputs` hashes or was written without them. Two Splits of one "
        "name may hold different Flows, so such a Run has to be re-hashed or re-run, never compared by the name alone."
    ),
    "attacker": "No Run recorded its attacker settings, so the arms cannot be shown to have faced the same attacker.",
    "prompt": "No Run recorded the sha256 of its prompt template, so the arms cannot be shown to have been measured on the same Detector.",
    "detector": "No Run recorded its Detector or its k, so the arms cannot be shown to have attacked the same thing.",
    "rounds": "No Run recorded how many Rounds it played: a longer experiment against a shorter one is not an arm against an arm.",
}

# What every row of `compare_runs` says about the one confound this table cannot control. A placebo playbook is derived from the final
# curated Context's own shape -- same Rule count, matched lengths -- so it does not exist until the loop has finished and can never be an
# arm of the loop; nothing here is guessed from a Run's name or kind, because there is nothing real to find.
PROMPT_LENGTH_CONTROL = (
    "prompt length not controlled here: this table compares whole Runs, and the placebo arm lives in the final evaluation "
    "(jev_ids/arena/final.py), which judges the baseline, the curated and the placebo Contexts over the same Flows"
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Every object of a JSONL file; an absent file is no objects at all."""
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def read_rounds(run_dir: Path) -> list[dict[str, Any]]:
    """Every object of the Run's `rounds.jsonl`, one per (seed, Round); an absent file is a Run that played none."""
    return read_jsonl(run_dir / "rounds.jsonl")


def read_config(run_dir: Path) -> dict[str, Any]:
    """The Run's `config.json`; an absent file is an empty config, which `refuse_incomparable` then declines to compare."""
    path = run_dir / "config.json"
    if not path.exists():
        return {}
    config: dict[str, Any] = json.loads(path.read_text("utf-8"))
    return config


def context_of(entry: Mapping[str, Any]) -> dict[str, Any] | None:
    """One line of `contexts.jsonl` as a Context: the line itself, the Context it carries, or None.

    Read leniently on purpose. The Round record's shape is fixed by the protocol and this file's is not, so a line is accepted either as
    a Context in the shape `arena.context.Context.to_dict` writes (`version`, `rules`, `example_ids`, `parent`, `note`) or as an object
    carrying one under `context`. Anything else is skipped rather than guessed at.
    """
    if "version" in entry:
        return dict(entry)
    nested: dict[str, Any] = entry.get("context") or {}
    return dict(nested) if "version" in nested else None


def read_contexts(run_dir: Path, records: Sequence[Mapping[str, Any]]) -> dict[tuple[Any, int], dict[str, Any]]:
    """Every Context the Run wrote, keyed by (seed, version).

    Both sources are read, `contexts.jsonl` first and the Round records second: each Round record embeds the Context in force, so a Run
    without the file still has every Context that ever judged traffic, but the Context accepted in the very last Round was never in force
    and lives only in the file.

    By seed and not by version alone, because each seed carries its own lineage: two seeds both write a version 1 and the two are
    different playbooks. A line naming no seed is filed under None and read only when the seed's own is missing.
    """
    contexts: dict[tuple[Any, int], dict[str, Any]] = {}
    for entry in [*read_jsonl(run_dir / "contexts.jsonl"), *records]:
        found = context_of(entry)
        if found is not None:
            contexts[(entry.get("seed"), int(found["version"]))] = found
    return contexts


def prices() -> dict[str, Any]:
    """The list prices `metrics.cost_usd_per_1m` bills a Context's tokens at, from the file `metrics.summarize` reads."""
    models: dict[str, Any] = json.loads(metrics.PRICES_PATH.read_text("utf-8"))["models"]
    return models


def run_state(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[Prediction]]:
    """A Run directory read once: its `config.json`, its Round records in (seed, Round) order, and its Predictions."""
    return read_config(run_dir), sorted(read_rounds(run_dir), key=round_key), read_predictions(run_dir)


def round_key(record: Mapping[str, Any]) -> tuple[Any, ...]:
    """Sort key of a Round record: by seed, then by Round, with a record missing either number last."""
    return metrics.none_last_key((record.get("seed"), record.get("round")))


def by_seed(rows: Sequence[dict[str, Any]]) -> dict[Any, list[dict[str, Any]]]:
    """The rows of each seed, keyed by the seed itself; `metrics.group_by_fields` keys by a tuple of fields.

    A Round record is a dict with a `seed` like a Prediction is, and the helper only reads the fields it is given, so both go through it.
    """
    return {key[0]: members for key, members in metrics.group_by_fields(rows, ("seed",)).items()}


def prompt_size(predictions: Sequence[Prediction]) -> float | None:
    """Mean `input_tokens` of the Predictions: how long the Context in force made every prompt.

    This column stands beside recall in every table of this module and is never reported instead of it. A curated Context is also a
    longer prompt; longer prompts move a model's answers on their own, so a recall that rose while the prompt grew is two hypotheses at
    once, and only the placebo arm of `compare_runs` — as many rules, of the same length, saying nothing useful — tells them apart. The
    same number prices the playbook: at list price the tokens are billed on every Flow the Detector ever judges.
    """
    usages: list[dict[str, Any]] = [p.get("usage", {}) for p in predictions]
    return metrics.mean(u.get("input_tokens") for u in usages)


def detection(predictions: Sequence[Prediction]) -> dict[str, Any]:
    """What the Detector did over one set of Flows, and the prompt length it did it at.

    Recall, F1 and the error rate come from `metrics.scores` over exactly the Predictions given. The false-alarm rate is `metrics.rate`
    over the benign Flows alone, which is the very number `arena.gate.false_alarm_rate` decides on, so the report and the gate cannot
    disagree about what a false alarm is.

    `misses` and `false_alarms` are counts over every Flow judged, Round-wide; `analyst_columns` says how few of them a human saw.
    """
    attacks = [p for p in predictions if p["is_attack"] == 1]
    benign = [p for p in predictions if p["is_attack"] == 0]
    scored = metrics.scores(predictions)
    return {
        "flows": len(predictions),
        "attack_flows": len(attacks),
        "benign_flows": len(benign),
        "recall": scored["recall"],
        "false_alarm_rate": metrics.rate(benign),
        "misses": len(attacks) - sum(metrics.verdict(p) for p in attacks),
        "false_alarms": sum(metrics.verdict(p) for p in benign),
        "f1": scored["f1"],
        "error_rate": scored["error_rate"],
        "input_tokens_mean": prompt_size(predictions),
    }


def playbook(context: Mapping[str, Any]) -> dict[str, Any]:
    """One Context's size: its version, how many Rules it carries and how many Examples it chose."""
    return {
        "context_version": context.get("version"),
        "rules": len(context.get("rules", [])),
        "examples": len(context.get("example_ids", [])),
    }


def attack_columns(record: Mapping[str, Any]) -> dict[str, Any]:
    """The attacker's Round: how many Flows it moved past the Detector, and what it spent doing it."""
    attack: dict[str, Any] = record.get("attack", {})
    return {
        "attacker_flows": attack.get("flows"),
        "attacker_evaded": attack.get("evaded"),
        "evasion_rate": attack.get("evasion_rate"),
        "attacker_queries": attack.get("queries"),
    }


def analyst_columns(record: Mapping[str, Any], traffic: Sequence[Prediction]) -> dict[str, Any]:
    """What the simulated analyst actually looked at, beside the Round-wide counts of `detection`.

    The curator's evidence is a biased sample with unbiased counts: it sees Feedback only for the Flows the analyst reviewed, the alert
    queue truncated at `alert_budget` and a sample of the quiet traffic, while `misses` and `false_alarms` count the whole Round. A
    curator can conclude a Category is rare when the analyst simply never reached it, so both numbers stand in the same row and
    `analyst_reviewed_share` says how wide the gap was.
    """
    analyst: dict[str, Any] = record.get("analyst", {})
    reviewed = analyst.get("reviewed")
    return {
        "analyst_reviewed": reviewed,
        "analyst_alerts_reviewed": analyst.get("alerts_reviewed"),
        "analyst_quiet_reviewed": analyst.get("quiet_reviewed"),
        "analyst_poisoned": analyst.get("poisoned"),
        "analyst_reviewed_share": None if reviewed is None else metrics.ratio(reviewed, len(traffic)),
    }


def curator_columns(record: Mapping[str, Any]) -> dict[str, Any]:
    """Who proposed this Round's Contexts, on what shortlist of Example candidates, and whether the call failed.

    The shortlist is evidence and not plumbing: the heuristic curator can only ever be as good as the Pool Flows it was offered, so a
    Run where the LLM wins is only a result if `shortlist_how` says both curators drew from the same shortlist.
    """
    curator: dict[str, Any] = record.get("curator", {})
    shortlist: dict[str, Any] = record.get("shortlist", {})
    return {
        "curator_kind": curator.get("kind"),
        "curator_model": curator.get("model"),
        "curator_proposals": curator.get("proposals"),
        "curator_error": curator.get("error"),
        "shortlist_size": shortlist.get("size"),
        "shortlist_how": shortlist.get("how"),
    }


def gate_columns(record: Mapping[str, Any]) -> dict[str, Any]:
    """How many proposals the gate kept and rolled back, which version came out, and why.

    `gate_reasons` carries every verdict's own sentence, the only trace left of why a Round kept the Context it already had. The four
    numbers beside it are the accepted proposal's, measured on the held-out Split: that is the generalisation test, and a Round with no
    accepted proposal leaves them empty rather than falling back to a rejected one's.

    `accepted_version` is the version in force after the gate, which is the incumbent's own when nothing was accepted, so it is
    `gate_accepted` and never that column that says whether the Round kept anything.
    """
    verdicts: list[dict[str, Any]] = record.get("gate", [])
    accepted = [verdict for verdict in verdicts if verdict.get("accepted")]
    best: dict[str, Any] = accepted[-1] if accepted else {}
    return {
        "gate_proposals": len(verdicts),
        "gate_accepted": len(accepted),
        "gate_rejected": len(verdicts) - len(accepted),
        "accepted_version": record.get("accepted_version"),
        "gate_candidate_recall": best.get("candidate_recall"),
        "gate_incumbent_recall": best.get("incumbent_recall"),
        "gate_candidate_false_alarm_rate": best.get("candidate_false_alarm_rate"),
        "gate_mcnemar_p": best.get("mcnemar_p"),
        "gate_reasons": " | ".join(
            f"v{verdict.get('version')} {'kept' if verdict.get('accepted') else 'rolled back'}: {verdict.get('reason', '')}"
            for verdict in verdicts
        ),
    }


def budget_spent(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The Budget as the last of these Rounds left it.

    The counters are cumulative and belong to the whole Run, not to one seed, so the maximum over the Rounds given is what had been
    spent by the last of them; a multi-seed Run's per-seed row therefore shows the Run's spend at that seed's last Round.
    """
    snapshots: list[dict[str, Any]] = [record.get("budget", {}) for record in records]
    return {name: max((s[name] for s in snapshots if s.get(name) is not None), default=None) for name in BUDGET_FIELDS}


def round_row(record: Mapping[str, Any], traffic: Sequence[Prediction]) -> dict[str, Any]:
    """One (seed, Round) as one row: the Context in force, the attacker, the Detector, the analyst, the curator, the gate, the Budget."""
    context: dict[str, Any] = record.get("context", {})
    return {
        "run_id": record.get("run_id"),
        "seed": record.get("seed"),
        "round": record.get("round"),
        **playbook(context),
        **attack_columns(record),
        **detection(traffic),
        **analyst_columns(record, traffic),
        **curator_columns(record),
        **gate_columns(record),
        **budget_spent([record]),
    }


def summarize_rounds(run_dir: Path) -> list[dict[str, Any]]:
    """One row per (seed, Round) of one Run: the loop's own story, ready for `cli.print_csv`.

    The attacker's evasion rate, the Detector's recall over the Round's mutated attack Flows and its false-alarm rate over the benign
    ones, the mean `input_tokens` of the Context in force, the analyst's reach, the gate's acceptances with their reasons, the playbook's
    size and the Budget so far. The detection numbers are taken over the Predictions of the `traffic` stage alone, since the two gate
    stages judged the held-out Split and their numbers are the gate's own.

    Args:
        run_dir: `results/arena/<run_id>`, holding `rounds.jsonl` and `predictions.jsonl`.

    Returns:
        One dict per Round record, ascending in (seed, Round); a Run that played no Round gives no rows.
    """
    _config, records, predictions = run_state(run_dir)
    traffic = metrics.group_by_fields([p for p in predictions if p.get("arena_stage") == TRAFFIC], ("seed", "round"))
    return [round_row(record, traffic.get((record.get("seed"), record.get("round")), [])) for record in records]


def latest_by_flow(predictions: Iterable[Prediction]) -> dict[Any, Prediction]:
    """The last Prediction written for each Flow, keyed by `row_id`.

    One Context stays in force for several Rounds, so the same Flow is judged under it more than once; a paired test needs one Verdict
    per Flow per side and takes the most recent, the one written after the most Rounds of the loop.
    """
    return {p["row_id"]: p for p in predictions}


def version_rows(predictions: Iterable[Prediction], version: int) -> dict[Any, Prediction]:
    """The last Prediction each Flow got under one Context version."""
    return latest_by_flow(p for p in predictions if p.get("context_version") == version)


def paired_rows(side_a: Mapping[Any, Prediction], side_b: Mapping[Any, Prediction]) -> list[metrics.PredictionPair]:
    """The two sides matched Flow by Flow over the Flows both judged; a Flow only one of them saw is dropped.

    Pairing on `row_id` is what entitles `metrics.mcnemar_exact` to the name: the two sides must have judged the same Flows. A mutated
    attack Flow keeps its parent's `row_id` by the loop's own rule, which is what makes the pairing survive the attacker.
    """
    return [(side_a[row_id], side_b[row_id]) for row_id in side_a if row_id in side_b]


def final_version(records: Sequence[Mapping[str, Any]]) -> int:
    """The version of the Context the Run ended under: the last Round that accepted one, else the last Context in force.

    A Run whose gate rejected every proposal, and a Run whose curator errored in every Round, both end under version 0. The comparison
    below is then a Context against itself, and says so: `final_version` is 0 and the paired test returns p = 1.
    """
    accepted = [record["accepted_version"] for record in records if record.get("accepted_version") is not None]
    if accepted:
        return int(accepted[-1])
    versions = [record.get("context", {}).get("version") for record in records]
    return int(versions[-1]) if versions and versions[-1] is not None else BASELINE_VERSION


def side_columns(rows: Sequence[Prediction], suffix: str, priced: dict[str, Any]) -> dict[str, Any]:
    """One side of a paired comparison: what it caught, what its prompt cost, and how long that prompt was.

    The cost is `metrics.cost_usd_per_1m` averaged over the Predictions, so it is the list price of a million Flows judged under this
    Context. A playbook is not paid for once: it rides on every Detector call, which is why the price stands in the answer's own row.

    The error rate is here for a harder reason. A Prediction whose call failed counts as `normal` (`metrics.verdict` fails open), so a
    Context long enough to run past the model's window, or worded well enough to provoke refusals, buys a perfect false-alarm rate by
    answering nothing at all. A false-alarm rate is only readable beside the share of calls that came back.
    """
    spend = metrics.usage(rows, priced)
    return {
        f"recall_{suffix}": metrics.rate([p for p in rows if p["is_attack"] == 1]),
        f"false_alarm_rate_{suffix}": metrics.rate([p for p in rows if p["is_attack"] == 0]),
        f"error_rate_{suffix}": metrics.scores(rows)["error_rate"],
        f"input_tokens_mean_{suffix}": spend.get("input_tokens_mean"),
        f"cost_usd_per_1m_{suffix}": spend.get("cost_usd_per_1m"),
    }


def trajectory(values: Sequence[float | None]) -> str:
    """A per-Round series as one CSV cell, `0.350 0.500 0.450`, with `?` for a Round that recorded none."""
    return " ".join("?" if value is None else f"{value:.3f}" for value in values)


def run_rows(
    records: Sequence[dict[str, Any]],
    predictions: Sequence[Prediction],
    priced: dict[str, Any],
    contexts: Mapping[tuple[Any, int], Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """One row per seed: the final Context against version 0 over the Flows both judged, and what the Run spent getting there."""
    by_seed_predictions = by_seed(predictions)
    return [
        seed_row(seed, seed_records, by_seed_predictions.get(seed, []), priced, contexts) for seed, seed_records in by_seed(records).items()
    ]


def seed_row(
    seed: Any,
    records: Sequence[dict[str, Any]],
    predictions: Sequence[Prediction],
    priced: dict[str, Any],
    contexts: Mapping[tuple[Any, int], Mapping[str, Any]],
) -> dict[str, Any]:
    """One seed's answer, with the confounds that could fake it in the same row.

    The two sides are the Run's final Context and version 0, each taken over the last Prediction it wrote for a Flow, then intersected
    on `row_id`: recall, false alarms, tokens and cost are therefore measured over one population and `metrics.compare_cell` gives the
    exact paired test over the Flows the two Contexts split on.

    Two things this row cannot hide. `paired_same_round` is false when the two sides were measured in different Rounds, and they almost
    always were — version 0 was in force early and the final Context late — so the attack Flows carry different mutations on the two
    sides and part of any recall difference is the attacker's, not the playbook's. `input_tokens_mean_final` against
    `input_tokens_mean_v0` is the other: a longer prompt is a second explanation of the same difference.
    """
    ordered = sorted(records, key=round_key)
    version = final_version(ordered)
    pairs = paired_rows(version_rows(predictions, version), version_rows(predictions, BASELINE_VERSION))
    return {
        "run_id": ordered[0].get("run_id") if ordered else None,
        "seed": seed,
        "rounds": len(ordered),
        "final_version": version,
        "baseline_version": BASELINE_VERSION,
        **{
            f"final_{name}": value for name, value in playbook(final_playbook(contexts, seed, version)).items() if name != "context_version"
        },
        **paired_columns(pairs),
        **side_columns([final for final, _ in pairs], "final", priced),
        **side_columns([baseline for _, baseline in pairs], "v0", priced),
        **loop_columns(ordered),
        **budget_spent(ordered),
    }


def final_playbook(contexts: Mapping[tuple[Any, int], Mapping[str, Any]], seed: Any, version: int) -> Mapping[str, Any]:
    """The Context one seed ended under: its own line, or one that named no seed, or nothing at all."""
    return contexts.get((seed, version)) or contexts.get((None, version), {})


def paired_columns(pairs: Sequence[metrics.PredictionPair]) -> dict[str, Any]:
    """The exact paired test over the Flows both Contexts judged, and the Round the two sides were judged in.

    `metrics.compare_cell` does the counting, so this test is the one the gate and the paper's other tables run; only the names change,
    from A and B to the final Context and version 0.
    """
    cell = metrics.compare_cell(pairs)
    return {
        "paired_flows": cell["pairs"],
        # None and not True over no pair at all: a comparison that found nothing to pair has not shown the two sides to be anything.
        "paired_same_round": all(final.get("round") == base.get("round") for final, base in pairs) if pairs else None,
        "discordant": cell["discordant"],
        "final_correct": cell["a_correct"],
        "v0_correct": cell["b_correct"],
        "mcnemar_p": cell["mcnemar_p"],
        "f1_final": cell["f1_a"],
        "f1_v0": cell["f1_b"],
    }


def loop_columns(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """What the Rounds did: the evasion rate's trajectory, the gate's tally over the whole Run, and the curator's failures.

    The trajectory is the one number that says whether the loop converged or the attacker kept winning, and it belongs beside the
    Run's recall: a Context that gained recall while the evasion rate climbed has not held the line.
    """
    evasion: list[float | None] = [record.get("attack", {}).get("evasion_rate") for record in records]
    verdicts = [verdict for record in records for verdict in record.get("gate", [])]
    return {
        "evasion_rate_first": evasion[0] if evasion else None,
        "evasion_rate_last": evasion[-1] if evasion else None,
        "evasion_rate_mean": metrics.mean(evasion),
        "evasion_rate_by_round": trajectory(evasion),
        "gate_accepted": sum(bool(verdict.get("accepted")) for verdict in verdicts),
        "gate_rejected": sum(not verdict.get("accepted") for verdict in verdicts),
        "curator_errors": sum(record.get("curator", {}).get("error") is not None for record in records),
    }


def summarize_run(run_dir: Path) -> list[dict[str, Any]]:
    """One row per seed of one Run: the answer, the confounds beside it, and what it cost.

    The final Context against version 0 over the Flows both judged, paired on `row_id` and tested with `metrics.mcnemar_exact`; the mean
    `input_tokens` and the list cost of a million Flows on each side, since a playbook is billed on every one of them; the evasion rate's
    trajectory across the Rounds; the proposals the gate kept and rolled back; and the Budget actually spent.

    The pairing is per seed and never across seeds: `metrics.compare_cell` needs each Flow once per side, and seeds pooled together would
    fall back to an unpaired count under the same name.

    Args:
        run_dir: `results/arena/<run_id>`, holding `rounds.jsonl` and `predictions.jsonl`.

    Returns:
        One dict per seed the Run played; a Run that played no Round gives no rows.
    """
    _config, records, predictions = run_state(run_dir)
    return run_rows(records, predictions, prices(), read_contexts(run_dir, records))


def dig(config: Mapping[str, Any], path: Sequence[str]) -> Any:
    """The value at a key path of a nested config, or `MISSING` when any step of it is absent."""
    found: Any = config
    for key in path:
        try:
            found = found[key]
        except (KeyError, IndexError, TypeError):
            return MISSING
    return found


def dig_any(config: Mapping[str, Any], paths: Sequence[Sequence[str]]) -> Any:
    """The first of several candidate key paths that resolves to something, or `MISSING` when none of them does.

    A path that resolves to null is passed over like an absent one: a Card whose hash was written as null recorded nothing about the
    bytes that were judged, and two Runs that both recorded nothing must not come out equal.
    """
    for path in paths:
        found = dig(config, path)
        if found is not MISSING and found is not None:
            return found
    return MISSING


def comparability(config: Mapping[str, Any]) -> dict[str, Any]:
    """What one Run's `config.json` says about the Flows it measured: one value per facet of `FACETS`, or `MISSING`."""
    return {name: dig_any(config, paths) for _dimension, name, paths in FACETS}


def refuse_incomparable(facets: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """The facets every Run agrees on, or a ValueError naming the first one they do not.

    Two Runs measured over different Flows are not a comparison, and silently averaging them would be the worst thing this module could
    do; so a difference of any facet of `FACETS` stops the table instead of being footnoted under it. A dimension no Run recorded at all
    stops it too: a check that could not run is not a check that passed, and a comparison that proceeds anyway produces a number a
    reader will quote.

    Args:
        facets: one `comparability` mapping per Run, keyed by whatever names the Run in the error message.

    Returns:
        The names of the facets that were compared and found equal, in `FACETS` order.

    Raises:
        ValueError: two Runs differ on a facet, or no Run recorded one of the six dimensions of `UNRECORDED`.
    """
    checked: list[str] = []
    for _dimension, name, _paths in FACETS:
        if all(run_facets[name] is MISSING for run_facets in facets.values()):
            continue
        refusal = disagreement(name, facets)
        if refusal is not None:
            raise ValueError(refusal)
        checked.append(name)
    covered = {dimension for dimension, name, _paths in FACETS if name in checked}
    missing = sorted({dimension for dimension, _name, _paths in FACETS} - covered)
    if missing:
        raise ValueError(" ".join(UNRECORDED[dimension] for dimension in missing))
    return checked


def disagreement(name: str, facets: Mapping[str, Mapping[str, Any]]) -> str | None:
    """Why one facet stops the comparison, or None when every Run recorded the same thing for it.

    A Run that did not record the facet at all disagrees with one that did: the Runs would be compared on the word of a file that never
    said it, which is the assumption this whole function exists to refuse.
    """
    reference_name, reference = next(iter(facets.items()))
    for run, run_facets in facets.items():
        if run_facets[name] != reference[name]:
            return (
                f"Runs measured over different Flows are not a comparison: {name} is "
                f"{describe(reference[name])} in {reference_name} and {describe(run_facets[name])} in {run}"
            )
    return None


def describe(value: Any) -> str:
    """One facet's value for an error message; `MISSING` reads as the absence it is."""
    return "not recorded" if value is MISSING else repr(value)


def arm(config: Mapping[str, Any]) -> str:
    """What this Run is an arm of: the curator, the gate's mode and the threats switched on.

    Built from the settings and never from the directory name, which the user chooses: each baseline is the same loop with one setting
    moved, so the label has to be the setting itself for a reader to see which arm a row is.
    """
    settings: dict[str, tuple[tuple[str, ...], ...]] = {
        "curator": (("config", "curator", "kind"), ("curator", "kind")),
        "gate": (("config", "gate", "mode"), ("gate", "mode")),
        "poisoning": (("config", "threats", "poisoning"), ("threats", "poisoning")),
        "failure_rate": (("config", "threats", "failure_rate"), ("threats", "failure_rate")),
    }
    named = [f"{name}={value}" for name, paths in settings.items() if (value := dig_any(config, paths)) is not MISSING]
    return " ".join(named) if named else "unlabelled"


def run_label(config: Mapping[str, Any], run_dir: Path) -> str:
    """How a Run is named in the table: its `run_id`, or the directory when the config has none."""
    return str(config.get("run_id") or run_dir.name)


def strategies(records: Sequence[Mapping[str, Any]]) -> dict[Any, tuple[Any, ...]]:
    """The attacker's knob settings in the last of these Rounds, keyed by the Flow they were found for.

    Two arms are compared over Flows of the same `row_id`, but each arm's attacker searched against that arm's own Context, so the
    mutations behind those row_ids need not be the same traffic at all. This is what `vs_reference_same_strategies` reports.
    """
    last: Mapping[str, Any] = records[-1] if records else {}
    found: list[dict[str, Any]] = last.get("attack", {}).get("strategies", [])
    return {s.get("row_id"): (s.get("bucket"), s.get("padding_bytes"), s.get("added_seconds")) for s in found}


def final_rows_by_seed(records: Sequence[dict[str, Any]], predictions: Sequence[Prediction]) -> dict[Any, dict[Any, Prediction]]:
    """Each seed's Predictions under the Context that seed ended with, keyed by seed and then by Flow."""
    by_seed_predictions = by_seed(predictions)
    return {
        seed: version_rows(by_seed_predictions.get(seed, []), final_version(sorted(seed_records, key=round_key)))
        for seed, seed_records in by_seed(records).items()
    }


def reference_bundle(run_dir: Path) -> dict[str, Any]:
    """What every other Run is paired against: the reference Run's name, its final Predictions and its last knob settings, by seed."""
    config, records, predictions = run_state(run_dir)
    return {
        "label": run_label(config, run_dir),
        "finals": final_rows_by_seed(records, predictions),
        "strategies": {seed: strategies(sorted(seed_records, key=round_key)) for seed, seed_records in by_seed(records).items()},
    }


def comparison_rows(run_dir: Path, reference: Mapping[str, Any], checked: Sequence[str]) -> list[dict[str, Any]]:
    """One Run's seeds as rows of the side-by-side table, each paired against the reference Run's same seed.

    Every column of `summarize_run` is kept, so an arm's own answer is readable in the row that compares it; the `vs_reference_` columns
    are the paired test of this Run's final Context against the reference Run's, over the Flows both judged.
    """
    config, records, predictions = run_state(run_dir)
    finals = final_rows_by_seed(records, predictions)
    own_strategies = {seed: strategies(sorted(seed_records, key=round_key)) for seed, seed_records in by_seed(records).items()}
    label, compared_on = arm(config), " ".join(checked)
    rows: list[dict[str, Any]] = []
    for row in run_rows(records, predictions, prices(), read_contexts(run_dir, records)):
        seed = row["seed"]
        cell = metrics.compare_cell(paired_rows(finals.get(seed, {}), reference["finals"].get(seed, {})))
        rows.append(
            {
                "arm": label,
                **row,
                "reference": reference["label"],
                "compared_on": compared_on,
                "prompt_length_control": PROMPT_LENGTH_CONTROL,
                "vs_reference_flows": cell["pairs"],
                "vs_reference_discordant": cell["discordant"],
                "vs_reference_correct": cell["a_correct"],
                "reference_correct": cell["b_correct"],
                "vs_reference_mcnemar_p": cell["mcnemar_p"],
                "vs_reference_same_strategies": own_strategies.get(seed) == reference["strategies"].get(seed),
            }
        )
    return rows


def compare_runs(run_dirs: Sequence[Path]) -> list[dict[str, Any]]:
    """Several Runs side by side, each paired against the first, or a refusal naming what makes them incomparable.

    The arms this exists for: the LLM curator against the heuristic curator, against a frozen version 0, against a placebo playbook of
    the same shape, and against the poisoned Runs with the gate guarded and with it off. Each is the same loop with one setting moved,
    so `arm` labels the row from the settings and the difference is read rather than asserted. The first directory is the reference the
    others are paired against, so `compare_runs([llm, heuristic, frozen, placebo])` reads straight down the column.

    Three warnings the table carries rather than hides. `vs_reference_same_strategies` is false when the two arms' attackers ended on
    different knob settings, which they normally do, because each searched against its own Context: the paired Flows share a `row_id`
    and not a mutation. `prompt_length_control` says that no arm here holds prompt length constant and where the arm that does lives;
    `input_tokens_mean_final` is the number that confound moves. And
    `compared_on` names the facets that were actually checked, so a reader sees what the refusal below did and did not rule out.

    Args:
        run_dirs: the Run directories, the reference first; each holds `config.json`, `rounds.jsonl` and `predictions.jsonl`.

    Returns:
        One dict per (Run, seed), every Run's own summary plus its paired test against the reference; no directories gives no rows.

    Raises:
        ValueError: the Runs differ on any facet of `FACETS`, or none of them recorded one of the six dimensions it checks.
    """
    if not run_dirs:
        return []
    checked = refuse_incomparable({str(run_dir): comparability(read_config(run_dir)) for run_dir in run_dirs})
    reference = reference_bundle(run_dirs[0])
    return [row for run_dir in run_dirs for row in comparison_rows(run_dir, reference, checked)]
