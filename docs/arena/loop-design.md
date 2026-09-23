# The Arena loop: protocol decisions

The single source of truth for how one Round runs, written by the orchestrator before the loop package was built. Packages that must
agree with it: the attacker, the round loop, the metrics and the documentation. Vocabulary is `CONTEXT.md`'s.

## Why the attacker returns a Strategy, not Flows

An attacker cannot write NSL-KDD feature values: the nineteen time-based and host-based features are recomputed by the sensor from the
attacker's connection log (`docs/arena/evasion-constraints.md`, §4).

The first plan was to model that computation — turn behaviour knobs and derive the nineteen features from them. The empirical work killed
it (`docs/arena/empirical-constraints.md`): the coupling identities such a model must respect are violated in 27% to 60% of the
Pool, because `count` and `srv_count` are taken over two parallel windows rather than one nested pair and the `dst_host_*` counts saturate
at 255. Worse, NSL-KDD carries no timestamps and no connection ordering, so no causal model of those features can be validated on it at
all. Synthesising derived values would mean inventing numbers whose joint consistency nobody can check.

So the attacker uses **constrained mimicry by donor substitution**: it never invents a derived value, it copies the whole derived block
from one real Flow the sensor actually produced, keeps the attack's fixed features, and moves only `duration` and `src_bytes` within
measured bounds. For r2l and probe that block is twenty features — the nineteen time-based and host-based ones plus `flag`; for dos, ten,
since the Category's own overrides freeze the rest. `dst_bytes` never travels: the victim writes it, and copying it would claim a reply
the server never sent. Whatever the true couplings are, a real block satisfies them by construction. This is Pierazzi's problem-space projection
with the side-effect features arriving as a bundle.

What the attacker returns is therefore a **Strategy** — the donor bucket plus the direct-lever settings — and not a mutated Flow. A
Strategy transfers to Flows the attacker never touched, which is what the gate's generalisation test rests on. Everything below depends on
that property.

## The three Splits

| Split | Flows | Who sees it | Role |
|---|---:|---|---|
| `arena` | 550 | attacker, analyst, curator | where the Rounds are played and the labels come from |
| `arena-val` | 250 | the gate only | held out; decides whether a proposed Context is kept |
| `paper` | 2,000 | the final measurement only | untouched, so the result stays comparable with upstream |

The curator never sees `arena-val` or `paper`, and never sees any Flow's true Category — only the analyst's reported label, through
`analyst.for_curator`.

## One Round

1. **Attack.** The attacker takes `flows_per_round` attack Flows of the configured Categories from `arena` and searches, at most
   `max_queries_per_flow` Detector calls each, for a knob setting whose mutated Flow the Detector no longer alerts on. It observes only
   what `attacker.observes` allows. It returns, per Flow, whether it evaded and the knob setting that did it.
2. **Traffic.** The Round's observed traffic is the benign Flows of `arena` plus its attack Flows mutated with the knob settings found.
   The Detector judges all of it under the Context in force.
3. **Labels.** The analyst reviews that traffic: the alert queue down to `alert_budget`, highest `p_attack` first, plus a `sample_rate`
   share of the quiet Flows. With the poisoning arm on, a `poisoned_fraction` of the attack Feedback is relabeled benign.
4. **Learn.** The curator reads the Feedback that `delay_rounds` allows, projected through `for_curator`, and proposes
   `proposals_per_round` Contexts.

   **The Example shortlist is evidence, not plumbing.** A Context's Examples must be Pool Flows, but the misses happen in the learn
   Split, so neither curator can offer a missed Flow itself. The loop draws a shortlist of Pool candidates, and the heuristic baseline can
   only ever be as good as that shortlist: draw it uniformly over 125,973 Pool Flows and the baseline is crippled, the LLM wins by
   default, and the headline result is an artefact of the draw. So the shortlist must be built the same way for both curators and must
   contain Pool Flows resembling the Round's misses — at minimum, per missed Flow, Pool Flows of the Category the analyst reported for
   it. How it is drawn goes in the Round record.
5. **Gate.** Each proposal and the incumbent judge the SAME evaluation set: the benign Flows of `arena-val` unchanged, plus its attack
   Flows mutated with **this Round's knob settings**. That is the generalisation test — does the new Context catch the attacker's
   technique on Flows the curator never saw, or did it only memorise the ones it did? The best accepted proposal becomes the Context in
   force; if none is accepted, the incumbent stands and the Round records why.

### Two rules the loop must not break

- **Gate one seed at a time.** `gate.pairing` requires each `row_id` to appear once per side. Predictions from several seeds pooled
  together silently fall back to the unpaired rule and the McNemar test is lost. One `evaluate` call per seed.
- **Mutated Flows keep the parent's `row_id`**, so the pairing matches; the knob setting travels beside it in the Round record, never in
  the `row_id`.

## Budget

Per seed per Round, in Detector calls. This arithmetic was wrong in the first version of this document — it counted only the first and
last terms — and the loop package caught it. A projection that under-counts fails at its one job, so all three terms are named here:

```
attacker   flows_per_round x max_queries_per_flow            = 600   (worst case; a Flow that evades early costs less)
traffic    |arena|                                           = 550   (the Round's own traffic, judged under the Context in force)
gate       |arena-val| x (proposals_per_round + incumbent)   = 750   (the incumbent is cached only while it and the Strategies hold)
```

At the committed defaults that is 1,900 per Round, **19,000** over ten Rounds, against a 20,000 cap — it fits, with little room. Three
seeds cost 57,000 and are refused. The loop **projects this before the first call** and refuses to start a Run it cannot finish, before
creating the Run directory, because an experiment that dies in Round 7 is worth less than one that was never begun.

The final measurement on `paper` is a separate command with its own budget: 2,000 Flows x seeds x (baseline Context, final Context).

## Two behaviours the implementation has that this document did not say

Both were found by reading the finished code against this file, and both change how a record is read.

- **The attacker's probes leave no Prediction.** Only the Round's traffic and the gate's two sides are written to
  `predictions.jsonl`; the attacker's search is booked against the Budget and summarised in `attack.queries`, but writing a row per probe
  would multiply the `row_id`s the gate pairs on. So cost and latency computed from `predictions.jsonl` understate the real spend by
  roughly a third at the defaults. **The Budget snapshot is the truth**, and the tables say so.
- **Under `on_failure = "closed"` the upstream error rate reads zero.** A failed call is recorded as an alert, so
  `metrics.scores`'s count of Predictions without a Verdict finds none. The gate works around it by counting the `error` field instead,
  which is why `gate.integrity` still fires in that arm; `report.py`'s `error_rate` column does not, and a fail-closed Run's column
  should be read as "rows with no Verdict", not "calls that failed".

## What a Round writes

One directory per Run under `results/arena/`, carrying `config.json` (the resolved config, the Card, Split and prompt hashes, the code
commit, the Budget snapshot) and, per Round: the Context in force and its `prompt_hash`, every proposal and the gate's `GateVerdict` with
its reason, the attacker's evasion rate and knob settings, the analyst's Feedback counts including how many were poisoned, and the
Predictions themselves in the existing `predictions.jsonl` shape so `jev_ids.metrics` reads them unchanged.

## The threat arms

Each is the same loop with one setting moved, so the damage is read as a difference and never asserted:

- **A1, evasion** — the loop itself. Reported as the attacker's evasion rate per Round and the Context's recall on the mutated
  `arena-val` attacks.
- **A2, poisoning** — `threats.poisoning = true`. Run it twice, `gate.mode = "guarded"` and `"none"`, and the difference is what the gate
  was buying.
- **A3, failure** — `threats.failure_rate > 0` with `on_failure = "open"` against `"closed"`: under a flood of failures, does the system
  miss attacks or raise false alarms? Both are costly, and that is the point.

## Baselines the result is meaningless without

- **Context v0 frozen** — the same Rounds with no curator at all. Everything else is measured against this.
- **The heuristic curator** — no LLM, Examples only. If the LLM curator does not beat it, the reasoning bought nothing.
- **The placebo playbook** — as many rules as the curated Context carries, of the same length, saying something true about network traffic
  and useless for this decision. A playbook rides on every Detector call, so a curated Context is also a longer prompt, and longer prompts
  move a model's answers on their own. Without this arm, "the playbook helped" cannot be told apart from "more text helped". The placebo
  is generated once from the final curated Context's shape, never by the curator.

## Confounds to report, not to hide

- **Prompt length.** Report mean `input_tokens` beside recall for every Context version. The cost figures depend on it too: at TypeSafe's
  list price the playbook's tokens are billed on every Flow.
- **The evidence is a biased sample with unbiased counts.** The curator's observations come through the analyst's truncated alert queue,
  but the `misses` and `false_alarms` counts are Round-wide. A curator can conclude a Category is rare when the analyst simply never
  reached it. Record both the counts and how many Flows the analyst actually reviewed.
