# Jev IDS — the Arena fork

**An adversarial loop around an intrusion Detector.** An attacker mutates attack Flows until the
Detector stops alerting on them; a simulated analyst labels the small share of the traffic a real SOC
would have time for; an LLM curator reads only those labels and rewrites the Detector's Context
between Rounds; and a gate refuses any rewritten Context that buys recall by raising false alarms.
Ten Rounds of that is one Run, and the question a Run exists to answer is whether a Detector whose
prompt is rewritten each Round holds up against an attacker who adapts to it.

> ## This is a fork, and the baseline numbers are not ours
>
> Upstream is **[jev-ids/jev-ids](https://github.com/jev-ids/jev-ids)** by **Paulo Severo**, **Silvio
> Quincozes** and **Amanda Dias**, MIT licensed. It is the Detector, the Dataset preparation, the
> metrics and the paper protocol; everything under `results/paper/` was measured by them and is
> quoted here, never re-measured. The [`LICENSE`](LICENSE) is theirs and stays as it is, and their
> front page is preserved word for word at
> [`docs/upstream-readme.md`](docs/upstream-readme.md) — read it first if you want to know what Jev
> IDS is before reading what this fork does to it.
>
> What this fork adds is everything under `jev_ids/arena/`, `configs/arena*.toml`,
> `prompts/arena/`, `docs/arena/` and `trabalho-adversarial/`.

## What is new here

A **Context** is the only thing about the Detector that may change between Rounds: a **playbook** of
up to fifteen short sentences placed in the request's `state`, and up to ten Pool Flows chosen as
Examples. The instructions, the column names, the Category descriptions, the wording of both
questions and the 0.5 cut are protocol and no Context may touch them.

One Round, in the order [`docs/arena/loop-design.md`](docs/arena/loop-design.md) fixes:

1. **Attack.** The attacker takes twenty attack Flows of the `arena` Split and spends at most thirty
   Detector calls on each, searching for a setting the Detector no longer alerts on. It never writes
   a derived feature value: it copies the whole twenty-feature derived block from one real benign
   Pool Flow — a **donor** — and moves only `duration` and `src_bytes`, increase-only, inside
   measured bounds. What it returns is a **Strategy** (a donor bucket plus the two lever settings),
   not a mutated Flow, so the same technique can be replayed on Flows it never touched.
2. **Traffic.** The whole `arena` Split, its attack Flows mutated with the Strategies found, judged
   under the Context in force.
3. **Labels.** The analyst reviews the alert queue down to fifty, highest `p_attack` first, plus a
   10% sample of the Flows that raised none. That sample is the only channel through which a missed
   attack can ever become knowledge.
4. **Learn.** The curator reads those labels — never a Flow's true Category, never whether a label
   was tampered with — and proposes two Contexts.
5. **Gate.** Each proposal and the incumbent judge the *same* held-out `arena-val` Split, mutated
   with this Round's Strategies. A proposal is kept only if it loses no recall it cannot be shown to
   have lost by chance and raises the false-alarm rate by no more than two points.

## Three findings that are this project's own

- **The coupling identities the adversarial-ML literature assumes for NSL-KDD do not hold.** Three of
  the four are violated in **27.5% to 60.5%** of the **125,973** Pool Flows, because `count` and
  `srv_count` are taken over two *parallel* windows rather than one nested pair, and the
  `dst_host_*` counts saturate at 255. That is why the attacker copies a real donor's block instead
  of computing one. Measured by `scripts/fit_mutations.py`; the table is in
  [`docs/arena/empirical-constraints.md`](docs/arena/empirical-constraints.md).
- **For r2l, slowing down is not a lever.** **69.3%** of the `arena` Split's r2l Flows already sit at
  `count = 1`, against 37.5% for probe. An attacker cannot thin a window that holds one connection,
  so the two Categories under attack have very different room to move — and the contrast between
  them is the result, not a nuisance ([`configs/arena.toml`](configs/arena.toml), `[attacker]`).
- **A curated Context changes three things at once, so the answer needs four arms.** It changes which
  Examples are shown, how long the prompt is, and what the playbook says. `baseline →
  examples_only → placebo → final` holds one more of them fixed at each step, and the
  `placebo → final` step is the only one that separates *"the playbook helped"* from *"more text
  helped"*. Without the placebo arm the headline claim is not testable
  ([`jev_ids/arena/final.py`](jev_ids/arena/final.py)).

**No result yet.** The loop has never been run against Jev. Only the no-key offline smoke run below
has been executed, and the offline Detector is a Random Forest that cannot read a playbook at all —
nothing measured with it is a result. Every number on this page is either upstream's or a measurement
of the Dataset itself.

## Install

Python 3.13 and [`uv`](https://docs.astral.sh/uv/). **`make` is not required and is not used here** —
the [`Makefile`](Makefile) targets are kept for upstream's macOS and Linux machines, and every
command on this page is the direct `uv` equivalent.

```bash
git clone https://github.com/Tucelos/jev-ids.git
cd jev-ids
uv sync
cp .env.example .env
```

`.env` is git-ignored and lists every key the project can read. Fill only what you run: nothing at
all for the offline smoke run, `TYPESAFE_API_KEY` for the Detector, and one provider key
(`DEEPSEEK_API_KEY` or `OPENAI_API_KEY`) for the LLM curator.

## Get the data

Download [NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd) into `data/raw/nsl-kdd/` — the
two files `KDDTrain+.txt` and `KDDTest+.txt` — then prepare it once:

```bash
uv run python -m scripts.prepare_nsl_kdd
```

That writes `data/nsl-kdd/pool.csv` (125,973 Flows) and `data/nsl-kdd/test.csv` (22,544). The Splits
under `data/nsl-kdd/splits/` and the constraint model `data/nsl-kdd/mutations.json` are committed, so
nothing else has to be drawn or fitted.

## Run the loop with no API key and no cost

```bash
uv run jev-ids arena --config configs/arena-offline.toml --dry-run   # what it would spend
uv run jev-ids arena --config configs/arena-offline.toml             # about 35 s, every call free
```

Two Rounds against a Random Forest wearing the Context's prompt hash. It exercises the attacker's
search, the analyst's budget, the shortlist, the curator, the gate and all four files a Run writes,
and it produces **no result whatsoever**. A gate that rejects every proposal is the expected outcome
and not a failure; [`docs/arena/como-rodar.md`](docs/arena/como-rodar.md) walks through the output
line by line.

## Run the loop for real

```bash
uv run jev-ids arena --dry-run                    # 19,000 Detector calls against a 20,000 cap
uv run jev-ids arena --config configs/arena.toml  # the committed protocol: 10 Rounds, seed 0
```

Needs `TYPESAFE_API_KEY` and the curator's provider key. The Run projects its whole cost before the
first call and refuses to start one it cannot finish, before creating any directory. Three seeds cost
57,000 calls and are refused on purpose; see [`docs/arena/como-rodar.md`](docs/arena/como-rodar.md)
for the arithmetic and what to do about it.

## Measure a finished Run

The loop's own numbers cannot answer whether the curator helped: across a Run, version 0 and the
final Context were in force in different Rounds against different mutations. This judges four
Contexts over one identical set of Flows on the untouched `paper` Split:

```bash
uv run jev-ids arena-eval results/arena/<run_id> --dry-run
uv run jev-ids arena-eval results/arena/<run_id>                      # prints the table as CSV
uv run jev-ids arena-eval results/arena/<run_id> --report results/arena-eval/<eval_id>
```

The four rows per seed read as three steps: `baseline → examples_only` is what choosing the Examples
bought, `examples_only → placebo` is what the extra prompt length bought, and `placebo → final` is
what the Rules actually say. Recall never appears without mean `input_tokens` beside it.

The per-Round and per-Run tables are not on the command line yet; reach them from Python:

```bash
uv run python -c "from pathlib import Path; from jev_ids.arena import report; from jev_ids.cli import print_csv; print_csv(report.summarize_rounds(Path('results/arena/<run_id>')))"
```

## The repository, file by file

| File | Job |
| --- | --- |
| [cli.py](jev_ids/cli.py) | `run`, `redo-errors`, `metrics`, `compare`, `arena`, `arena-eval` |
| [dataset.py](jev_ids/dataset.py) | The Card, the Pool, the Splits and the k-shot Example draw |
| [run.py](jev_ids/run.py) | Upstream's loop, cell by cell and Flow by Flow |
| [records.py](jev_ids/records.py) | One Prediction row and its JSONL |
| [metrics.py](jev_ids/metrics.py) | F1, recall per Category, PR-AUC, tokens, cost, McNemar |
| [detectors/jev.py](jev_ids/detectors/jev.py) | Jev through TypeSafe's API, one Flow per request |
| [detectors/llm.py](jev_ids/detectors/llm.py) | The LLM baselines through Agno |
| [detectors/random_forest.py](jev_ids/detectors/random_forest.py) | The classical baseline |
| [detectors/isolation_forest.py](jev_ids/detectors/isolation_forest.py) | The unsupervised baseline |
| [detectors/offline.py](jev_ids/detectors/offline.py) | That forest wearing a Context's prompt hash, so the Arena runs free |
| [arena/context.py](jev_ids/arena/context.py) | The Context: the playbook, the chosen Examples, and how it renders to a prompt |
| [arena/config.py](jev_ids/arena/config.py) | Every knob of `configs/arena.toml`; an unknown key raises at load time |
| [arena/budget.py](jev_ids/arena/budget.py) | The hard cap on the calls one Run may make |
| [arena/attacker.py](jev_ids/arena/attacker.py) | Constrained mimicry by donor substitution, and the search over it |
| [arena/analyst.py](jev_ids/arena/analyst.py) | The simulated analyst, the label budget, the poisoning arm and `for_curator` |
| [arena/curator.py](jev_ids/arena/curator.py) | The LLM curator and the heuristic baseline it has to beat |
| [arena/gate.py](jev_ids/arena/gate.py) | Whether a proposed Context replaces the one in force, and why |
| [arena/loop.py](jev_ids/arena/loop.py) | One Round played over and over, and the pre-flight projection |
| [arena/records.py](jev_ids/arena/records.py) | The four files a Run writes |
| [arena/report.py](jev_ids/arena/report.py) | The per-Round, per-Run and Run-against-Run tables |
| [arena/final.py](jev_ids/arena/final.py) | The four-arm measurement on the untouched Split |
| [configs/arena.toml](configs/arena.toml) | The committed protocol, every knob commented |
| [configs/arena-offline.toml](configs/arena-offline.toml) | The same loop with no key and no cost |
| [prompts/arena/curator.md](prompts/arena/curator.md) | What the LLM curator is told |
| [scripts/fit_mutations.py](scripts/fit_mutations.py) | Fits `data/nsl-kdd/mutations.json` from the Pool |

## Documentation

| Where | What |
| --- | --- |
| [`docs/arena/`](docs/arena/README.md) | The fork's own documentation: how to run it, how it is built, and the four research documents behind it (index in Portuguese, research in English) |
| [`trabalho-adversarial/README.md`](trabalho-adversarial/README.md) | The course report, in Portuguese: actors, strategic model, threats, limits |
| [`CONTEXT.md`](CONTEXT.md) | The glossary. Flow, Category, Split, Detector, Prediction, Verdict — use these words and no others |
| [`docs/upstream-readme.md`](docs/upstream-readme.md) | Upstream's front page, preserved |
| [`docs/protocol.md`](docs/protocol.md) and [`docs/results.md`](docs/results.md) | Upstream's paper protocol and published results |
| [`docs/arena/tarefas.md`](docs/arena/tarefas.md) | What the fork inherited and has not decided yet |

## Development

No `make` on Windows. Run the gate's parts directly:

```bash
uvx ruff check . && uvx ruff format --check .
uvx complexipy -q --max-complexity-allowed 15 .
uv run pyright
uv run pytest
```

`make check` also runs vulture, pip-audit and jscpd; read them off the [`Makefile`](Makefile) if you
want the full gate. Thresholds live in [`pyproject.toml`](pyproject.toml). `git config core.autocrlf false` matters here:
prompts, Cards and Splits are hashed as bytes, so a CRLF checkout silently changes every
`prompt_hash` and stops a Run being comparable with upstream's. [`.gitattributes`](.gitattributes)
pins `eol=lf` for exactly that reason.

---

Fork of [jev-ids/jev-ids](https://github.com/jev-ids/jev-ids) · MIT · not affiliated with TypeSafe ·
[Glossary](CONTEXT.md)
