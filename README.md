<img src="docs/banner.svg" alt="Jev IDS banner showing the jev_ids terminal lockup, the tagline &quot;Intrusion detection with a System One Model, benchmarked against an LLM and a Random Forest.&quot;, and the command that runs a detector over NSL-KDD" width="100%" />

# Jev IDS

![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-0B6B3A?style=flat&labelColor=121917) ![Detector Jev, from TypeSafe](https://img.shields.io/badge/detector-Jev%20%28TypeSafe%29-0B6B3A?style=flat&labelColor=121917) ![Dataset NSL-KDD](https://img.shields.io/badge/dataset-NSL--KDD-0B6B3A?style=flat&labelColor=121917) ![Pilot F1 0.86](https://img.shields.io/badge/pilot%20F1-0.86-0B6B3A?style=flat&labelColor=121917)

**An intrusion detection system that asks TypeSafe's Jev two typed questions about one network flow and gets a verdict back, with no text to parse.**

Give it one flow record and one labeled example per category. [TypeSafe's Jev](https://docs.typesafe.ai/introduction) answers the probability that the flow is an attack and the category it belongs to, in one request.

**Five labeled flows. F1 0.86 on NSL-KDD. Half a second per verdict.** In the same pilot, GPT-5.6 reached 0.78 at 2.4 s per flow and a Random Forest 0.73. On attacks of a kind absent from the examples, Jev caught 84% and the LLM 55%.

[Read the loop](jev_ids/run.py) · [The request template](prompts/nsl-kdd/jev.json) · [Glossary](CONTEXT.md)

## The request

Jev is a System One Model. It takes a `state` and typed questions about it and returns typed answers with probabilities instead of generated text. Jev IDS sends one flow per request. The state holds the instructions, the column header, the five category descriptions, the labeled examples and the flow under test. Two questions point at it:

```text
is_attack   noul     Is the connection an intrusion attempt?   → 0.82
category    choice   Which category does it belong to?        → dos, confidence 0.84
```

```text
                          one TypeSafe request
                    ┌────────────────────────────────┐
flow + k examples   │ state: instructions, columns,  │
per category ──────►│        categories, examples,   │
                    │        flows.under_test        │
                    │ is_attack (noul)               │──► p_attack ──► ≥ 0.5 → attack
                    │ category  (choice)             │──► category, confidence
                    └────────────────────────────────┘
```

The verdict is p_attack ≥ 0.5, the same cut for every detector. The whole conversation with Jev lives in [`prompts/nsl-kdd/jev.json`](prompts/nsl-kdd/jev.json). Python adds only the flow and the examples, and the sha256 of the file travels in every prediction row as `prompt_hash`. Examples are labeled by category only, so attack names such as `neptune` never reach a model.

The same protocol runs two baselines: an LLM through an Agno agent with a JSON output schema (GPT-5.6 through the ChatGPT Codex backend, or DeepSeek), and a scikit-learn Random Forest trained on the same k examples. Every detector judges the same frozen split with the same examples, drawn from the same seeds.

## Try it

```bash
git clone https://github.com/jev-ids/jev-ids.git
cd jev-ids
uv sync
# .env: AI_GATEWAY_API_KEY for Jev through the Vercel AI Gateway; DEEPSEEK_API_KEY and CHATGPT_CLIENT_ID only for the LLM baselines.
```

Download [NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd) into `data/raw/nsl-kdd/` and prepare it once:

```bash
uv run python -m scripts.prepare_nsl_kdd
uv run jev-ids run --dataset data/nsl-kdd/dataset.json --detector jev --split smoke --k 0,1
```

The smoke split is five flows. The run writes `results/<timestamp>-nsl-kdd-jev-smoke/` with `config.json`, one JSON row per flow in `predictions.jsonl` (the verdict, the truth, p_attack, the category, the confidence, the latency and the gateway's token report) and the raw answers in `responses.jsonl`.

## Compare detectors

```bash
uv run jev-ids run --dataset data/nsl-kdd/dataset.json --detector jev --split pilot --k 0,1,2,4,8,16 --seeds 0,1,2
uv run jev-ids run --dataset data/nsl-kdd/dataset.json --detector llm:openai --model gpt-5.6-luna --split pilot --k 0,1,2,4,8,16
uv run jev-ids run --dataset data/nsl-kdd/dataset.json --detector random_forest --split pilot --k 1,2,4,8,16,all
uv run jev-ids metrics results/<run_id> [results/<run_id> ...] > results/summary.csv
uv run jev-ids compare results/<jev_run> results/<rf_run> --subset novel --k-a 0 --k-b all
```

k is the number of labeled examples per category. k = 1 with five categories means five examples, and `all` means the whole pool. `metrics` prints one CSV row per detector and k with F1, recall on novel attacks, tokens, latency and cost. `compare` pairs two runs flow by flow and runs McNemar's test on the discordant pairs, because only the flows two detectors disagree on tell them apart. Cost is computed offline as tokens times the list prices in [`prices.json`](prices.json), for every detector alike.

## Why it is fast and cheap

- **One request per flow, two answers.** Jev evaluates both questions in parallel over the same state. The answers are a probability, an option and a confidence, so there is no text to parse and no output schema to enforce.
- **Input only.** Jev's list price is $0.042 per million input tokens and output is free. A k = 1 request is about 1,800 tokens, so a million verdicts cost about $74 at list price.
- **The prompt is a file.** Jev's template and the LLM's instructions are text files hashed into every row. Changing a word changes the hash, and runs with different hashes are never compared as equals.
- **Flows in the innermost loop.** k, then seed, then repetition, then every flow of the split. The prompt prefix stays constant for as long as possible, so provider prefix caches get their best chance.
- **Fail open, log everything.** A failed call ends as a row with `error`, never as a crash, and the metrics count it as no alert.
- **Same cut for everyone.** p_attack ≥ 0.5 decides the verdict for Jev, the LLM and the Random Forest. No per-detector threshold tuning.

## Small enough to read

| File                                                             | Job                                                                        |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------- |
| [cli.py](jev_ids/cli.py)                                         | `run`, `metrics` and `compare`                                             |
| [dataset.py](jev_ids/dataset.py)                                 | The card, the pool, the splits and the k-shot example draw                 |
| [run.py](jev_ids/run.py)                                         | The loop, cell by cell and flow by flow, and the three files of a run      |
| [records.py](jev_ids/records.py)                                 | One prediction row and its JSONL                                           |
| [metrics.py](jev_ids/metrics.py)                                 | F1, novel recall, tokens, cost, latency, and the paired comparison         |
| [detectors/jev.py](jev_ids/detectors/jev.py)                     | Jev through the Vercel AI Gateway, one flow per request                    |
| [detectors/llm.py](jev_ids/detectors/llm.py)                     | The LLM baselines through Agno                                             |
| [detectors/random_forest.py](jev_ids/detectors/random_forest.py) | The classical baseline                                                     |
| [prompts/nsl-kdd/](prompts/nsl-kdd)                              | `jev.json`, the whole request template; `llm.md`, the agent's instructions |

## Evidence and limits

Pilot split of NSL-KDD: 300 flows, 160 of them attacks and 39 of those of a kind absent from KDDTrain+. Three seeds of examples, so 900 predictions per detector and k. Means over the three seeds, from the runs of 2026-09-21.

| Detector                  | k   | F1        | Precision | Recall | Novel-attack recall | Latency  | Cost per 1M flows |
| ------------------------- | --- | --------- | --------- | ------ | ------------------- | -------- | ----------------- |
| Jev (`typesafe-ai/jev`)   | 1   | **0.859** | 0.941     | 0.790  | **0.838**           | 504 ms   | $74               |
| GPT-5.6 (`gpt-5.6-luna`)  | 1   | 0.776     | 0.914     | 0.675  | 0.547               | 2,410 ms | $283              |
| Random Forest (100 trees) | 1   | 0.728     | 0.574     | 1.000  | 1.000               | 3 ms     | local             |
| Jev                       | 2   | 0.839     | 0.929     | 0.765  | 0.761               | 494 ms   | $106              |
| GPT-5.6                   | 2   | 0.807     | 0.930     | 0.715  | 0.573               | 2,476 ms | $399              |
| Random Forest             | 2   | 0.766     | 0.629     | 0.990  | 0.991               | 2 ms     | local             |

Jev against the Random Forest at k = 1: of 900 paired verdicts, 439 differ. Jev is right in 338 of them and the forest in 101 (McNemar p ≈ 6 × 10⁻³¹). A forest trained on five rows calls almost everything an attack, which is why its recall is perfect and its precision is not.

Limits worth knowing:

- These are pilot numbers, taken to settle the protocol. The reported results will come from the disjoint `paper` split with k up to 16. NF-UQ-NIDS-v2 has a card and a preparation script and no run yet.
- Latency is the wall clock around the successful HTTP call, measured from the client through the Vercel AI Gateway. The gateway rate-limits often: 1,350 of the 1,800 Jev rows needed at least one retry, and the retries are not in the latency.
- Cost is tokens times list prices, not what was billed. Jev was free under a promotion until 2026-09-25, and GPT-5.6 ran through the ChatGPT Codex backend, priced here at the public API list rate.
- The gateway masks Jev's version (it reports `typesafe-ai/jev`; TypeSafe direct reports `jev-1.13.0`). The run date in `config.json` is the only pin.
- Jev's `noul` answer carries no confidence. Only the `choice` answer does.

## Development

```bash
make check
```

Python 3.13+. The gate runs ruff with Google-style docstring rules, complexipy, pyright in strict mode, pytest with coverage, vulture, pip-audit and jscpd. Thresholds live in `pyproject.toml` and `.jscpd.json`. Runs make paid API calls and write only under `results/`.

Jev IDS is an independent research project and is not affiliated with TypeSafe or Vercel.

---

[TypeSafe docs](https://docs.typesafe.ai/introduction) · [Jev on the Vercel AI Gateway](https://vercel.com/ai-gateway/models/jev) · [NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd) · [Glossary](CONTEXT.md)
