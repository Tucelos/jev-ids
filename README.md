# SOMIDS

Intrusion detection system built on TypeSafe's System One Model Jev,
evaluated on NSL-KDD against an LLM baseline and a Random Forest. The
comparison axes are data efficiency (F1 against the number of labeled examples
per category), cost and latency. A second dataset, NF-UQ-NIDS-v2, is prepared
in the same shape; the package itself never names a dataset.

## Layout

| Path          | Content                                                                                                                    |
| ------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `somids/`     | Package: `cli`, `dataset`, `run`, `records`, `metrics` and `detectors/`; each module's docstring is its reading guide      |
| `scripts/`    | One preparation script per dataset, run once after the download                                                            |
| `prompts/`    | Per dataset: `jev.json` (Jev's request template: state and questions) and `llm.md` (the Agno agent's instructions)         |
| `prices.json` | Dated list prices; `metrics` prices the tokens each row carries                                                            |
| `data/`       | `raw/` (ignored; downloaded by hand) and one `<dataset>/` folder: the card `dataset.json`, `pool.csv` (ignored), `splits/` |
| `results/`    | One directory per run: predictions, raw responses, config                                                                  |
| `CONTEXT.md`  | Glossary of the project's terms                                                                                            |

## Usage

Managed with [uv](https://docs.astral.sh/uv/). Secrets live in `.env`
(`AI_GATEWAY_API_KEY`, `DEEPSEEK_API_KEY`, `KAGGLE_USERNAME`, `KAGGLE_KEY`,
`CHATGPT_CLIENT_ID`), never in git.

A dataset is prepared once: download it by hand into `data/raw/<dataset>/`
and run its script, which writes `pool.csv` (and, for NSL-KDD, `test.csv`)
next to the card `data/<dataset>/dataset.json`.

```bash
uv run python -m scripts.prepare_nsl_kdd   # data/raw/nsl-kdd -> data/nsl-kdd/{pool,test}.csv
uv run python -m scripts.prepare_nf_uq_nids_v2 --novel <CATEGORY> ...   # one pass over the 13.7 GB CSV
```

NF-UQ-NIDS-v2 is sampled, not converted: a class-balanced pool and three
proportional splits in one pass, with the categories named by `--novel` held
out of the pool as the novel attacks. The script checks the card's feature
names against the file's header before it samples.

Every run names its dataset by the card:

```bash
uv run python -m somids run --dataset data/nsl-kdd/dataset.json --detector jev --split internal --k 0,1,2,4,8,16 --seeds 0,1,2
uv run python -m somids run --dataset data/nsl-kdd/dataset.json --detector llm:openai --split paper --k 0 --reps 3 --model gpt-5.6-luna
uv run python -m somids run --dataset data/nsl-kdd/dataset.json --detector random_forest --split paper --k 1,2,4,8,16,all
uv run python -m somids metrics results/<run_id> [results/<run_id> ...] > results/summary.csv
uv run python -m somids compare results/<run_a> results/<run_b>                     # paired, per k and rep
uv run python -m somids compare results/<jev> results/<rf> --subset novel --k-a 0 --k-b all
```

`run` judges one Flow per request, always in CSV. Jev reads its request
template from `prompts/<dataset>/jev.json` and the LLMs their instructions
from `prompts/<dataset>/llm.md`; Python adds only the record and the
examples, and the sha256 of the file used goes in every row as `prompt_hash`.
Every run gets a fresh `results/<timestamp>-<dataset>-<detector>-<split>`
directory with `config.json`, `predictions.jsonl` (one row per Flow: the
cell, the truth, the Verdict and whatever the detector measured, including
the provider's token report as `usage`) and `responses.jsonl` (the raw
answers, ignored by git). `metrics` and `compare` print CSV on stdout and
write nothing; redirect them to keep a file. Cost is computed there, offline:
tokens × the list prices of `prices.json`.

The card lists the dataset's features, the symbolic ones among them, its
categories and the benign label. `pool.csv` and `splits/*.csv` share one
shape: `row_id`, one column per feature, `category`, `novel_attack`; extra
columns are trace only. The NSL-KDD splits were drawn by the `split`
subcommand that existed until 2026-09-21 and are committed as they were
(`data/nsl-kdd/splits/SOURCE.json` records the draw).

## Quality gate

```bash
make check
```

Python 3.13+. Runs ruff (with Google-style docstring rules), complexipy,
pyright (strict), pytest with coverage, vulture, pip-audit and jscpd.
Thresholds live in `pyproject.toml` and `.jscpd.json`.
