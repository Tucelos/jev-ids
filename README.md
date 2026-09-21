# SOMIDS

Pilot of an intrusion detection system built on TypeSafe's System One Model
Jev, evaluated on NSL-KDD against an LLM baseline and a Random Forest. The
comparison axes are data efficiency (F1 against the number of labeled examples
per category), cost and latency.

## Layout

| Path          | Content                                                           |
| ------------- | ----------------------------------------------------------------- |
| `somids/`     | Package: CLI, dataset, records, metrics, run loop and detectors   |
| `prompts/`    | Versioned prompts (`v1.md`); the prompt hash goes in every record |
| `prices.json` | Dated list prices used to derive cost from measured tokens        |
| `data/`       | Raw NSL-KDD files (ignored) and the committed splits              |
| `results/`    | One directory per run: predictions, raw responses, config         |
| `dev-docs/`   | Brainstorm and grilling records with every design decision        |
| `CONTEXT.md`  | Glossary of the project's terms                                   |

## Usage

Managed with [uv](https://docs.astral.sh/uv/). Secrets live in `.env`
(`AI_GATEWAY_API_KEY`, `DEEPSEEK_API_KEY`, `KAGGLE_USERNAME`, `KAGGLE_KEY`,
`CHATGPT_CLIENT_ID`), never in git.

```bash
uv run python -m somids download
uv run python -m somids split
uv run python -m somids split --band mid            # balanced diagnostic split (hard | mid)
uv run python -m somids split --proportional pilot  # extra proportional split, disjoint
uv run python -m somids run --detector jev --split internal --k 0,1,2,4,8,16 --seeds 0,1,2
uv run python -m somids metrics results/<run_id>
uv run python -m somids compare results/<run_a> results/<run_b>                       # paired, per k and rep
uv run python -m somids compare results/<jev> results/<rf> --subset novel --k-a 0 --k-b all
```

The subcommands land module by module; see
[dev-docs/grilling-01-decisions.md](dev-docs/grilling-01-decisions.md),
section 10, for the order.

## Quality gate

```bash
make check
```

Runs ruff, complexipy, pyright (strict), pytest with coverage, vulture,
pip-audit and jscpd. Thresholds live in `pyproject.toml` and `.jscpd.json`.
