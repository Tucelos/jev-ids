# The virtual environment lives outside the repository unless the shell says otherwise: this folder may sit on a synced volume (iCloud
# Drive evicts files of .venv and hides its .pth files, so `uv run` hangs or cannot import the package). `?=` keeps any value the shell
# already exported.
UV_PROJECT_ENVIRONMENT ?= $(HOME)/.venvs/jev-ids
export UV_PROJECT_ENVIRONMENT

# Quality gate (added by /quality-init). Thresholds live in pyproject.toml / eslint.config.mjs.
.PHONY: check fast check-py check-ts check-dup

check: check-py check-ts check-dup

fast:
	@[ ! -f pyproject.toml ] || (uvx ruff check . && uvx ruff format --check . && uvx complexipy -q --max-complexity-allowed 15 .)
	@[ ! -f package.json ] || (npx eslint . && npx prettier --check .)

check-py:
	@[ ! -f pyproject.toml ] || (uvx ruff check . && uvx ruff format --check . \
	  && uvx complexipy -q --max-complexity-allowed 15 . \
	  && uv run pyright && uv run pytest && uv run vulture \
	  && uv export --format requirements-txt --no-hashes -q | uvx pip-audit --no-deps --disable-pip -r /dev/stdin)

check-ts:
	@[ ! -f package.json ] || (npx tsc --noEmit && npx eslint . && npx prettier --check . \
	  && npx vitest run --coverage && npx knip \
	  && npx madge --circular --extensions ts,tsx --exclude 'node_modules|\.next|dist' . \
	  && npm audit --audit-level=high)

check-dup:
	@npx jscpd .

# Paper protocol (docs/protocol.md): the four detectors over the `paper` split of NSL-KDD into results/paper/, then the summary. Each
# detector is its own target so they can run in separate terminals; `paper` runs them one after the other. The LLM is the slow one, about
# 1.7 s per flow, so it is split into one target per k, each its own run directory: `make -j5 paper-llm` runs the five at once;
# `metrics` and `compare --b` take the five directories together. k stops at 8 since 2026-09-22 (docs/protocol.md).
PAPER_RUN = uv run jev-ids run --dataset data/nsl-kdd/dataset.json --split paper --results-dir results/paper --seeds 0,1,2
LLM_KS = 0 1 2 4 8
.PHONY: paper paper-jev paper-llm paper-random-forest paper-isolation-forest paper-summary

paper: paper-jev paper-llm paper-random-forest paper-isolation-forest paper-summary

paper-jev:
	$(PAPER_RUN) --detector jev --k 0,1,2,4,8

paper-llm: $(addprefix paper-llm-k,$(LLM_KS))

paper-llm-k%:
	$(PAPER_RUN) --detector llm:openai --model gpt-5.6-luna --k $*

paper-gemini: $(addprefix paper-gemini-k,$(LLM_KS))

paper-gemini-k%:
	$(PAPER_RUN) --detector llm:gemini --model gemini-3.6-flash --k $*

paper-random-forest:
	$(PAPER_RUN) --detector random_forest --k 1,2,4,8,all

paper-isolation-forest:
	$(PAPER_RUN) --detector isolation_forest --k all

paper-summary:
	uv run jev-ids metrics results/paper/*/ > results/paper/summary.csv
