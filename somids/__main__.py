"""`python -m somids`: load the secrets and hand the command line to the CLI.

The API keys live in `.env` and never in git (README); loading them is the only thing that happens before `cli.main`.
"""

from dotenv import load_dotenv

from somids import ROOT, cli

if __name__ == "__main__":
    load_dotenv(ROOT / ".env")
    raise SystemExit(cli.main())
