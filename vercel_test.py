"""Probe Jev directly through Vercel AI Gateway with the classifier.dev test case.

Mirrors the request classifier.dev builds internally (src/jev.ts): the state is a
list of ``{id, text}`` items and each item gets one ``choice`` question with the
instructions appended. Same row, same labels and same instructions.txt as the
classifier.dev call, so the answer is directly comparable with the wrapper's
output (label teardrop, scores 0.95/0.05, confidence 0.9).

Prints the raw response plus the four numbers the paper needs per request:
probabilities, confidence, input tokens and gateway cost, and the end-to-end
latency measured on the client.
"""

import json
import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
GATEWAY_URL = "https://ai-gateway.vercel.sh/typesafe/v1/systemone"
MODEL = "typesafe-ai/jev"
LABELS = ["normal", "teardrop"]
ITEM_ID = "i0"
ROW = (
    "0,udp,private,SF,28,0,0,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,30,30,"
    "0.00,0.00,0.00,0.00,1.00,0.00,0.00,255,97,0.38,0.01,0.38,0.00,0.00,0.00,0.00,0.00"
)


def build_payload(instructions: str) -> dict[str, object]:
    """Same shape classifier.dev sends upstream for a single-label request."""
    question = f"Which category does item `{ITEM_ID}` belong to? {instructions}"
    return {
        "model": MODEL,
        "state": [{"id": ITEM_ID, "text": ROW}],
        "questions": {
            ITEM_ID: {
                "type": "choice",
                "instructions": question,
                "criteria": {label: None for label in LABELS},
            }
        },
    }


def main() -> None:
    load_dotenv(HERE / ".env")
    api_key = os.environ["AI_GATEWAY_API_KEY"]
    instructions = (HERE / "instructions.txt").read_text(encoding="utf-8").strip()

    started = time.perf_counter()
    response = requests.post(
        GATEWAY_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=build_payload(instructions),
        timeout=60,
    )
    latency_ms = (time.perf_counter() - started) * 1000
    if not response.ok:
        # The gateway answers 402/403/429 with a JSON body that says why
        # (no card on file, exhausted credit, rate limit); show it.
        raise SystemExit(f"HTTP {response.status_code}: {response.text}")
    body = response.json()

    answer = body["answers"][ITEM_ID]
    gateway = body.get("provider_metadata", {}).get("gateway", {})

    print(json.dumps(body, indent=2, ensure_ascii=False))
    print("---")
    print(f"choice        : {answer.get('choice')}")
    print(f"probabilities : {answer.get('probabilities')}")
    print(f"confidence    : {answer.get('confidence')}")
    print(f"input_tokens  : {body.get('usage', {}).get('input_tokens')}")
    print(f"cost_usd      : {gateway.get('cost')}")
    print(f"latency_ms    : {latency_ms:.0f} (client, end to end)")


if __name__ == "__main__":
    main()
