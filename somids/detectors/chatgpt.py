"""OpenAI GPT-5.x through the ChatGPT Codex backend, signed in with the Codex
OAuth tokens of the user's original `ChatGPTSubscriptionModel`.

This is the minimal, typed re-implementation agreed in the grilling (Q28, Q34):
the same environment variables and token file as the original module, token
refresh, `base_url`, `store=False`, encrypted reasoning, `reasoning_summary`,
`instructions` injection and the aggregation of the forced stream. The browser
login is not here: run it once through the original module if the refresh
token ever expires.
"""

from __future__ import annotations

import base64
import json
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
from agno.models.message import Message
from agno.models.openai.responses import OpenAIResponses
from agno.models.response import ModelResponse
from agno.run.agent import RunOutput
from pydantic import BaseModel

OAUTH_REFRESH_URL = "https://auth.openai.com/oauth/token"
BACKEND_BASE_URL = "https://chatgpt.com/backend-api/codex"
CLIENT_ID_VAR = "CHATGPT_CLIENT_ID"
OAUTH_FILE_VAR = "CHATGPT_TOKEN_PATH"
DEFAULT_OAUTH_FILE = Path.home() / ".chatgpt_oauth" / "tokens.json"
REFRESH_MARGIN_SECONDS = 300.0
JWT_PARTS = 3
# Tried first (grilling Q29); the backend validates that `instructions` exists.
NEUTRAL_PREAMBLE = (
    "You are a classifier for network intrusion detection. Follow the developer "
    "instructions and answer only in the requested JSON format."
)
# Used only if the backend rejects the neutral preamble.
CODEX_PREAMBLE = (
    "You are Codex, based on GPT-5. You are running as a coding agent in the "
    "Codex CLI on a user's computer."
)


def oauth_file() -> Path:
    return Path(os.environ.get(OAUTH_FILE_VAR, str(DEFAULT_OAUTH_FILE))).expanduser()


def jwt_expiry(token: str) -> float | None:
    """The `exp` claim of a JWT, read without verifying the signature."""
    parts = token.split(".")
    if len(parts) != JWT_PARTS:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims: dict[str, Any] = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    exp = claims.get("exp")
    return None if exp is None else float(exp)


@dataclass(slots=True)
class TokenStore:
    """The OAuth tokens on disk, refreshed through the Codex client id."""

    path: Path = field(default_factory=oauth_file)
    tokens: dict[str, Any] = field(default_factory=dict[str, Any])

    def load(self) -> TokenStore:
        if not self.path.exists():
            msg = (
                f"no OAuth tokens at {self.path}; log in once with the original module"
            )
            raise FileNotFoundError(msg)
        self.tokens = json.loads(self.path.read_text(encoding="utf-8"))
        return self

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.tokens, indent=2), encoding="utf-8")
        self.path.chmod(0o600)

    def is_expired(self, now: float | None = None) -> bool:
        expires_at = float(self.tokens.get("expires_at", 0.0))
        current = now if now is not None else time.time()
        return current + REFRESH_MARGIN_SECONDS >= expires_at

    def access_token(self) -> str:
        if not self.tokens:
            self.load()
        if self.is_expired():
            self.refresh()
        return str(self.tokens["access_token"])

    def refresh(self) -> None:
        client_id = os.environ.get(CLIENT_ID_VAR)
        if not client_id:
            msg = f"{CLIENT_ID_VAR} is not set"
            raise RuntimeError(msg)
        response = requests.post(
            OAUTH_REFRESH_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": self.tokens["refresh_token"],
                "client_id": client_id,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        if not response.ok:
            detail = response.text[:200]
            msg = f"token refresh failed: HTTP {response.status_code} {detail}"
            raise RuntimeError(msg)
        data: dict[str, Any] = response.json()
        access = str(data["access_token"])
        self.tokens["access_token"] = access
        self.tokens["expires_at"] = jwt_expiry(access) or time.time() + 3600
        if "refresh_token" in data:
            self.tokens["refresh_token"] = data["refresh_token"]
        self.save()


@dataclass
class ChatGPTSubscriptionModel(OpenAIResponses):
    """Agno model routed to the ChatGPT Codex backend with an OAuth token."""

    id: str = "gpt-5.6-luna"
    name: str = "ChatGPTSubscription"
    provider: str = "ChatGPT-Subscription"
    preamble: str = NEUTRAL_PREAMBLE
    token_store: TokenStore = field(default_factory=TokenStore)
    _last_token: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        # What the Codex backend requires of every request.
        self.base_url = BACKEND_BASE_URL
        self.store = False
        self.include = ["reasoning.encrypted_content"]
        self.reasoning_summary = "auto"
        self.set_preamble(self.preamble)

    def set_preamble(self, preamble: str) -> None:
        """The backend requires `instructions`; whatever is sent is recorded."""
        self.preamble = preamble
        params: dict[str, Any] = dict(self.request_params or {})
        params["instructions"] = preamble
        self.request_params = params

    def _get_client_params(self) -> dict[str, Any]:
        token = self.token_store.access_token()
        if token != self._last_token:
            self._last_token = token
            self.client = None
            self.async_client = None
        params: dict[str, Any] = {"api_key": token, "base_url": self.base_url}
        for name in ("timeout", "max_retries", "default_headers", "default_query"):
            value = getattr(self, name)
            if value is not None:
                params[name] = value
        if self.client_params:
            params.update(self.client_params)
        return params

    def invoke(  # noqa: PLR0913, PLR0917 - the parent's signature
        self,
        messages: Sequence[Message],
        assistant_message: Message,
        response_format: dict[str, Any] | type[BaseModel] | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
        run_response: RunOutput | None = None,
        compress_tool_results: bool = False,
    ) -> ModelResponse:
        """The backend only streams; collect the deltas into one response."""
        parent: Any = super()
        deltas = parent.invoke_stream(
            messages=list(messages),
            assistant_message=assistant_message,
            response_format=response_format,
            tools=tools,
            tool_choice=tool_choice,
            run_response=run_response,
            compress_tool_results=compress_tool_results,
        )
        return aggregate(deltas)


def aggregate(deltas: Any) -> ModelResponse:
    """Merge streamed deltas: text, reasoning, usage and provider data."""
    merged = ModelResponse()
    merged.role = "assistant"
    content: list[str] = []
    reasoning: list[str] = []
    for delta in deltas:
        _collect_text(delta, content, reasoning)
        _collect_metadata(delta, merged)
    if content:
        merged.content = "".join(content)
    if reasoning:
        merged.reasoning_content = "".join(reasoning)
    return merged


def _collect_text(delta: Any, content: list[str], reasoning: list[str]) -> None:
    if delta.content is not None:
        content.append(delta.content)
    if delta.reasoning_content is not None:
        reasoning.append(delta.reasoning_content)


def _collect_metadata(delta: Any, merged: ModelResponse) -> None:
    if delta.response_usage is not None:
        merged.response_usage = delta.response_usage
    if delta.provider_data is not None:
        merged.provider_data = {**(merged.provider_data or {}), **delta.provider_data}
