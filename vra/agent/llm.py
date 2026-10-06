"""Anthropic client for the agent's reasoning (§8) — stdlib HTTP, no SDK.

The agent used to depend on the `anthropic` SDK, which on this py3.9 host is
pinned to the 0.x line (structured output only via `extra_body`). We now talk to
the Messages API directly over `urllib` so:
  * there is no SDK version cap (py3.9 is fine),
  * `available()` needs only a key (no importable package), and
  * structured output is forced via a single-tool `tool_choice`, which returns
    schema-valid JSON on every stable API version — the model can't "forget" a
    field the way it can when asked to emit JSON as free text.

Every call is wrapped so a transient API error degrades (raises LLMUnavailable)
instead of crashing the pipeline; the orchestrator catches that and falls back
to the deterministic path. We never print or log the key.

Auth: ANTHROPIC_API_KEY env, else a key file (project `.anthropic_key` or
~/.config/anthropic/key).
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Optional

DEFAULT_MODEL = os.environ.get("VRA_MODEL", "claude-opus-5-5")
API_URL = os.environ.get("VRA_API_URL", "https://api.anthropic.com/v1/messages")
API_VERSION = "2023-06-01"

_KEY_FILES = [
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                 ".anthropic_key"),
    os.path.expanduser("~/.config/anthropic/key"),
]

# Transport signature: (url, headers, body_bytes, timeout) -> (status, resp_bytes).
Transport = Callable[[str, dict, bytes, float], "tuple[int, bytes]"]


class LLMUnavailable(RuntimeError):
    """No API key, or the API errored/refused after retries."""


def _load_key() -> Optional[str]:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return os.environ["ANTHROPIC_API_KEY"]
    for p in _KEY_FILES:
        try:
            with open(p) as fh:
                k = fh.read().strip()
            if k:
                return k
        except OSError:
            continue
    return None


def available() -> bool:
    """A key is all we need now (no SDK import)."""
    return _load_key() is not None


def _urllib_transport(url: str, headers: dict, body: bytes,
                      timeout: float) -> "tuple[int, bytes]":
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class LLM:
    """One handle to the Messages API. `structured()` is the only entry point the
    rest of the agent uses; `_transport` is injectable for tests."""

    def __init__(self, model: str = DEFAULT_MODEL, *,
                 transport: Optional[Transport] = None, max_retries: int = 4,
                 timeout: float = 120.0):
        key = _load_key()
        if key is None:
            raise LLMUnavailable(
                "No Anthropic API key. Set ANTHROPIC_API_KEY, or write it to "
                f"{_KEY_FILES[0]} (chmod 600).")
        self.model = model
        self._key = key
        self._transport = transport or _urllib_transport
        self._max_retries = max_retries
        self._timeout = timeout

    # -- public ------------------------------------------------------------
    def structured(self, system: str, user: str, schema: dict, *,
                   effort: str = "high", max_tokens: int = 8000,
                   temperature: float = 0.0) -> dict:
        """Force a schema-valid JSON object via single-tool tool_choice.

        `effort` is accepted for call-site compatibility; the Messages API has
        no such field, so it is ignored (the model runs adaptive by default)."""
        tool = {"name": "emit", "description":
                "Return the result as the single structured object for this task.",
                "input_schema": schema}
        body = {
            "model": self.model, "max_tokens": max_tokens,
            "temperature": temperature, "system": system,
            "messages": [{"role": "user", "content": user}],
            "tools": [tool], "tool_choice": {"type": "tool", "name": "emit"},
        }
        resp = self._post(body)
        if resp.get("stop_reason") == "refusal":
            raise LLMUnavailable("model refused the request")
        for block in resp.get("content", []):
            if block.get("type") == "tool_use" and block.get("name") == "emit":
                return block.get("input", {})
        # Fallback: a plain-text answer we try to parse (older/edge behavior).
        for block in resp.get("content", []):
            if block.get("type") == "text":
                return _parse_json(block["text"])
        raise LLMUnavailable("no tool_use/text block in response")

    # -- transport ---------------------------------------------------------
    def _post(self, body: dict) -> dict:
        headers = {"content-type": "application/json",
                   "x-api-key": self._key,
                   "anthropic-version": API_VERSION}
        raw = json.dumps(body).encode()
        last = ""
        for attempt in range(self._max_retries):
            try:
                status, data = self._transport(API_URL, headers, raw, self._timeout)
            except Exception as e:                       # network / socket error
                last = f"transport error: {e}"
                status, data = 0, b""
            if status == 200:
                try:
                    return json.loads(data)
                except ValueError as e:
                    raise LLMUnavailable(f"bad JSON from API: {e}") from e
            last = _err_text(status, data)
            if status in (408, 409, 429, 500, 502, 503, 504, 0):
                time.sleep(min(2 ** attempt, 20))        # exp backoff, capped
                continue
            break                                        # 400/401/403: don't retry
        raise LLMUnavailable(f"API call failed ({last})")


def _err_text(status: int, data: bytes) -> str:
    try:
        j = json.loads(data)
        msg = j.get("error", {}).get("message") or j.get("message") or ""
    except Exception:
        msg = data[:200].decode("utf-8", "replace")
    return f"HTTP {status}: {msg}".strip()


def _parse_json(text: str) -> dict:
    text = text.strip()
    try:
        return json.loads(text)
    except ValueError:
        s, e = text.find("{"), text.rfind("}")
        if s >= 0 and e > s:
            return json.loads(text[s:e + 1])
        raise LLMUnavailable("response was not JSON")
