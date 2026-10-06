"""Offline 'brain' transport (§8) — Claude Code (or any human/LLM) answers the
agent's LLM calls without the Anthropic API, so the reasoning layer runs on a
Claude subscription instead of API credits.

Crucially this is a DROP-IN TRANSPORT at the exact seam `llm.LLM` uses for HTTP.
The loop (`loop.py`), the per-step calls and schemas (`steps.py`), and everything
written to the KB are byte-for-byte identical to the API path — only HOW a single
request gets answered changes. Switching back to the API later is just unsetting
`VRA_OFFLINE_DIR`; the loop behaves the same.

Content-addressed, two-pass:
  * key = sha256(model + system + user + schema). Deterministic per request.
  * if `<dir>/cache/<key>.json` exists -> return it wrapped in the SAME response
    shape the API returns (a `tool_use` block named "emit"), so `LLM.structured`
    parses it identically.
  * else -> write `<dir>/pending/<key>.json` (model/system/user/schema) and return
    an HTTP-400-shaped "brain-pending" result, which `LLM._post` turns into
    `LLMUnavailable` WITHOUT retrying; the loop's per-step guard skips it.
So: run once to emit every prompt, fill the answers into `cache/`, run again and
the whole loop completes exactly as the API would have produced it.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Callable


def request_key(model: str, system: str, user: str, schema: dict) -> str:
    blob = "\0".join([model or "", system or "", user or "",
                      json.dumps(schema, sort_keys=True)])
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _dirs(brain_dir: str):
    cache = os.path.join(brain_dir, "cache")
    pending = os.path.join(brain_dir, "pending")
    os.makedirs(cache, exist_ok=True)
    os.makedirs(pending, exist_ok=True)
    return cache, pending


def offline_transport(brain_dir: str) -> Callable:
    """Return a transport fn matching llm.Transport: (url, headers, body, timeout)
    -> (status, resp_bytes)."""
    cache, pending = _dirs(brain_dir)

    def transport(url, headers, body, timeout):
        req = json.loads(body)
        model = req.get("model", "")
        system = req.get("system", "")
        user = req["messages"][0]["content"]
        schema = req["tools"][0]["input_schema"]
        key = request_key(model, system, user, schema)

        cache_f = os.path.join(cache, key + ".json")
        if os.path.isfile(cache_f):
            with open(cache_f) as fh:
                obj = json.load(fh)
            resp = {"stop_reason": "tool_use",
                    "content": [{"type": "tool_use", "name": "emit", "input": obj}]}
            return 200, json.dumps(resp).encode()

        # not answered yet: record the prompt for the brain to fill
        with open(os.path.join(pending, key + ".json"), "w") as fh:
            json.dump({"key": key, "model": model, "system": system,
                       "user": user, "schema": schema}, fh, indent=2)
        return 400, json.dumps(
            {"error": {"message": f"brain-pending:{key} "
                       "(answer it in the brain dir, then re-run)"}}).encode()

    return transport


# -- helpers for the `vra brain` CLI ---------------------------------------
def list_pending(brain_dir: str) -> list:
    _, pending = _dirs(brain_dir)
    out = []
    for fn in sorted(os.listdir(pending)):
        if fn.endswith(".json"):
            with open(os.path.join(pending, fn)) as fh:
                out.append(json.load(fh))
    return out


def answer(brain_dir: str, key: str, obj: dict) -> None:
    cache, pending = _dirs(brain_dir)
    with open(os.path.join(cache, key + ".json"), "w") as fh:
        json.dump(obj, fh, indent=2)
    p = os.path.join(pending, key + ".json")
    if os.path.isfile(p):
        os.remove(p)


def clear_pending(brain_dir: str) -> int:
    _, pending = _dirs(brain_dir)
    n = 0
    for fn in os.listdir(pending):
        if fn.endswith(".json"):
            os.remove(os.path.join(pending, fn)); n += 1
    return n
