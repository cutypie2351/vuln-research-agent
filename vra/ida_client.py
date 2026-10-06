"""Dependency-light MCP client for the IDA Pro MCP server.

The harness talks to a running IDA instance over the MCP streamable-HTTP
transport (JSON-RPC 2.0). This is the standalone-harness replacement for the
Ghidra-headless script in the original plan (§3): instead of a one-shot dump,
we get a live, queryable RE backend.

Transport notes (verified against zeromcp/1.3.0, protocol 2025-06-18):
  - POST JSON-RPC to the /mcp endpoint.
  - Server assigns a session via the `Mcp-Session-Id` response header on
    `initialize`; it must be echoed on every subsequent request.
  - Responses may be plain `application/json` or SSE (`text/event-stream`);
    both are handled here.
  - Tool results arrive as {content:[{type:text,text:<json-string>}],
    structuredContent:<obj>}. We prefer `structuredContent`.

stdlib only (urllib) on purpose — the client must be robust and portable.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Optional

DEFAULT_URL = "http://127.0.0.1:13337/mcp"
PROTOCOL_VERSION = "2025-06-18"


class IdaMcpError(RuntimeError):
    """Raised when the IDA MCP server returns a JSON-RPC error."""


class IdaMcpClient:
    """Minimal JSON-RPC client over MCP streamable HTTP.

    Usage:
        with IdaMcpClient() as ida:
            ida.call("list_funcs", offset=0, count=50)
    """

    def __init__(self, url: str = DEFAULT_URL, timeout: float = 120.0):
        self.url = url
        self.timeout = timeout
        self.session_id: Optional[str] = None
        self._id = 0
        self._initialized = False

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "IdaMcpClient":
        self.initialize()
        return self

    def __exit__(self, *exc) -> None:
        # Stateless server; nothing to tear down. Session simply expires.
        return None

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _post(self, payload: dict, expect_response: bool = True) -> Optional[dict]:
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        req = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            raise IdaMcpError(f"HTTP {e.code} from IDA MCP: {body[:500]}") from e
        except urllib.error.URLError as e:
            raise IdaMcpError(
                f"Cannot reach IDA MCP at {self.url} ({e.reason}). "
                "Is IDA running with the MCP plugin?"
            ) from e

        # Capture/refresh the session id from the initialize response.
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            self.session_id = sid

        raw = resp.read().decode("utf-8", "replace")
        if not expect_response or not raw.strip():
            return None

        ctype = resp.headers.get("Content-Type", "")
        if "text/event-stream" in ctype:
            return self._parse_sse(raw)
        return json.loads(raw)

    @staticmethod
    def _parse_sse(raw: str) -> dict:
        """Extract the last JSON `data:` payload from an SSE stream."""
        last = None
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                last = line[len("data:"):].strip()
        if last is None:
            raise IdaMcpError("Empty SSE response from IDA MCP")
        return json.loads(last)

    def initialize(self) -> dict:
        if self._initialized:
            return {}
        resp = self._post({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "vuln-research-agent", "version": "0.1"},
            },
        })
        # Required post-initialize notification (no id, no response body).
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"},
                   expect_response=False)
        self._initialized = True
        return (resp or {}).get("result", {})

    # -- RPC ---------------------------------------------------------------
    def list_tools(self) -> list[dict]:
        if not self._initialized:
            self.initialize()
        resp = self._post({
            "jsonrpc": "2.0", "id": self._next_id(),
            "method": "tools/list", "params": {},
        })
        self._raise_on_error(resp)
        return resp["result"]["tools"]

    def call(self, tool: str, **arguments: Any) -> Any:
        """Call an IDA MCP tool by name. Returns parsed structured result."""
        if not self._initialized:
            self.initialize()
        resp = self._post({
            "jsonrpc": "2.0", "id": self._next_id(),
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        })
        self._raise_on_error(resp)
        return self._unwrap(resp["result"], tool)

    @staticmethod
    def _raise_on_error(resp: Optional[dict]) -> None:
        if resp and "error" in resp:
            err = resp["error"]
            raise IdaMcpError(f"{err.get('code')}: {err.get('message')}")

    @staticmethod
    def _unwrap(result: dict, tool: str) -> Any:
        """Prefer structuredContent; fall back to parsing the text content."""
        if isinstance(result, dict) and result.get("isError"):
            text = _first_text(result)
            raise IdaMcpError(f"Tool '{tool}' failed: {text}")
        if isinstance(result, dict) and "structuredContent" in result:
            sc = result["structuredContent"]
            # Some servers wrap the real payload under a single "result" key.
            if isinstance(sc, dict) and set(sc.keys()) == {"result"}:
                return sc["result"]
            return sc
        text = _first_text(result)
        if text is None:
            return result
        try:
            return json.loads(text)
        except (ValueError, TypeError):
            return text


def _first_text(result: Any) -> Optional[str]:
    if isinstance(result, dict):
        for item in result.get("content", []) or []:
            if isinstance(item, dict) and item.get("type") == "text":
                return item.get("text")
    return None
