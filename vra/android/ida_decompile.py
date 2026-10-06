"""IDA Hex-Rays decompilation enrichment (host-side).

IDA Pro runs on the host with the MCP server; Docker only runs the fuzzer. To
use real decompilation you open the target `.so` in IDA (one IDB per lib) and
this module queries IDA MCP host-side to:
  - enrich findings with the decompilation of the crashing function (root cause),
  - provide the decompilation to the LLM static-audit / strategy.

All best-effort: if IDA isn't running or the loaded IDB isn't this `.so`, it
skips cleanly — the harness still works without IDA (capstone fallback).
"""
from __future__ import annotations

import hashlib
import os
from typing import Optional

from ..ida_client import IdaMcpClient, IdaMcpError
from ..surface import decompile_full
from .. import config


def _sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def get_client(url: str = config.IDA_MCP_URL) -> Optional[IdaMcpClient]:
    try:
        ida = IdaMcpClient(url)
        ida.call("server_health")
        return ida
    except IdaMcpError:
        return None
    except Exception:
        return None


def loaded_sha(ida: IdaMcpClient) -> Optional[str]:
    try:
        sv = ida.call("survey_binary", detail_level="brief")
        return (sv.get("metadata") or {}).get("sha256")
    except Exception:
        return None


def resolve_symbol(ida: IdaMcpClient, name: str) -> Optional[str]:
    """Symbol name -> function address string, via lookup_funcs."""
    for query in (name, name.lstrip("_")):
        try:
            r = ida.call("lookup_funcs", queries=[query])
            items = r if isinstance(r, list) else (r.get("data", []) if isinstance(r, dict) else [])
            for it in items:
                if not isinstance(it, dict):
                    continue
                fn = it.get("fn") or it            # lookup_funcs nests under "fn"
                if isinstance(fn, dict) and fn.get("addr"):
                    return fn["addr"]
        except Exception:
            continue
    return None


def decompile_symbol(ida: IdaMcpClient, name: str) -> Optional[str]:
    addr = resolve_symbol(ida, name)
    if not addr:
        return None
    try:
        code = decompile_full(ida, addr, cap_lines=400)
        return code or None
    except Exception:
        return None


def enrich_findings(kb, apk_id: int, package: str, targets_dir: str,
                    url: str = config.IDA_MCP_URL, log=print) -> str:
    """For findings whose .so is the one currently open in IDA, attach the
    Hex-Rays decompilation of the crashing function."""
    ida = get_client(url)
    if ida is None:
        return "IDA MCP not reachable (open the .so in IDA to get Hex-Rays root cause)."
    lsha = loaded_sha(ida)
    findings = kb.get_findings(apk_id)
    # distinct (native_method, native_symbol, native lib file)
    done, matched = 0, 0
    libdir = os.path.join(targets_dir, package, "libs")
    seen = set()
    for f in findings:
        nm = f["native_method"]
        sym = f["detail"].get("native_symbol")
        if not sym or nm in seen:
            continue
        seen.add(nm)
        # does IDA currently have THIS lib open? match by sha of any abi's lib
        lib_match = False
        if lsha and os.path.isdir(libdir):
            for abi in os.listdir(libdir):
                for fn in os.listdir(os.path.join(libdir, abi)):
                    if _sha(os.path.join(libdir, abi, fn)) == lsha:
                        lib_match = True
        if not lib_match:
            continue
        matched += 1
        code = decompile_symbol(ida, sym)
        if code:
            done += kb.attach_decompile(apk_id, nm, code)
            log(f"[ida] decompiled {sym} ({len(code)} chars) -> root cause attached")
    if matched == 0:
        return (f"IDA is running but the loaded IDB (sha {str(lsha)[:12]}) is not this "
                f"APK's .so — open libs/<abi>/*.so for {package} to attach decompilation.")
    return f"IDA enrichment: decompiled {done} finding function(s)."
