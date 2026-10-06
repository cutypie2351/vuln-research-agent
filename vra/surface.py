"""Phase 2 — Attack-surface mapping via IDA MCP (§3).

This is the standalone-harness replacement for the Ghidra headless script.
Instead of a one-shot Jython dump, we query a live IDA instance:

  1. survey        -> file metadata (sha256/arch/imagebase/top strings)
  2. imports       -> which dangerous sinks / input sources are present
  3. xrefs_to(sink)-> call sites + containing functions (the surfaces)
  4. decompile     -> caller code the model will later read
  5. callees       -> call-graph edges + input-source reachability

The tool emits deterministic facts into the KB (§2 principle: tools return
structured data; the model reasons over the summary). Scoring here is a stable
prior only — the LLM refines ranking + grammar in a later step.
"""
from __future__ import annotations

from typing import Any, Optional

from . import config
from .ida_client import IdaMcpClient
from .kb import KB


def _as_list(resp: Any) -> list:
    """Normalize {data:[...]} or [...] responses to a plain list."""
    if isinstance(resp, dict):
        return resp.get("data", [])
    return resp if isinstance(resp, list) else []


def survey(ida: IdaMcpClient) -> dict:
    return ida.call("survey_binary", detail_level="brief")


def fetch_imports(ida: IdaMcpClient, page: int = 500) -> list[dict]:
    out: list[dict] = []
    offset = 0
    while True:
        batch = _as_list(ida.call("imports", offset=offset, count=page))
        if not batch:
            break
        out.extend(batch)
        if len(batch) < page:
            break
        offset += len(batch)
    return out


def fetch_functions(ida: IdaMcpClient, cap: int = 20000) -> list[dict]:
    out: list[dict] = []
    offset = 0
    while len(out) < cap:
        resp = ida.call("list_funcs", queries=[{"offset": offset, "count": 500}])
        # list_funcs returns a list of per-query results.
        block = resp[0] if isinstance(resp, list) and resp else resp
        data = _as_list(block)
        if not data:
            break
        out.extend(data)
        nxt = block.get("next_offset") if isinstance(block, dict) else None
        if nxt is None or len(data) < 500:
            break
        offset = nxt
    return out


def decompile_full(ida: IdaMcpClient, addr: str, cap_lines: int = 1500) -> str:
    """Page through decompilation up to cap_lines (model-readable context)."""
    chunks: list[str] = []
    offset = 0
    got = 0
    while got < cap_lines:
        d = ida.call("decompile", addr=addr, max_lines=min(500, cap_lines - got),
                     offset=offset)
        if not isinstance(d, dict):
            break
        code = d.get("code", "")
        if code:
            chunks.append(code)
        got += d.get("line_count", 0)
        if not d.get("truncated"):
            break
        cursor = d.get("cursor") or {}
        nxt = cursor.get("next")
        if nxt is None or nxt == offset:
            break
        offset = nxt
    return "\n".join(chunks)


def _collect_callees(ida: IdaMcpClient, addrs: list[str],
                     chunk: int = 50) -> dict[str, list[dict]]:
    """addr -> list of callee dicts, batched to bound round-trips."""
    result: dict[str, list[dict]] = {}
    for i in range(0, len(addrs), chunk):
        part = addrs[i:i + chunk]
        resp = ida.call("callees", addrs=part, limit=256)
        for entry in _as_list(resp) if isinstance(resp, dict) else resp:
            if isinstance(entry, dict) and "addr" in entry:
                result[entry["addr"]] = entry.get("callees", []) or []
    return result


def map_surfaces(ida: IdaMcpClient, kb: KB, target_id: int,
                 *, decompile_cap: int = 1500, verbose: bool = True) -> dict:
    """Run Phase 2 against the live IDA session, writing facts to the KB."""
    run_id = kb.start_run(target_id, "surface")
    log = (lambda *a: print("[surface]", *a)) if verbose else (lambda *a: None)
    try:
        # 1. imports + functions -------------------------------------------
        imps = fetch_imports(ida)
        kb.add_imports(target_id, imps)
        funcs = fetch_functions(ida)
        kb.add_functions(target_id, funcs)
        log(f"imports={len(imps)} functions={len(funcs)}")

        # 2. which sinks / sources are actually imported --------------------
        present_sinks = [i for i in imps
                         if config.canonical(i.get("imported_name", "")) in config.SINKS]
        present_sources = [i for i in imps
                           if config.canonical(i.get("imported_name", "")) in config.INPUT_SOURCES]
        log(f"sinks={[i['imported_name'] for i in present_sinks]}")
        log(f"sources={[i['imported_name'] for i in present_sources]}")

        # 3. xrefs to each sink -> surfaces --------------------------------
        surfaces_raw: list[dict] = []
        surface_func_addrs: set[str] = set()
        for imp in present_sinks:
            sym = imp["imported_name"]
            canon = config.canonical(sym)
            cat = config.SINKS[canon]
            xr = ida.call("xrefs_to", addrs=sym, limit=500)
            for group in (xr if isinstance(xr, list) else [xr]):
                for ref in group.get("xrefs", []):
                    fn = ref.get("fn")
                    if not fn:
                        continue  # data ref, no containing function
                    surfaces_raw.append({
                        "sink": sym, "sink_canonical": canon, "sink_category": cat,
                        "func_name": fn.get("name"), "func_addr": fn.get("addr"),
                        "call_addr": ref.get("addr"),
                    })
                    surface_func_addrs.add(fn.get("addr"))
        log(f"raw surfaces={len(surfaces_raw)} in {len(surface_func_addrs)} funcs")

        # 4. input-source reachability (callees of surface funcs) ----------
        callee_map = _collect_callees(ida, sorted(surface_func_addrs))
        reaches_source: dict[str, bool] = {}
        for faddr, callees in callee_map.items():
            names = {config.canonical(c.get("name", "")) for c in callees}
            reaches_source[faddr] = bool(names & config.INPUT_SOURCES)

        # 5. decompile each surface function once (cache) ------------------
        decomp_cache: dict[str, str] = {}
        for faddr in sorted(surface_func_addrs):
            decomp_cache[faddr] = decompile_full(ida, faddr, decompile_cap)

        # 6. score + persist surfaces --------------------------------------
        for s in surfaces_raw:
            faddr = s["func_addr"]
            code = decomp_cache.get(faddr, "")
            src_in_code = any(src in code for src in config.INPUT_SOURCES)
            reads_src = reaches_source.get(faddr, False) or src_in_code
            score = config.CATEGORY_BASE_SCORE.get(s["sink_category"], 40)
            if reads_src:
                score = min(100, score + config.INPUT_REACH_BONUS)
            kb.add_surface(target_id, reads_input_source=int(reads_src),
                           base_score=score, model_score=None,
                           decompiled=code, **s)

        # 7. call-graph edges (all functions) ------------------------------
        all_addrs = [f.get("addr") for f in funcs if f.get("addr")]
        full_callees = _collect_callees(ida, all_addrs)
        name_by_addr = {f.get("addr"): f.get("name") for f in funcs}
        edges = []
        for caller_addr, callees in full_callees.items():
            for c in callees:
                edges.append({
                    "caller_addr": caller_addr,
                    "caller_name": name_by_addr.get(caller_addr),
                    "callee_addr": c.get("addr"),
                    "callee_name": c.get("name"),
                })
        n_edges = kb.add_call_edges(target_id, edges)
        log(f"call_edges={n_edges}")

        # 8. top strings (for dict/seed in Phase 3) ------------------------
        sv = survey(ida)
        top_strings = sv.get("strings") or sv.get("top_strings") or []
        str_items = [{"addr": s.get("addr") if isinstance(s, dict) else None,
                      "value": s.get("value") if isinstance(s, dict) else str(s)}
                     for s in top_strings]
        if str_items:
            kb.add_strings(target_id, str_items)

        summary = kb.summarize(target_id)
        kb.end_run(run_id, "ok", {"surfaces": summary["counts"]["surfaces"]})
        return summary
    except Exception as e:
        kb.end_run(run_id, "error", {"error": str(e)})
        raise
