"""End-to-end deterministic hunt: controllable natives -> fuzz -> triage -> findings.

Two halves (so the host can drive host-only RE and the container can fuzz):
  - `fuzzrun()` runs INSIDE the vra-fuzz container (qiling/capstone/angr): reads
    the KB, picks the controllable native targets (from the app model), builds a
    FuzzHarness per target, fuzzes with seeds + CmpLog, optionally hands hard
    branches to angr, triages every unique crash, and writes findings to the KB.
  - `render_report()` prints the ranked findings (§6/§12).

Needs no API key — the LLM brain plugs in separately.
"""
from __future__ import annotations

import os
import re
import struct

from .kb import KB
from .agent import appmodel


def _so_for(targets_dir: str, package: str, native_lib, abi: str = "x86_64"):
    d = os.path.join(targets_dir, package, "libs", abi)
    if not os.path.isdir(d):
        return None
    if native_lib:
        cand = os.path.join(d, f"lib{native_lib}.so")
        if os.path.isfile(cand):
            return cand
    sos = [f for f in os.listdir(d) if f.endswith(".so")]
    return os.path.join(d, sos[0]) if len(sos) == 1 else None


def fuzzrun(targets_dir: str, rootfs: str, package: str, *, budget_s: float = 30.0,
            use_angr: bool = False, fuzz_all: bool = False, verbose: bool = True) -> dict:
    from .fuzz.engine import FuzzHarness, fuzz
    from .fuzz.seeds import seeds as mk_seeds, dictionary as mk_dict
    from .fuzz import inputspec, logic
    from .triage.triage import Triage
    from .agent import loop as agent_loop

    log = (lambda *a: print("[hunt]", *a, flush=True)) if verbose else (lambda *a: None)
    kb = KB(os.path.join(targets_dir, package, "kb.sqlite"))
    apk = kb.get_apk(package=package) or kb.get_apk()
    if not apk:
        kb.close()
        raise RuntimeError(f"no APK in KB for {package}")
    aid = apk["id"]
    structure = appmodel.build_structure(kb, aid)
    kb.clear_findings(aid)
    if fuzz_all:
        # also drive natives that are reachable but whose controllability taint
        # couldn't be proven (e.g. data laundered through ByteBuffer/containers)
        targets = [n for n in structure["natives"]
                   if n.get("controllable") or n.get("reachable")]
    else:
        targets = structure["fuzz_targets"]
    log(f"{package}: {len(targets)} native target(s) "
        f"({'all reachable' if fuzz_all else 'controllable'})")

    summary = {"package": package, "targets": [], "n_findings": 0}
    for t in targets:
        name = f"{t['java_class']}.{t['java_method']}"
        if not t.get("native_addr"):
            log(f"  SKIP {name}: unresolved native address"); continue
        so = _so_for(targets_dir, package, t.get("native_lib"), "x86_64")
        if not so:
            log(f"  SKIP {name}: no x86_64 .so"); continue
        try:
            addr = int(str(t["native_addr"]), 16)
            spec = inputspec.build(t.get("arg_types", []), t.get("controlled_args", []),
                                   fuzz_all=fuzz_all)
            h = FuzzHarness(so, rootfs, addr, spec=spec)
            h.win_blocks = logic.win_blocks(h, addr)   # logic-flip oracle
        except Exception as e:
            log(f"  SKIP {name}: harness load failed ({e})"); continue
        log(f"       args {spec.summary()}  win-blocks={len(h.win_blocks)}")
        # --- static vuln-research pass (reason before fuzzing) ---
        from .research import static_scan
        sr = static_scan(so, t["native_symbol"])
        for hyp in sr["hypotheses"]:
            kb.add_finding(aid, name, "hypothesis: " + hyp["bug_class"], hyp["severity"],
                           "static:" + hyp["sink"],
                           f"static: {name} calls {hyp['sink']} (candidate {hyp['bug_class']})",
                           {"kind": "static", "sink": hyp["sink"], "offset": hyp["offset"],
                            "native_symbol": t["native_symbol"], "java_method": name,
                            "controlled_args": t["controlled_args"]})
        log(f"  RESEARCH {name}: {len(sr['hypotheses'])} static hypotheses "
            f"({', '.join(h['sink'] for h in sr['hypotheses']) or 'none'}); "
            f"+{len(sr['dict_consts'])} dict consts")

        sd = mk_seeds(so)
        dic = mk_dict(so) + sr["dict_consts"]   # smart dict: static constants
        # fold in the model-designed input model (seeds + dictionary), if any
        im = agent_loop.input_model_seeds(kb, aid, t["native_symbol"])
        if im.get("seeds") or im.get("dictionary"):
            sd = im["seeds"] + sd
            dic = im["dictionary"] + dic
            log(f"       input-model: +{len(im['seeds'])} seed(s) "
                f"+{len(im['dictionary'])} dict  ({im.get('note','')[:60]})")
        log(f"  FUZZ {name}  sym={t['native_symbol']} ({budget_s:.0f}s) ...")
        r = fuzz(h, sd, budget_s=budget_s, dictionary=dic)
        log(f"       execs={r.execs} cov={r.coverage} crashes={len(r.crashes)} "
            f"logic-flips={len(r.wins)}")
        for w in r.wins:
            kb.add_finding(aid, name, "logic-flaw (control-flow divergence)", "medium",
                           f"logic:{name}",
                           f"attacker input reaches a privileged/success path in {name}",
                           {"kind": "logic", "native_symbol": t["native_symbol"],
                            "java_method": name, "min_input_hex": w[:64].hex(),
                            "controlled_args": t["controlled_args"],
                            "note": "input drives a security decision to the positive "
                                    "side (candidate auth/logic bypass; not exploited)"})
        if use_angr and not r.crashes:
            from .fuzz.plateau import angr_break
            log("       plateau: angr concolic hand-off ...")
            extra = angr_break(h, so, addr, timeout=min(120.0, budget_s * 3))
            if extra:
                log(f"       angr produced {len(extra)} gate-passing seed(s); re-fuzzing")
                r2 = fuzz(h, extra + sd, budget_s=budget_s, dictionary=dic)
                keys = {c.key for c in r.crashes}
                for c in r2.crashes:
                    if c.key not in keys:
                        r.crashes.append(c); keys.add(c.key)
                r.coverage = len(h.cov_global)
                log(f"       after angr: cov={r.coverage} crashes={len(r.crashes)}")
        tri = Triage(h, so)
        n_find = 0
        for c in r.crashes:
            fnd = tri.triage(c.input)
            if not fnd:
                continue
            kb.add_finding(aid, name, fnd.bug_class, fnd.severity, fnd.bug_key,
                           f"{fnd.bug_class} in {name} ({t['native_symbol']})",
                           {**_finding_dict(fnd), "kind": "dynamic",
                            "native_symbol": t["native_symbol"],
                            "java_method": name, "controlled_args": t["controlled_args"]})
            n_find += 1
            log(f"       FINDING [{fnd.severity}] {fnd.bug_class}  "
                f"min={fnd.min_input_len}B repro={fnd.repro_rate}")
        summary["targets"].append({"target": name, "execs": r.execs,
                                   "coverage": r.coverage, "findings": n_find})
        summary["n_findings"] += n_find

    summary["findings"] = kb.get_findings(aid)
    kb.close()
    return summary


def report_from_kb(kb, apk_id: int) -> str:
    """Render a report from persisted findings (host-side, after IDA enrichment)."""
    apk = next((r for r in [kb.get_apk()] if r), None)
    findings = kb.get_findings(apk_id)
    summary = {"package": apk["package"] if apk else "?", "targets": [],
               "n_findings": sum(1 for f in findings
                                 if f["detail"].get("kind") == "dynamic"),
               "findings": findings}
    return render_report(summary)


def _finding_dict(fnd) -> dict:
    from dataclasses import asdict
    return asdict(fnd)


def render_report(summary: dict) -> str:
    L = [f"\n{'='*70}", f"HUNT REPORT — {summary['package']}", "=" * 70,
         f"controllable targets fuzzed: {len(summary['targets'])}   "
         f"unique findings: {summary['n_findings']}"]
    for t in summary["targets"]:
        L.append(f"  - {t['target']}: execs={t['execs']} cov={t['coverage']} "
                 f"findings={t['findings']}")
    dynamic = [f for f in summary["findings"] if f["detail"].get("kind") == "dynamic"]
    static = [f for f in summary["findings"] if f["detail"].get("kind") == "static"]
    logic = [f for f in summary["findings"] if f["detail"].get("kind") == "logic"]

    L.append("\n--- STATIC VULN-RESEARCH (hypotheses from code analysis) ---")
    if not static:
        L.append("  (none)")
    for f in static:
        d = f["detail"]
        L.append(f"  [{f['severity']}] {f['native_method']} calls {d.get('sink')} "
                 f"@ {d.get('offset')} — {f['bug_class'].replace('hypothesis: ','')}")

    L.append("\n--- CONFIRMED FINDINGS (fuzzing + triage) ---")
    if not dynamic:
        L.append("  No memory-safety crashes (oracle stayed quiet — "
                 "no false positives on safe code).")
    for f in dynamic:
        d = f["detail"]
        L.append(f"[{f['severity'].upper()}] {f['bug_class']} — {f['native_method']}")
        L.append(f"    symbol     : {d.get('native_symbol')}")
        L.append(f"    access     : {d.get('access')} @ {hex(d.get('fault_addr', 0))}")
        L.append(f"    fault insn : {hex(d.get('fault_pc', 0))}  {d.get('faulting_insn','')}")
        L.append(f"    reproducer : {d.get('min_input_len')} bytes  "
                 f"({d.get('repro_rate')})  hex={d.get('min_input_hex','')[:64]}...")
        if d.get("decompiled"):
            L.append(f"    IDA decompile (root cause):\n"
                     + "\n".join("        " + ln for ln in
                                 d["decompiled"].splitlines()[:20]))
        if d.get("backtrace"):
            L.append(f"    backtrace  : {' <- '.join(d['backtrace'])}")

    L.append("\n--- LOGIC-FLAW CANDIDATES (control-flow divergence) ---")
    if not logic:
        L.append("  (none)")
    for f in logic:
        d = f["detail"]
        L.append(f"  [{f['severity']}] {f['native_method']} — {f['summary']}")
        L.append(f"      input hex={d.get('min_input_hex','')}  ({d.get('note','')})")
    return "\n".join(L)
