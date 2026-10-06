"""The agent orchestrator (§8): understand -> plan each target -> hunt -> assess.

The spine is a sequence of SMALL LLM calls (see `steps.py`), not one mega-prompt:
  1. understand        — app-level roles / trust boundaries           (1 call)
  2. per controllable target: plan_target + input_model               (2 calls each)
  3. [heavy work: fuzz/triage runs in the vra-fuzz container]
  4. per finding: assess_finding                                      (1 call each)
  5. next_action        — what to do next                             (1 call)

Every step is independently guarded: if the API is unavailable or one call
fails, that step is skipped and the deterministic pipeline still runs. The
per-target input models are persisted so the container fuzzer can pick up the
model-designed seeds/dictionary without needing a key itself.
"""
from __future__ import annotations

import binascii

from ..kb import KB
from . import appmodel, strategy, steps
from . import llm as agent_llm


def plan_phase(kb: KB, apk_id: int, *, verbose: bool = True) -> dict:
    """Deterministic structure map + (if a key exists) decomposed LLM planning."""
    log = (lambda *a: print("[agent]", *a, flush=True)) if verbose else (lambda *a: None)
    structure = appmodel.build_structure(kb, apk_id)
    kb.set_app_model(apk_id, "structure", structure)

    if not agent_llm.available():
        return {"structure": structure, "strategy": None, "input_models": {}}

    try:
        lm = agent_llm.LLM()
    except agent_llm.LLMUnavailable as e:
        log(f"LLM unavailable ({e}); deterministic map only")
        return {"structure": structure, "strategy": None, "input_models": {}}

    understanding = _guard(log, "understand",
                           lambda: steps.understand(lm, structure)) or {}
    kb.set_app_model(apk_id, "understanding", understanding)

    targets, input_models = [], {}
    for t in structure.get("fuzz_targets", []):
        name = f"{t['java_class']}.{t['java_method']}"
        decomp = kb.get_app_model(apk_id, f"decomp:{t.get('native_symbol')}") or ""
        if isinstance(decomp, dict):
            decomp = decomp.get("text", "")
        plan = _guard(log, f"plan_target {name}",
                      lambda: steps.plan_target(lm, t, decomp))
        if plan:
            plan["target"] = name
            plan["native_symbol"] = t.get("native_symbol")
            targets.append(plan)
        im = _guard(log, f"input_model {name}",
                    lambda: steps.input_model(lm, t, decomp))
        if im and t.get("native_symbol"):
            input_models[t["native_symbol"]] = {
                "note": im["structure_note"],
                "seeds": [b.hex() for b in im["seeds"]],
                "dictionary": [b.hex() for b in im["dictionary"]],
            }

    research_plan = {"objective": understanding.get("summary", ""),
                     "targets": sorted(targets, key=lambda x: x.get("priority", 99))}
    kb.set_research_plan(apk_id, research_plan, lm.model)
    kb.set_app_model(apk_id, "input_models", input_models)
    log(f"planned {len(targets)} target(s); "
        f"{sum(len(v['seeds']) for v in input_models.values())} model seed(s)")
    return {"structure": structure,
            "strategy": {"app_understanding": understanding,
                         "research_plan": research_plan},
            "input_models": input_models}


def assess_findings(kb: KB, apk_id: int, *, verbose: bool = True) -> dict:
    """Assess each finding with its own small LLM call (not one big batch)."""
    log = (lambda *a: print("[agent]", *a, flush=True)) if verbose else (lambda *a: None)
    findings = kb.get_findings(apk_id)
    dynamic = [f for f in findings if f.get("detail", {}).get("kind") == "dynamic"]
    if not dynamic or not agent_llm.available():
        return {}
    try:
        lm = agent_llm.LLM()
    except agent_llm.LLMUnavailable:
        return {}
    triaged = []
    for f in dynamic:
        a = _guard(log, f"assess {f['bug_class']}",
                   lambda: steps.assess_finding(lm, f))
        if a:
            a["finding"] = f"{f['bug_class']} in {f['native_method']}"
            triaged.append(a)
    summary = f"{len(triaged)} finding(s) assessed by the model."
    nxt = _guard(log, "next_action", lambda: steps.next_action(
        lm, {"n_findings": len(dynamic),
             "findings": [t["finding"] for t in triaged]})) or {}
    return {"summary": summary, "triaged": triaged,
            "next_actions": [f"{nxt.get('action','')}: {nxt.get('why','')}"]
            if nxt else []}


def input_model_seeds(kb: KB, apk_id: int, native_symbol: str) -> dict:
    """Container-side accessor: model-designed seeds/dict for a symbol (bytes)."""
    models = kb.get_app_model(apk_id, "input_models") or {}
    m = models.get(native_symbol)
    if not m:
        return {"seeds": [], "dictionary": []}
    return {"seeds": _unhex(m.get("seeds", [])),
            "dictionary": _unhex(m.get("dictionary", [])),
            "note": m.get("note", "")}


# -- rendering --------------------------------------------------------------
def render(plan: dict, assessment: dict) -> str:
    L = []
    if plan.get("strategy"):
        L.append(strategy.render_plan(plan["strategy"]))
    else:
        L.append("(no API key — skipped LLM understanding/strategy; "
                 "deterministic structure map used)")
        L.append(appmodel.render(plan["structure"]))
    if assessment:
        L.append("\n=== LLM FINDINGS ASSESSMENT ===")
        L.append("  " + assessment.get("summary", ""))
        for t in assessment.get("triaged", []):
            L.append(f"  [{t['severity']}] {t['finding']}: {t['root_cause_guess']}")
            L.append(f"        impact: {t['impact_note']}")
        for a in assessment.get("next_actions", []):
            L.append(f"  next: {a}")
    return "\n".join(L)


# -- internals --------------------------------------------------------------
def _guard(log, what: str, fn):
    """Run one LLM step; on any LLM failure, log and return None (degrade)."""
    try:
        return fn()
    except agent_llm.LLMUnavailable as e:
        log(f"step '{what}' skipped: {e}")
        return None
    except Exception as e:                      # schema / parsing / unexpected
        log(f"step '{what}' error: {e}")
        return None


def _unhex(items) -> list:
    out = []
    for h in items or []:
        try:
            out.append(binascii.unhexlify(h))
        except Exception:
            continue
    return out
