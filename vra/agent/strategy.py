"""Strategy step (§8): LLM turns the structure map into understanding + plan."""
from __future__ import annotations

import json

from .llm import LLM
from .prompts import SYSTEM_STRATEGIST, STRATEGY_SCHEMA


def strategize(llm: LLM, structure: dict) -> dict:
    """One structured call -> {app_understanding, research_plan}."""
    user = (
        "Here is the factual structure map of the app. Produce the "
        "app_understanding and a prioritized research_plan per the schema.\n\n"
        "```json\n" + json.dumps(structure, indent=2) + "\n```"
    )
    return llm.structured(SYSTEM_STRATEGIST, user, STRATEGY_SCHEMA,
                          effort="high", max_tokens=16000)


def render_plan(result: dict) -> str:
    u = result.get("app_understanding", {})
    p = result.get("research_plan", {})
    L = ["=== APP UNDERSTANDING ===", "  " + u.get("summary", ""), "",
         "  Architecture: " + u.get("architecture", "")]
    if u.get("trust_boundaries"):
        L.append("  Trust boundaries:")
        L += [f"    - {t}" for t in u["trust_boundaries"]]
    if u.get("library_roles"):
        L.append("  Library roles:")
        for r in u["library_roles"]:
            L.append(f"    - {r['lib']}: {r['role']}  "
                     f"(likely: {', '.join(r.get('likely_bug_classes', []))})")
    if u.get("notable_risks"):
        L.append("  Notable risks:")
        L += [f"    - {r}" for r in u["notable_risks"]]
    L += ["", "=== RESEARCH PLAN ===", "  Objective: " + p.get("objective", "")]
    for t in sorted(p.get("targets", []), key=lambda x: x.get("priority", 99)):
        L.append(f"  [P{t.get('priority')}] {t.get('target')}  ({t.get('technique')})")
        L.append(f"       hypothesis: {t.get('hypothesis')}")
        L.append(f"       bug classes: {', '.join(t.get('bug_classes', []))}")
        L.append(f"       input model: {t.get('input_model')}")
    if p.get("sequence"):
        L.append("  Sequence:")
        L += [f"    {i+1}. {s}" for i, s in enumerate(p["sequence"])]
    L.append("  Stop: " + p.get("stop_criteria", ""))
    return "\n".join(L)
