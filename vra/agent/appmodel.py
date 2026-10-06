"""Deterministic app-structure map (§8 understanding, factual half).

Aggregates the KB (apk, entry points, native libs, JNI methods + flow) into one
holistic model of the app: how external input reaches native code, what each
lib exposes, and a ranked target list. This is the factual substrate the LLM
reasons over to produce understanding + a research strategy; building it here
(not in the prompt) keeps the model focused and the facts verifiable.
"""
from __future__ import annotations

from typing import Optional

from ..kb import KB


def build_structure(kb: KB, apk_id: int) -> dict:
    s = kb.summarize_apk(apk_id)
    natives = []
    for m in s["native_methods"]:
        fl = m.get("flow", {})
        natives.append({
            "java_class": m["java_class"], "java_method": m["java_method"],
            "arg_types": m.get("arg_types", []),
            "jni_signature": m.get("jni_signature"),
            "native_symbol": m.get("native_symbol"),
            "native_addr": m.get("native_addr"),
            "native_lib": m.get("native_lib"),
            "registration": m.get("registration"),
            "controllable": fl.get("controllable", False),
            "reachable": fl.get("reachable", False),
            "controlled_args": fl.get("controlled_args", []),
            "sources": fl.get("sources", []),
            "score": _score(m, fl),
        })
    natives.sort(key=lambda n: -n["score"])

    # data-flow edges: attacker source -> native method (controllable only)
    dataflow = [{"from": src, "to": f'{n["java_class"]}.{n["java_method"]}',
                 "arg": n["controlled_args"]}
                for n in natives if n["controllable"] for src in n["sources"]]

    return {
        "package": s["package"], "version": s["version"],
        "min_sdk": s["min_sdk"], "target_sdk": s["target_sdk"],
        "abis": s["abis"], "abi_plan": s["abi_plan"],
        "launchable_activity": s["launchable_activity"],
        "entry_points": s["exported_entry_points"],
        "native_libs": s["native_libs"],
        "natives": natives,
        "dataflow": dataflow,
        "fuzz_targets": [n for n in natives if n["controllable"]],
        "counts": s["counts"],
    }


def _score(m: dict, fl: dict) -> int:
    """Deterministic target prior: controllability dominates, then reachability
    and a controllable-arg signal. The LLM refines this with lib-role reasoning."""
    score = 0
    if fl.get("controllable"):
        score += 100
    if fl.get("reachable"):
        score += 20
    # byte[]/String args are the richest fuzz surface
    for t in m.get("arg_types", []):
        if "byte[]" in t or t == "String":
            score += 10
    if m.get("native_addr"):
        score += 5
    return score


def render(structure: dict) -> str:
    L = []
    L.append(f"APP: {structure['package']} v{structure['version']} "
             f"(minSdk={structure['min_sdk']}, abis={structure['abis']})")
    L.append(f"  launch: {structure['launchable_activity']}")
    L.append("EXPORTED ENTRY POINTS (attacker-reachable):")
    for e in structure["entry_points"]:
        L.append(f"  [{e['component_type']}] {e['name']}")
    L.append("NATIVE LIBS:")
    for l in structure["native_libs"]:
        L.append(f"  {l['abi']:12s} {l['name']}")
    L.append("ATTACK-SURFACE DATA FLOW (source -> native):")
    if structure["dataflow"]:
        for d in structure["dataflow"]:
            L.append(f"  {d['from']}  ->  {d['to']} (arg {d['arg']})")
    else:
        L.append("  (no controllable flows found)")
    L.append("RANKED NATIVE TARGETS:")
    for n in structure["natives"]:
        tag = ("CONTROLLABLE" if n["controllable"] else
               "reachable" if n["reachable"] else "unreached")
        args = ",".join(n["arg_types"])
        L.append(f"  [{n['score']:3d}] {n['java_class']}.{n['java_method']}({args}) "
                 f"-> {n['native_symbol']}  [{tag}]")
    return "\n".join(L)
