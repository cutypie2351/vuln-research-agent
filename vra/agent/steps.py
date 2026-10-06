"""The LLM loop, decomposed into small single-purpose steps (§8).

Each function is ONE structured call with ONE narrow schema, so the model never
has to carry every part of the job in a single response (which is where a big
monolithic prompt silently drops fields). The orchestrator in `loop.py` strings
these together and persists each result; any individual step may fail
(LLMUnavailable) without sinking the run.

Steps:
  understand(structure)                      -> app_understanding
  plan_target(target, decomp)                -> one research step for a target
  input_model(target, decomp)                -> seeds[] + dictionary[] (hex) + notes
  audit(func_name, decomp, args)             -> bug-class hypotheses  (static_audit)
  assess_finding(finding)                    -> severity + root cause + impact
  next_action(state)                         -> chosen next action + why
"""
from __future__ import annotations

import binascii
import json
from typing import Optional

from .llm import LLM
from . import prompts
from .static_audit import audit as _audit_call

# -- schemas ----------------------------------------------------------------
_UNDERSTAND_SCHEMA = prompts.STRATEGY_SCHEMA["properties"]["app_understanding"]

_PLAN_TARGET_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "hypothesis": {"type": "string"},
        "bug_classes": {"type": "array", "items": {"type": "string"}},
        "technique": {"type": "string",
                      "enum": ["smart-fuzz", "static-audit", "concolic", "combo"]},
        "input_model": {"type": "string"},
        "rationale": {"type": "string"},
        "priority": {"type": "integer"},
    },
    "required": ["hypothesis", "bug_classes", "technique", "input_model",
                 "rationale", "priority"],
}

_INPUT_MODEL_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "structure_note": {"type": "string"},
        "seeds_hex": {"type": "array", "items": {"type": "string"}},
        "dictionary_hex": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["structure_note", "seeds_hex", "dictionary_hex"],
}

_ASSESS_ONE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "severity": {"type": "string"},
        "root_cause_guess": {"type": "string"},
        "impact_note": {"type": "string"},
    },
    "required": ["severity", "root_cause_guess", "impact_note"],
}

_NEXT_ACTION_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "action": {"type": "string",
                   "enum": ["refuzz-more-budget", "concolic", "new-input-model",
                            "audit-decompile", "move-to-next-target", "stop"]},
        "target": {"type": "string"},
        "why": {"type": "string"},
    },
    "required": ["action", "why"],
}


# -- steps ------------------------------------------------------------------
def understand(lm: LLM, structure: dict) -> dict:
    user = ("Structure map of the app:\n```json\n"
            + json.dumps(_trim_structure(structure), indent=2) + "\n```")
    return lm.structured(prompts.SYS_UNDERSTAND, user, _UNDERSTAND_SCHEMA,
                         max_tokens=4000)


def plan_target(lm: LLM, target: dict, decomp: str = "") -> dict:
    user = _target_brief(target)
    if decomp:
        user += f"\n\nDecompilation:\n```\n{decomp[:8000]}\n```"
    return lm.structured(prompts.SYS_PLAN_TARGET, user, _PLAN_TARGET_SCHEMA,
                         max_tokens=2000)


def input_model(lm: LLM, target: dict, decomp: str = "") -> dict:
    """Returns {structure_note, seeds: [bytes], dictionary: [bytes]} — hex decoded."""
    user = _target_brief(target)
    if decomp:
        user += f"\n\nDecompilation:\n```\n{decomp[:8000]}\n```"
    raw = lm.structured(prompts.SYS_INPUT_MODEL, user, _INPUT_MODEL_SCHEMA,
                        max_tokens=2000)
    return {
        "structure_note": raw.get("structure_note", ""),
        "seeds": _decode_hexes(raw.get("seeds_hex", [])),
        "dictionary": _decode_hexes(raw.get("dictionary_hex", [])),
    }


def audit(lm: LLM, func_name: str, decomp: str, arg_info: str = "") -> dict:
    return _audit_call(lm, func_name, decomp, arg_info)


def assess_finding(lm: LLM, finding: dict) -> dict:
    compact = {"bug_class": finding.get("bug_class"),
               "severity": finding.get("severity"),
               "native_method": finding.get("native_method"),
               "detail": {k: finding.get("detail", {}).get(k) for k in
                          ("access", "fault_pc", "faulting_insn", "min_input_len",
                           "repro_rate", "backtrace", "controlled_args", "notes")}}
    user = ("Assess ONE native memory-corruption finding from an authorized "
            "defensive run. Give severity, a non-exploit root-cause guess, and an "
            "impact note (read vs write, reach).\n\n```json\n"
            + json.dumps(compact, indent=2) + "\n```")
    return lm.structured(prompts.SYSTEM_STRATEGIST + "\n\nMODE: triage one finding.",
                         user, _ASSESS_ONE_SCHEMA, max_tokens=1500)


def next_action(lm: LLM, state: dict) -> dict:
    user = ("Research state so far:\n```json\n" + json.dumps(state, indent=2)
            + "\n```\nChoose the single most valuable next action.")
    return lm.structured(prompts.SYS_NEXT_ACTION, user, _NEXT_ACTION_SCHEMA,
                         max_tokens=800)


# -- helpers ----------------------------------------------------------------
def _target_brief(t: dict) -> str:
    return ("Native target:\n"
            f"  java        : {t.get('java_class')}.{t.get('java_method')}\n"
            f"  jni signature: {t.get('jni_signature') or t.get('arg_types')}\n"
            f"  symbol      : {t.get('native_symbol')}\n"
            f"  controllable args: {t.get('controlled_args')}\n"
            f"  sources     : {t.get('sources')}")


def _trim_structure(structure: dict) -> dict:
    """Drop verbose per-method verdicts; keep what the model needs to reason."""
    keep = {k: structure.get(k) for k in
            ("package", "version", "min_sdk", "abis", "entry_points",
             "native_libs", "dataflow", "counts")}
    keep["natives"] = [{k: n.get(k) for k in
                        ("java_class", "java_method", "arg_types", "native_symbol",
                         "native_lib", "controllable", "reachable",
                         "controlled_args", "sources")}
                       for n in structure.get("natives", [])]
    return keep


def _decode_hexes(items) -> list:
    out = []
    for h in items or []:
        try:
            out.append(binascii.unhexlify(_clean_hex(h)))
        except Exception:
            continue
    return out


def _clean_hex(h: str) -> str:
    h = (h or "").strip().lower().replace("0x", "").replace(" ", "").replace("_", "")
    return h if len(h) % 2 == 0 else "0" + h
