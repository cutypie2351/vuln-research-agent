"""Static vuln-research mode (§6 'research, not just fuzz').

The LLM audits the decompilation/disassembly of a controllable native for
memory-corruption bug classes (integer overflow before alloc, missing length
check before memcpy, UAF, off-by-one), emitting hypotheses + a confirmation
plan. Complements fuzzing: finds bugs by reasoning, then hands a target/seed to
the dynamic side. Key-gated (needs ANTHROPIC_API_KEY)."""
from __future__ import annotations

from .llm import LLM
from .prompts import SYSTEM_STRATEGIST

_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "hypotheses": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "bug_class": {"type": "string"},
                "severity": {"type": "string"},
                "line_or_offset": {"type": "string"},
                "reason": {"type": "string"},
                "confirm": {"type": "string"},
            },
            "required": ["bug_class", "severity", "line_or_offset", "reason", "confirm"],
        }},
        "verdict": {"type": "string"},
    },
    "required": ["hypotheses", "verdict"],
}

_SYS = (SYSTEM_STRATEGIST + "\n\nMODE: static audit. You are given the "
        "disassembly/decompilation of ONE native function that receives "
        "attacker-controlled data. Find memory-corruption bugs by reading it. "
        "For each, give the bug_class, where (line/offset), the code reason, and "
        "how to confirm it dynamically. Output ONLY the JSON object.")


def audit(llm: LLM, func_name: str, disasm_or_decomp: str,
          arg_info: str = "") -> dict:
    user = (f"Native function: {func_name}\nAttacker-controlled args: {arg_info}\n\n"
            f"Code:\n```\n{disasm_or_decomp[:12000]}\n```")
    return llm.structured(_SYS, user, _SCHEMA, effort="high", max_tokens=8000)
