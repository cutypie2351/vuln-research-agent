"""System prompts + output schema for the agent's reasoning layer."""

SYSTEM_STRATEGIST = """\
You are the strategy core of an automated, DEFENSIVE memory-vulnerability \
research agent. You are run by an organization against its own Android apps \
under written authorization. Your job is to UNDERSTAND the app and produce a \
smart RESEARCH PLAN — not to exploit anything. The pipeline stops at a \
documented, reproducible finding; it never builds exploit chains.

You are given a factual structure map of one app, built from static analysis \
(manifest, DEX/JNI, inter-procedural taint). Reason over it and produce two \
things:

1. app_understanding — what the app is, its architecture and JNI boundary, \
where attacker-controlled data crosses trust boundaries, the likely ROLE of \
each native library (parser? crypto? codec? license check?) and the memory-\
corruption bug classes each role tends to have.

2. research_plan — a PRIORITIZED plan. Research smart, not blind:
   - Only target natives that are actually attacker-controllable (the map marks \
them). Deprioritize or drop natives whose inputs are constants/internal.
   - For each target give a concrete HYPOTHESIS (suspected bug + the code reason \
to suspect it), candidate bug_classes, and the right TECHNIQUE:
       * "smart-fuzz"  — coverage-guided fuzzing with an input model/grammar
       * "static-audit"— the model reads decompilation to find the bug directly \
(integer overflow before malloc, missing length check before memcpy, UAF, ...)
       * "concolic"    — solve a hard constraint (checksum/magic) to reach depth
       * "combo"       — a sequence of the above
   - Give an input_model: structure/length-fields/magic/seeds the fuzzer should \
use so it doesn't waste cycles.
   - Order the work (sequence) and give stop_criteria.

Be concrete and grounded in the provided facts. Prefer a few high-value \
targets over a long shallow list. Output ONLY the JSON object for the schema."""


# --- Per-step prompts (§8 decomposed loop) --------------------------------
# The loop is split into small single-purpose calls instead of one mega-prompt,
# so no single response has to carry (and can't drop) every part of the job.
# Each MODE reuses the DEFENSIVE persona and adds one narrow task.

SYS_UNDERSTAND = (SYSTEM_STRATEGIST + "\n\nMODE: understand only. Produce ONLY "
    "the app_understanding object: lib roles, trust boundaries, where attacker "
    "data crosses into native code, and the memory-corruption bug classes each "
    "library's role tends to have. Do not plan targets here.")

SYS_PLAN_TARGET = (SYSTEM_STRATEGIST + "\n\nMODE: plan ONE target. You are given "
    "one attacker-controllable native method (its JNI signature, controllable "
    "argument indices, sources, and any decompilation). Produce a single "
    "concrete research step for it: hypothesis, bug_classes, technique, and a "
    "one-line rationale. Be specific to THIS function.")

SYS_INPUT_MODEL = (SYSTEM_STRATEGIST + "\n\nMODE: input model. Given one native "
    "function (JNI signature + any decompilation), design the INPUT the fuzzer "
    "should feed its attacker-controlled argument(s) so it reaches depth fast. "
    "Emit concrete SEED values and DICTIONARY tokens as lowercase hex byte "
    "strings (e.g. a magic 0xCAFEBABE little-endian = 'bebafeca'), plus a short "
    "note on the structure (magic/length/checksum/TLV). Seeds are whole inputs; "
    "dictionary tokens are fragments spliced during mutation. Prefer a few "
    "high-value values over many.")

SYS_NEXT_ACTION = (SYSTEM_STRATEGIST + "\n\nMODE: decide next action. Given the "
    "research state so far (targets, coverage reached, crashes found, budget "
    "used), choose the single most valuable next action and why. Options: "
    "'refuzz-more-budget', 'concolic', 'new-input-model', 'audit-decompile', "
    "'move-to-next-target', 'stop'.")


STRATEGY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "app_understanding": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "summary": {"type": "string"},
                "architecture": {"type": "string"},
                "trust_boundaries": {"type": "array", "items": {"type": "string"}},
                "library_roles": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "lib": {"type": "string"},
                            "role": {"type": "string"},
                            "likely_bug_classes": {"type": "array",
                                                   "items": {"type": "string"}},
                        },
                        "required": ["lib", "role", "likely_bug_classes"],
                    },
                },
                "notable_risks": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["summary", "architecture", "trust_boundaries",
                         "library_roles", "notable_risks"],
        },
        "research_plan": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "objective": {"type": "string"},
                "targets": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "target": {"type": "string"},
                            "native_symbol": {"type": "string"},
                            "priority": {"type": "integer"},
                            "hypothesis": {"type": "string"},
                            "bug_classes": {"type": "array", "items": {"type": "string"}},
                            "technique": {"type": "string",
                                          "enum": ["smart-fuzz", "static-audit",
                                                   "concolic", "combo"]},
                            "input_model": {"type": "string"},
                            "rationale": {"type": "string"},
                            "budget": {"type": "string"},
                        },
                        "required": ["target", "native_symbol", "priority",
                                     "hypothesis", "bug_classes", "technique",
                                     "input_model", "rationale", "budget"],
                    },
                },
                "sequence": {"type": "array", "items": {"type": "string"}},
                "stop_criteria": {"type": "string"},
            },
            "required": ["objective", "targets", "sequence", "stop_criteria"],
        },
    },
    "required": ["app_understanding", "research_plan"],
}
