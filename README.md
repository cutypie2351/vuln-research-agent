# vuln-research-agent

Defensive memory-vulnerability research harness. Design spec: see
`vuln-research-agent-plan.md`. Intended for authorized use only — running an
organization against its own binaries, with written scope. The system stops at
a documented, reproducible finding; it does not build exploits.

## Status
**Step 1 — RE layer (done):** Phase 1 intake + Phase 2 attack-surface mapping
driven by a live IDA Pro instance over MCP. All facts land in a per-target
SQLite Knowledge Base (the source of truth; the LLM only ever sees the compact
summary).

**Step A — Android front-end (done):** `apk` → extract native `.so` per ABI,
parse manifest entry points, enumerate JNI native methods (dexdump), resolve
to native symbols/addresses (static name-mangling; dynamic RegisterNatives via
IDA). Per-APK KB at `targets/<package>/kb.sqlite` (schema v2).

Orchestration model: **standalone autonomous agent** (plan §8). IDA Pro is
reached as an MCP client (replacing the Ghidra-headless step from the plan).
Primary target: **Android native libraries** from APKs.

## Layout
    vra/ida_client.py           MCP streamable-HTTP client for IDA (stdlib only)
    vra/env.py                  host toolchain discovery (SDK, jadx, dexdump, JDK)
    vra/intake.py               Phase 1: format/arch/mitigations detection
    vra/surface.py              Phase 2: sinks/sources/xrefs/decompile -> KB
    vra/android/apk_extract.py  Phase A.1: extract .so, ABI plan, manifest
    vra/android/jadx_context.py Phase A.2: jadx + dexdump native methods
    vra/android/flow.py         Phase A.2b: controllability (dexdump taint)
    vra/android/jni_map.py      Phase A.3: JNI static+dynamic resolution
    vra/harness/jni_harness.py  Phase 3: C/AFL harness generator (fake JNIEnv)
    vra/harness/qiling_harness.py Phase 3: Qiling isolated harness (bionic+JNIEnv)
    vra/kb.py                   Knowledge Base (SQLite, schema v2)
    vra/config.py               sink/source catalogs + scoring priors
    vra/cli.py                  `python -m vra {apk|new|surface|show|targets}`

## Usage
    # Android (run under the venv for lief; needs Android SDK env):
    .venv/bin/python -m vra apk samples/UnCrackable-Level3.apk
    .venv/bin/python -m vra apk app.apk --no-jadx   # faster, dexdump only
    .venv/bin/python -m vra apk app.apk --ida       # +dynamic RegisterNatives
    # Binary RE (needs IDA Pro + MCP plugin at http://127.0.0.1:13337/mcp):
    python3 -m vra surface            # map the binary currently loaded in IDA
    python3 -m vra show               # print KB summary (ranked surfaces)

## Status: full pipeline complete
`vra agent <apk>` / `vra hunt <apk>` run end-to-end: APK -> controllable natives
-> Qiling isolated harness -> coverage fuzz (+CmpLog, guard-page oracle, auto-unlock,
angr concolic hand-off) -> triage -> findings. Validated on a CTF native-vuln suite
(stack/heap/off-by-one/magic-gate/constraint-gate/init-gate all found) and UnCrackable3
(no false positives). LLM brain (plan/assess/static-audit) is key-gated.

## Roadmap (remaining)
- Activate the LLM brain (set `ANTHROPIC_API_KEY`): plan/assess/static-audit are built but untested
- arm64-v8a harness path (currently x86_64 native-host only)
- Frida in-situ harness on the AVD (§10 A.5) for hard-to-model targets
- Validate dynamic `RegisterNatives` JNI resolution on a real target
- Broader real-world APK corpus + regression/CI mode (§12)
