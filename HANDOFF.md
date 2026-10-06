# vuln-research-agent — Handoff / Continuation Guide

**Last updated:** 2026-10-06 (generic-input-model + oracle-depth + always-on LLM upgrade)
**Purpose:** Everything built so far, how it works, how to run it, results, and
exactly what to do next. A fresh session should be able to read this and
continue testing + developing without re-deriving context.

---

## 0. What this project is

An **automated memory-vulnerability research agent** for **Android native
libraries** (`.so` from APKs). **Defensive / authorized use only** — the system
discovers and documents memory-corruption bugs and stops at a reproducible
finding; it does **not** build exploits.

Pipeline intent:
`APK → extract .so + map Java→native input flow → find attacker-controllable
natives → statically research for bug classes → synthesize an isolated harness →
smart coverage-guided fuzzing (+ magic/constraint solving) → triage → documented,
minimized, reproducible finding (+ IDA Hex-Rays root cause).`

Design spec (Hebrew): `~/Downloads/vuln-research-agent-plan.md`.
Code: `~/vuln-research-agent/` (this repo). Memory notes the AI keeps:
`~/.claude/projects/-Applications-IDA-Professional-9-4-app-Contents-MacOS/memory/vuln-research-agent.md`.

### Core architecture decisions (already made — don't relitigate)
- **Standalone autonomous agent** (own LLM loop), not Claude-Code-as-orchestrator.
- **RE backend = IDA Pro via MCP** (replaces the plan's Ghidra). Reached as an MCP
  **client** over HTTP at `http://127.0.0.1:13337/mcp` (stdlib client, no SDK).
- **KB = one SQLite file per target/APK** (`targets/<pkg>/kb.sqlite`). The LLM only
  ever sees `KB.summarize*()`, never raw dumps.
- **Primary target = Android native libs** (arm64 + x86_64). Everything below runs
  the **x86_64** path for speed (arm64 path not built yet).
- **Fuzzing/symbex run in a Linux Docker container** (`vra-fuzz`); RE + orchestration
  run on the macOS host.

---

## 1. The machine / environment (critical — Intel Mac, no brew)

- **Intel x86_64 Mac** (i7-9750H, 16 GB), **macOS 15.0.1**. **Homebrew DOES NOT WORK**
  (Homebrew dropped Intel support; installer hard-refuses). Everything installed
  **manually**. Do NOT suggest brew.
- Claude Code has been running **as root (uid 0) with passwordless sudo** (the user
  launched it that way). Homebrew/brew refuse root anyway. **Run user-space tools as
  `sudo -u admin -H …`** so files stay owned by `admin` (uid 501, group staff/20).
  Always `cd` to an admin-readable dir first — the scratchpad under `/private/tmp/claude-0/…`
  is root-only and causes `getcwd` noise when dropping to admin.
- After writing files as root, **`chown -R 501:20 <paths>`** to keep them admin-owned.
- **No `ANTHROPIC_API_KEY` is set**, and the `ant` CLI is not installed. The LLM parts
  (strategy / assess / static-audit) are built but **cannot be run** until a key is
  provided (env `ANTHROPIC_API_KEY`, or write it to `~/vuln-research-agent/.anthropic_key`,
  chmod 600 — gitignored). The deterministic pipeline needs **no key**.

### Installed toolchain (all manual)
- **JDK** Temurin 17 → `JAVA_HOME="$(/usr/libexec/java_home -v 17)"`.
- **Android SDK** at `/Users/admin/Library/Android/sdk`: `platform-tools` (adb),
  `emulator` 37.2, `build-tools/34.0.0` (aapt2, d8, zipalign, apksigner, dexdump),
  `platforms/android-34` (android.jar), system image `android-34;google_apis;x86_64`.
- **AVD** named `fuzz_x86_64` (Android 14, rootable). Boot headless:
  `emulator -avd fuzz_x86_64 -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect`.
  (An emulator may still be running from a previous session.)
- **jadx** 1.5.6, **apktool** 3.0.3 in `/usr/local/bin`.
- **Docker Desktop** (CLI at `/usr/local/bin/docker`, Linux VM x86_64, 12 CPU / 8 GB).
  Known quirk: the VM clock skews → apt in Docker builds needs
  `-o Acquire::Check-Date=false`.
- **Python venv** at `~/vuln-research-agent/.venv` (system python **3.9** — this caps
  `anthropic` at the 0.x SDK; 1.x needs py3.10+). Installed: `frida` 17.22,
  `frida-tools`, `jnitrace`, `lief` 1.0, `capstone`, `unicorn`, `anthropic` 0.125.
- **Shell profile** `~/.zprofile` exports JAVA_HOME / ANDROID_HOME / PATH and a
  `vra-venv` alias.

### The `vra-fuzz` Docker image (the fuzzing/symbex host)
- Built from `docker/Dockerfile.fuzz` (Ubuntu 24.04): AFL++ 4.09c, clang/llvm 18,
  `qemu-user-static`, and **python3.12** with **angr 10.0.1, qiling 1.4.6, unicornafl,
  lief, capstone, unicorn, pwntools**.
- Run pattern (mount the repo at `/work`):
  ```
  docker run --rm -v /Users/admin/vuln-research-agent:/work -e PYTHONPATH=/work -w /work \
      vra-fuzz python3 -m vra _fuzzrun --name <pkg> --budget 20 --angr
  ```
- Rebuild: `docker/build.sh`.

### Bionic rootfs (for Qiling to load real Android `.so`)
- `~/vuln-research-agent/rootfs/x86_64_android/` holds real x86_64 **bionic**
  `libc.so`/`libm.so`/`libdl.so`/`liblog.so` + `linker64`, pulled via `adb pull` from
  the booted AVD (`/apex/com.android.runtime/lib64/bionic/*` and `/system/lib64/liblog.so`).
  Gitignored (binaries). Needed because glibc can't load bionic `.so`.

---

## 2. Repo layout & every module (36 python files)

```
vra/
  __init__.py, __main__.py
  cli.py            CLI: apk | hunt | agent | plan | surface | new | show | targets | _fuzzrun
  config.py         IDA URL, sink/source catalogs, scoring priors
  env.py            host tool discovery (aapt2, dexdump, jadx, adb, java_home)
  ida_client.py     IDA MCP client over HTTP/JSON-RPC (stdlib; initialize+tools/call)
  intake.py         Phase 1: format/arch/mitigations (macho/elf/pe; lief optional)
  surface.py        Phase 2: IDA-driven sinks/xrefs/decompile/callgraph -> KB
  kb.py             SQLite Knowledge Base (schema v4 + migrations)
  research.py       Static vuln-research pass (objdump sink scan -> hypotheses + dict consts)
  hunt.py           End-to-end deterministic hunt (container worker + report)

  android/
    apk_extract.py  Phase A.1: unzip .so per ABI, ABI plan, aapt2 manifest -> entry points
    jadx_context.py Phase A.2: dexdump native methods (JNI descriptors) + jadx decompile
    flow.py         Phase A.2b: inter-procedural Dalvik taint -> controllability
    jni_map.py      Phase A.3: JNI static (name-mangling+nm) + dynamic (RegisterNatives via IDA)
    ida_decompile.py HOST-side IDA Hex-Rays enrichment of findings (open .so in IDA)

  harness/
    jni_harness.py    Phase 3: C/AFL harness generator (fake JNIEnv) — early approach
    qiling_harness.py Phase 3: Qiling isolated harness (bionic + modeled JNIEnv + libc stubs)

  fuzz/
    engine.py       FuzzHarness (fast Qiling loop) + guard-page oracle + coverage + fuzz()
    cmplog.py       RedQueen-lite: harvest comparison magics into the dictionary
    seeds.py        seeds + dictionary from .so strings/rodata
    plateau.py      angr concolic hand-off: solve uncovered branch targets -> seeds

  symbex/
    angr_solve.py   angr solver: symbolic byte[] + JNIEnv SimProcedures -> reach target addr

  triage/
    triage.py       minimize, reproduce, classify, disasm (capstone), symbolized backtrace, Finding

  agent/
    llm.py          Anthropic client wrapper (key from env/.anthropic_key; output_config via extra_body)
    prompts.py      strategist system prompt + JSON schema
    appmodel.py     deterministic app-structure map (entry->native dataflow, ranked targets)
    strategy.py     LLM: understanding + prioritized research plan (key-gated)
    static_audit.py LLM: read decompilation -> bug-class hypotheses (key-gated)
    loop.py         orchestrator: plan_phase + assess_findings (key-gated, degrades gracefully)

docker/Dockerfile.fuzz, docker/build.sh
scripts/build_ctf.sh         builds the CTF challenge APK suite
rootfs/x86_64_android/       bionic libs (gitignored)
samples/                     test APKs (gitignored)
scratch/                     dev scripts, vuln sources, CTF build (gitignored)
targets/<pkg>/kb.sqlite      per-APK Knowledge Base (+ libs/, dex/, jadx/)
```

---

## 3. How the pipeline works (end to end)

### Phase A — Android front-end (host; `vra apk <apk>`)
1. **apk_extract**: unzip `lib/<abi>/*.so`; `aapt2 dump badging` for package/sdk/abis;
   `aapt2 dump xmltree AndroidManifest.xml` → exported components (relative names like
   `.MainActivity` are expanded to `pkg.MainActivity`). ABI plan prefers x86_64
   native-host + arm64 emulated.
2. **jadx_context**: `dexdump -f` → every `native` method with its exact JNI descriptor
   (`([B)Z` etc.) + parsed arg types; `jadx` decompiles to Java (for later model
   reasoning; `--no-jadx` skips it — faster, flow still works via dexdump).
3. **flow** (controllability): inter-procedural **backward taint over Dalvik bytecode**
   (`dexdump -d`). For each native call site it classifies each argument register
   origin (const/field/param/source) and follows params up the call graph to a
   SOURCE (`getIntent/get*Extra/getData/getText/streams/provider`) or a constant.
   Marks `controllable` + `controlled_args` + `sources`. **Only controllable natives
   are fuzzed.** (Key bug fixed: `_def_index` must skip `if-*`/stores/branches which
   read — not write — their first register; see `_NON_DEF`.)
4. **jni_map**: resolve each Java native method → native symbol/address. Static via
   **JNI name-mangling** (`.`→`_`, `_`→`_1`, `;`→`_2`, `[`→`_3`) matched against `nm -D`;
   dynamic `RegisterNatives` via IDA (built, **untested**). Note: the `native_lib` name
   and the symbol must match JNI mangling — package ids with underscores escape to `_1`.

All facts → KB. `vra apk <apk> [--no-jadx] [--ida]`.

### §8 agent reasoning (host; `vra plan` / `vra agent`)
- **appmodel.build_structure**: deterministic app-structure map — exported entry points,
  native libs, `source → native` dataflow edges, ranked targets (controllable first).
- **strategy.strategize** (LLM, key-gated): app understanding (lib roles, trust
  boundaries, likely bug classes) + prioritized research plan (per target: hypothesis,
  technique smart-fuzz/static-audit/concolic, input model). Degrades to the deterministic
  map with no key.

### Static vuln-research (container, in hunt; `research.static_scan`)
Before fuzzing each target: `objdump --disassemble=<symbol>` → flag dangerous-sink calls
(memcpy/strcpy/sprintf/alloca/malloc…) as **bug-class hypotheses**, and harvest the
function's immediates into the **fuzz dictionary** (so fuzzing is magic-aware from the
start). Report shows "STATIC VULN-RESEARCH" vs "CONFIRMED FINDINGS".

### Phase 3/4/5 — harness + fuzz + triage (container; `vra _fuzzrun` / via `hunt`)
- **FuzzHarness** (`fuzz/engine.py`): loads the `.so` once in Qiling (bionic rootfs),
  models **JNIEnv** as a 300-entry function-pointer table (index = struct offset/8;
  171=GetArrayLength, 184=GetByteArrayElements, 169=GetStringUTFChars) whose entries
  point to hooked trampolines implemented in Python; stubs all **libc imports by name**
  (bump-malloc with **guard pages**, memcpy via `_emu_write`, …) and **neutralizes
  anti-tamper** (ptrace/fork/pthread_create). Sets FS base (stack canary). Fast re-enter
  per input via `uc.context_restore`. **auto_unlock**: scans the entry for an early
  `cmp [rip+x], IMM` init-gate and writes IMM to that global (cracks flag gates).
  `jbyteArray` modeled as `{int32 len; ptr data}`.
- **Oracle**: unmapped/prot memory hooks + the **guard-page heap** → even a +1 heap
  overflow faults. Crash dedup via `crash_key` (in-image pc = stable site; else one
  "pc-control" bucket so one bug ≠ thousands of crashes).
- **fuzz()**: coverage-guided havoc (incl. length-grow, dict splice). **CmpLog**
  (`cmplog.py`) seeds the dictionary from comparisons; **seeds.py** adds strings.
- **angr hand-off** (`plateau.py` + `symbex/angr_solve.py`): on 0-crash plateau with
  `--angr`, find uncovered conditional-branch targets, angr-solve to reach them, re-seed.
- **triage** (`triage/triage.py`): minimize (truncate+canonicalize), reproduce (6/6),
  classify (heap/stack/pc-control/oob + severity), disasm faulting insn (capstone),
  symbolized backtrace (lief) → `Finding` → KB.
- **IDA enrichment** (`android/ida_decompile.py`, HOST, after container fuzz): if the
  target `.so` is **open in IDA** (sha match), attach Hex-Rays decompilation of the
  crashing function to the finding (root cause) and feed the LLM audit.

### Report
`hunt.render_report` / `report_from_kb`: STATIC hypotheses + CONFIRMED findings (with
symbol, access, fault insn, minimized reproducer hex, backtrace, IDA decompile block).

---

## 4. CLI quick reference (run under the venv on the host)

```
# Full agent (ingest -> plan -> fuzz/triage -> IDA enrich -> assess):
sudo -u admin -H JAVA_HOME="$(/usr/libexec/java_home -v 17)" ANDROID_HOME=/Users/admin/Library/Android/sdk \
  /Users/admin/vuln-research-agent/.venv/bin/python -m vra agent <app.apk> --budget 25 [--no-jadx]

# Deterministic end-to-end hunt:
… .venv/bin/python -m vra hunt <app.apk> --budget 30 --angr [--no-jadx]

# Phase A only (ingest):            … -m vra apk <app.apk> [--no-jadx]
# Plan/understanding only:          … -m vra plan --name <pkg> [--no-llm]
# Container fuzz worker (internal): docker run … vra-fuzz python3 -m vra _fuzzrun --name <pkg> --budget 20 --angr

# IMPORTANT: `hunt`/`agent` run Phase A on host then shell to Docker for fuzzing.
# Host stdout and container stdout interleave — to see a CLEAN report, run the
# container worker directly:
docker run --rm -v /Users/admin/vuln-research-agent:/work -e PYTHONPATH=/work -w /work \
  vra-fuzz python3 -m vra _fuzzrun --name <pkg> --budget 20 --angr | sed -n '/HUNT REPORT/,$p'
```

---

## 5. Results so far (all validated)

**CTF-style native-vuln suite** (built by `scripts/build_ctf.sh`, sources in
`scratch/ctf_src/`, APKs in `scratch/ctf/`). Each is a real signed APK: an exported
Activity passes `getIntent().getByteArrayExtra("d")` into a native method.

| APK | Bug | Skill that cracked it | Result |
|-----|-----|-----------------------|--------|
| c1stack | stack overflow (memcpy) | coverage fuzz | CRITICAL + HIGH |
| c2heap | heap overflow | guard-page oracle | HIGH |
| c3offbyone | heap **+1 byte** | guard-page oracle | HIGH |
| c4magic | `0xDEADBEEF` gate | **CmpLog** (cov→1431) + static dict | CRITICAL |
| c5constraint | xor+sum gate | **angr hand-off** (0→1 crash) | HIGH |
| c6initgate | init flag gate | **auto-unlock** (cov→3407) | CRITICAL |

- **com.vra.test** (earlier vuln APK, `scratch/vuln-test.apk`): 4 reproducible findings.
- **OWASP UnCrackable-Level3** (`samples/UnCrackable-Level3.apk`): real native, **0
  findings = no false positives** (oracle quiet on safe code; coverage shallow because
  `bar` has an init gate not unlocked generically).
- Static research + smart dict proven on c4magic: the crash reproducer begins
  `efbeadde` (0xDEADBEEF LE) — the magic injected from the harvested constant.
- IDA Hex-Rays decompilation through the harness validated against the loaded KeygenMe
  (resolve symbol → 3278 chars).

**Mission bar met:** finds the planted native memory bug in every vulnerable target and
stays silent on safe code; every finding is minimized + reproducible.

---

## 6. Honest gaps / what is NOT done

- **LLM brain** (understand / plan / input-model / audit / assess / next-action):
  rewritten this session to stdlib-HTTP + decomposed per-step calls (see §8.5).
  Still needs `ANTHROPIC_API_KEY` for a live smoke test. Default `claude-opus-5-5`
  (override `VRA_MODEL`); structured output via single-tool `tool_choice`.
- **x86_64 only.** No arm64-v8a harness (needs an arm64 bionic rootfs + arm64 register/
  calling-convention changes in `fuzz/engine.py`).
- **Dynamic `RegisterNatives`** JNI resolution: coded (`jni_map.resolve_dynamic_via_ida`,
  string-anchored via IDA) but **never validated** on a real target.
- **Frida in-situ** harness (plan §10 A.5) not built.
- **No real-world CTF APK with a native memory bug tested yet** (only the synthetic CTF
  suite + UnCrackable3 for no-FP). ← this is the current task (see §7).
- IDA MCP must be connected for `surface`/`ida_decompile` (it disconnected at the end of
  the last session; reconnect by having IDA Pro open with the MCP plugin on `:13337`).

---

## 7. CURRENT TASK (interrupted by session usage limit) — do this next

The user asked to **find a NEW, harder, bigger real native-vuln CTF APK** and run the
**full harness** on it (as a "new agent run"), to prove the harness succeeds on a
realistic target (native vulns only).

Progress when interrupted:
- Chosen candidate: **Allsafe** (modern multi-challenge vulnerable Android app; has a
  real `libnative` **stack-overflow** JNI challenge reachable from an Activity — bigger/
  harder than the toy libs). Repos tried: `t3jv1l/Allsafe`, `sh4hin/Allsafe` — **no
  prebuilt APK in GitHub releases** (they ship source).
- `WebSearch` then hit the **session usage limit** before finding a download.

### Suggested next steps
1. **Find a downloadable real native-vuln APK.** Candidates to try:
   - **Allsafe** — build from source (gradle) OR find a prebuilt APK mirror; its native
     challenge does `strcpy` of attacker input into a fixed stack buffer (String arg →
     our harness models `GetStringUTFChars` idx 169).
   - **DIVA** (divajni) — native challenge exists but is a hardcoded-compare (logic), may
     yield no memory finding (good no-FP test, not a bug-find).
   - **OWASP UnCrackable-Level4** (`Crackmes/Android/Level_04`) — uses native +
     `RegisterNatives` (would also exercise the untested dynamic-JNI path), but it's a
     logic crackme (likely no memory bug → no-FP).
   - Search F-Droid / CTF archives for apps bundling a vulnerable parser `.so`.
   - To fetch OWASP crackmes (worked before):
     `https://github.com/OWASP/owasp-mastg/raw/master/Crackmes/Android/Level_04/…apk`
2. **If no reliable real one is found**, build a **harder, bigger synthetic CTF APK** that
   clearly exceeds the toys: a realistic binary-format parser `.so` (header magic +
   length field + checksum/CRC gate + nested TLV records) with a **deep heap overflow**
   only reachable after passing the magic (needs CmpLog), the checksum (needs the
   "neutralize checksum for fuzzing" trick or angr), and a length computation
   (integer-overflow → under-alloc). This stresses CmpLog + angr + guard-oracle +
   grammar together. Extend `scripts/build_ctf.sh` (remember: **package ids must be
   underscore-free** or JNI mangling breaks the symbol match — a builder bug fixed last
   session). Model a `String` arg path too (tests `GetStringUTFChars`).
3. **Run the full harness** on the chosen APK:
   - `vra apk <apk>` (ingest) → confirm flow marks the vuln native controllable.
   - `vra hunt <apk> --budget 60 --angr` (give a real target more budget).
   - For IDA root cause: open the target `.so` in IDA Pro (MCP on `:13337`), then the
     `hunt`/`agent` host step auto-attaches Hex-Rays decompilation.
   - Verify: a CONFIRMED finding with a minimized, reproducible input; no false positives
     on the app's safe natives.
4. **If a real app exposes gaps** (new JNIEnv functions the native calls, multidex,
   dynamic RegisterNatives, a String/other arg type, larger functions), fix them — these
   are exactly the robustness improvements worth making. Likely spots:
   - `fuzz/engine.py` JNIEnv table: add more stubbed JNIEnv indices if the native calls
     them (symptom: jump to the generic stub returning 0 then odd behavior; or an
     unmapped fetch inside the native). Map more of `JNINativeInterface` by offset/8.
   - `fuzz/engine._wire_libc`: add libc stubs if an import isn't covered (symptom:
     execution derails to a PLT target; add the name to the stub table).
   - `android/jni_map` dynamic path if the symbol isn't a static `Java_*` export.

### How to resume concretely
```
cd ~/vuln-research-agent
# (ensure IDA Pro open w/ MCP on :13337 if you want decompilation; emulator optional)
# try to fetch a candidate APK into samples/ (own empty dir, treat as untrusted)
# then:
sudo -u admin -H JAVA_HOME="$(/usr/libexec/java_home -v 17)" ANDROID_HOME=/Users/admin/Library/Android/sdk \
  ./.venv/bin/python -m vra hunt samples/<candidate>.apk --budget 60 --angr --no-jadx
# clean report:
docker run --rm -v "$PWD":/work -e PYTHONPATH=/work -w /work vra-fuzz \
  python3 -m vra _fuzzrun --name <pkg> --budget 60 --angr | sed -n '/HUNT REPORT/,$p'
```

---

## 8. Gotchas cheat-sheet (things that bit us; keep them in mind)

- **Run user tools as `sudo -u admin -H`**, `cd` to an admin-readable dir first; chown
  new files to `501:20`. Container mounts map container-root → host-admin, so build dirs
  the container writes into must be admin-owned first.
- **Docker VM clock skew** → apt in image builds needs `Acquire::Check-Date=false`.
- **Qiling loads the `.so` without its deps** → we stub libc by name + model JNIEnv; if a
  real target uses an unstubbed import or JNIEnv entry, add it.
- **anthropic is 0.x** on this py3.9 host → structured output via `extra_body`, not the
  1.x `messages.parse`.
- **KB migrations**: `kb.py` `_migrate()` ALTERs old KBs; schema is v4. Delete a
  `targets/<pkg>/kb.sqlite` to force a clean re-ingest if schema changes.
- **CTF APK builder**: package ids MUST be underscore-free (JNI `_`→`_1`).
- **Host vs container stdout interleave** in `hunt`/`agent`; run `_fuzzrun` directly for a
  clean report.
- **IDA MCP** currently disconnected (end of last session). Reconnect: IDA Pro open with
  the MCP plugin serving `http://127.0.0.1:13337/mcp`. One IDB = one `.so`.

---

## 8.5 — 2026-10-06 UPGRADE (waves 1–5): what changed & what to validate

Implemented this session (host-verified by `compileall` + unit tests; the
Qiling/angr runtime paths still need a **container run** to validate — Docker was
down here). New/changed files:

- **`vra/agent/llm.py`** — rewritten to call the Messages API over **stdlib
  `urllib`** (no SDK → the py3.9 cap is gone). Structured output is forced with a
  single-tool `tool_choice` (schema-valid JSON every time). Retries with backoff
  on 429/5xx; every failure degrades to `LLMUnavailable`. `available()` now needs
  only a key. Unit-tested with a mock transport.
- **`vra/agent/steps.py`** (new) + **`loop.py`** (rewritten) — the LLM loop is now
  **many small single-purpose calls** instead of one mega-prompt: `understand` →
  per-target `plan_target` + `input_model` → (fuzz) → per-finding `assess_finding`
  → `next_action`. Each step is independently guarded (one failing step never
  sinks the run). Per-target **input models** (model-designed seeds + dictionary,
  stored as hex in `app_model` kind `input_models`) are persisted so the
  container fuzzer picks them up with no key of its own (`loop.input_model_seeds`).
  New per-step prompts in `prompts.py`.
- **`vra/fuzz/inputspec.py`** (new) — **generic JNI input model**. Turns a
  method's readable arg types + `controlled_args` into SysV slots for EVERY
  argument (GP regs, xmm, stack) and packs one flat fuzz buffer into the whole
  tuple. Handles `byte[]`, all primitive arrays, `String`, **direct `ByteBuffer`**,
  and scalars (`int/long/float/double/bool/byte/char/short`). Single-`byte[]`
  stays byte-identical to the old harness (results preserved). Arch-parametrized
  (`arch="x86_64"|"arm64"`). Fully unit-tested on the host.
- **`vra/fuzz/engine.py`** — rewritten to be **spec-driven** (fills all args incl.
  xmm/stack) with a much richer **JNIEnv** (string/array/directbuffer accessors,
  `Get*ArrayElements` for every prim type, `Get*ArrayRegion`/`GetStringUTFRegion`
  copies modeled through the OOB-write oracle, `GetDirectBufferAddress/Capacity`,
  benign non-null default for `FindClass`/etc., `ExceptionCheck/Occurred`→0).
  Oracle depth: **per-run memory snapshot/restore** of the lib's writable
  segments (deterministic, kills cross-run contamination), **double-sided guard
  pages** (catch overflow AND underflow; allocs alternate alignment), **UAF**
  (`free()` protects the chunk page NONE → later access faults), input arrays are
  end-aligned (OOB **read** of attacker data faults). More libc stubs
  (`memset/strcpy/strcat/*_chk/...`). New bug classes wired into `triage.py`.
- **`vra/fuzz/logic.py`** (new) — **logic-flaw oracle via control-flow
  divergence**. Marks "win" blocks (refs to success-ish strings / calls to
  sensitive sinks); an input that reaches one the seeds never did is reported as
  a candidate auth/logic bypass (no exploit). Wired through `engine.fuzz()` →
  `hunt` → report (new "LOGIC-FLAW CANDIDATES" section).
- **`vra/fuzz/frida_harness.py`** (new, **VALIDATED on-device 2026-10-06**) —
  in-situ Frida harness: runs the real `.so` with the real JNIEnv/libc (no
  modeling). CLI: `vra insitu --name <pkg> --so libX.so --symbol Java_... [--arg string|bytearray] [--abi x86_64] [--execs N]`.
  Hard-won frida-17 specifics baked in (see the module docstring):
  * **No `Java` bridge** (removed in frida 17) — the JNIEnv comes straight from
    libart (`JNI_GetCreatedJavaVMs` -> `AttachCurrentThread`) and args are built
    through the JNIEnv vtable by index (`NewStringUTF`=167, `NewByteArray`=176,
    `SetByteArrayRegion`=208), all via `NativeFunction`.
  * frida-17 Module API: `Module.load`, `Module.getGlobalExportByName`, instance
    `module.getExportByName` (the old `Module.getExportByName(null,…)` is gone).
  * SELinux(enforcing) blocks exec-mapping from /data/local/tmp, so `stage_lib()`
    copies the extracted .so into the app's `code_cache` (app uid + restorecon),
    then `Module.load`s it. Works even for extractNativeLibs=false apps (no .so on
    disk) because we stage our own extracted copy.
  * Crash detection = `Process.setExceptionHandler` (SIGSEGV/SIGBUS/SIGILL) PLUS
    abort/fatal/process-death from the RPC (stack-canary/FORTIFY/checked-JNI
    aborts are SIGABRT, which the handler doesn't see).
  Validation: on Allsafe's real `checkPassword(String)` it loads the 299KB lib,
  gets a real JNIEnv, and runs strings up to 64KB with NO crash — confirming
  checkPassword has no memory bug (so the Qiling "findings" on it were derail
  false positives, correctly discarded). The device setup that worked: AVD
  `fuzz_x86_64` booted, `adb root`, push `frida-server` 17.22.2 (MUST match the
  host frida-python version exactly) to /data/local/tmp and run it, `adb install`
  the APK.
- **CLI**: `_fuzzrun --fuzz-all` (drive every data-bearing arg, not just
  proven-controllable — "don't miss any"); `insitu` command.

### VALIDATED 2026-10-06 (container run, Docker up)
Ran the full suite through the rewritten engine. All pass + no false positives:
- CTF c1–c6: all crack (c1/c4/c6 CRITICAL stack; c2/c3/c5 HIGH heap), 6/6 reproducible.
- **New generic-input-model suite** (`scripts/build_ctf2.sh`, sources in
  `scratch/ctf_src/c7string.c|c8multi.c|c9buffer.c`):
  * **c7string** — `run(String)` strcpy → CRITICAL stack overflow (validates the
    String path: GetStringUTFChars + String materialization).
  * **c8multi** — `run(int n, byte[] d)` undersized alloc → HIGH heap overflow
    (validates the multi-arg tuple `int@rdx + byte[]@rcx` and scalar-aware mutation).
  * **c9buffer** — `run(ByteBuffer)` → CRITICAL stack overflow via `--fuzz-all`
    (validates direct ByteBuffer: GetDirectBufferAddress/Capacity).
- UnCrackable3: 0 findings (no false positives).
- **Real app — Allsafe** (`samples/allsafe/allsafe.apk`, `infosecadventures.allsafe`):
  ingest resolved the String native `checkPassword` via the NEW multi-lib JNI
  resolution; fuzzing a 299KB Flutter/C++ lib under pure Qiling eventually DERAILS
  (unmodeled C++/JNI) — this is the emulation-fidelity ceiling, so for such targets
  use the **Frida in-situ** path (`vra insitu`), not the emulator.

Bugs found & fixed while testing (all real, all help real libs):
- XMM regs live in `unicorn.x86_const` (float/double args were never set).
- `_auto_unlock` generalized to the `mov rX,[rip+got]; mov eX,[rX]; cmp eX,IMM`
  pointer-to-flag gate (c6's shape; the old matcher only did `cmp [mem],imm`).
- `_apply_relative_relocs`: apply RELATIVE + GLOB_DAT + JUMP_SLOT for
  locally-defined symbols (Qiling leaves them 0 → pointer-to-data and local PLT
  calls faulted). Big correctness win for real libs.
- `_wire_libc`: bind EVERY unresolved imported function to a benign stub (+ C++
  runtime: operator new/delete, `__cxa_guard_*`, strdup) so an unmodeled libc call
  doesn't jump a null PLT slot (was a false crash).
- `run()` only reports a crash when the oracle recorded a fault; a stub that raises
  with no fault is a harness limit, not a finding (killed addr-0 false positives).
  `_emu_read` records a real fault address for genuine stub OOB reads.
- Input buffers get zero-padded slack instead of a guard page (real ART arrays have
  headroom; fencing them produced false String overflows).
- **Determinism fix:** guard pages are PROT_NONE (not unmapped) so `map_anywhere`
  can't hand them back out and destroy the oracle mid-fuzz; oversized allocs are
  capped (`_ALLOC_CAP`) and reclaimed each run (`context_restore` doesn't undo
  mappings). `_emu_write`/`_emu_read` check the span against guard/freed ranges
  because `ql.mem.*` bypass unicorn page perms. This fixed non-reproducible crashes.
- JNIEnv: safe-object (slots → ret gadget) for opaque handles; reserve page 0 so
  NULL derefs fault and nothing maps at 0.
- `jni_map.run_multi` + `--fuzz-all` + scalar-aware mutation (boundary/overflow ints).

### VALIDATE NEXT (do this first — it's the main regression check)
Docker was not running here, so the rewritten engine has not been run. Start the
daemon and re-run the CTF suite + the no-FP target; every row in §5 must still
pass and UnCrackable3 must still yield 0 findings:
```
cd ~/vuln-research-agent
docker run --rm -v "$PWD":/work -e PYTHONPATH=/work -w /work vra-fuzz \
  python3 -m vra _fuzzrun --name com.ctf.c1stack --budget 20 --angr | sed -n '/HUNT REPORT/,$p'
# repeat for c2heap c3offbyone c4magic c5constraint c6initgate, and uncrackable3 (expect 0)
```
Watch for: XMM/stack arg writing, `mem.protect`/`segments` lief API, and the
guard math on real libs. If a regression appears it's almost certainly in
`engine.run()` arg setup or `_snapshot_init`.

### STILL TODO
- **arm64 engine**: `inputspec` already emits arm64 regs (`x2..x7`, `v0..v7`); a
  parallel aarch64 `engine` (register names, `_ret` via `x30`, FS/TLS → `TPIDR`)
  + an **arm64 bionic rootfs** are still needed. Until then, arm64 reality is best
  reached through the **Frida in-situ** path on an arm64 emulator (the frida agent
  is arch-agnostic — same code, just boot an arm64 AVD + arm64 frida-server).
- **Frida harness** (now validated): add coverage (Stalker / AFL++ frida_mode) for
  throughput — today it's a confirmation/triage path, and long mutated String
  inputs are slow (NewStringUTF of MBs); bias the in-situ mutator to smaller sizes.
  Also: plumb `vra insitu` findings into the KB/report like the Qiling path.
- **LLM loop**: live-tested two ways. API path reached Anthropic successfully
  (auth/transport/forced-tool JSON all correct) but the account has $0 API credit
  (Pro/Max subscription does NOT include API credits — separate prepaid billing).
  **Offline-brain path works fully** (see below) and runs the identical loop on a
  Claude subscription via Claude Code. A one-line API smoke test is still TODO for
  whenever credits are added (just unset `VRA_OFFLINE_DIR`).

### Offline brain (run the LLM loop WITHOUT API credits) — `vra/agent/offline.py`
`VRA_OFFLINE_DIR=<dir>` swaps the HTTP transport in `llm.LLM` for a
content-addressed file transport. The loop/steps/schemas/KB writes are UNCHANGED
— only how one request is answered differs, so switching to the API later
(unset the env var) behaves identically. Two-pass: run the agent once to emit
prompts to `<dir>/pending/`, answer each (Claude Code, on the subscription, or a
human) into `<dir>/cache/<key>.json`, re-run -> every step cache-hits and the
loop completes exactly as the API would. CLI: `vra brain [--answer KEY --file J]
[--clear]`. Validated on Allsafe: produced app_understanding + a P1 research plan
+ input_models, and the container fuzzer then consumed `+8 model seeds +10 dict`.
Key is stored at `.anthropic_key` (chmod 600, git-ignored) for the API path.
- **A real native MEMORY-bug target**: Allsafe's native is a safe logic check (no
  memory bug — correctly reported as clean by both engines). Still want a real APK
  that ships a vulnerable parser `.so` to demonstrate an end-to-end real finding;
  our synthetic c1–c9 cover the bug classes but a real one is the last proof.

## 9. One-line status

**A working defensive Android-native vuln-research harness**: APK → controllable natives
→ static research + smart (CmpLog/angr/guard-oracle) fuzzing → minimized, reproducible
findings → IDA Hex-Rays root cause. Proven on a 6-case CTF suite + no-FP on UnCrackable3.
**Next: prove it on a harder/bigger real native-vuln CTF APK; activate the LLM brain with
an API key; add arm64 + Frida in-situ.**
