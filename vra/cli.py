"""CLI entrypoint for the harness (first step: intake + surface + show).

    python -m vra new  <binary> [--name N] [--source]
    python -m vra surface [--name N]        # map the binary loaded in IDA
    python -m vra show   [--name N]
    python -m vra targets                   # list known targets

The KB lives at  <project>/targets/<name>/kb.sqlite  (one per target).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

from . import config
from .ida_client import IdaMcpClient, IdaMcpError
from .intake import intake as run_intake
from .kb import KB
from .surface import map_surfaces
from .android import apk_extract, jadx_context, jni_map, flow
from .agent import appmodel, strategy, llm as agent_llm

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS_DIR = os.path.join(PROJECT_ROOT, "targets")
ROOTFS = os.path.join(PROJECT_ROOT, "rootfs", "x86_64_android")
FUZZ_IMAGE = "vra-fuzz"


def _kb_path(name: str) -> str:
    return os.path.join(TARGETS_DIR, name, "kb.sqlite")


def _store_target(kb: KB, tgt) -> int:
    return kb.upsert_target(
        name=tgt.name, path=tgt.path, sha256=tgt.sha256, fmt=tgt.fmt,
        arch=tgt.arch, bits=tgt.bits, source_available=tgt.source_available,
        imagebase=tgt.imagebase, mitigations=tgt.mitigations, meta=tgt.meta)


def cmd_new(args) -> int:
    tgt = run_intake(args.binary, name=args.name, source_available=args.source)
    with KB(_kb_path(tgt.name)) as kb:
        tid = _store_target(kb, tgt)
    print(f"intake ok -> target '{tgt.name}' (id={tid})")
    print(json.dumps(tgt.as_dict(), indent=2, default=str))
    return 0


def cmd_surface(args) -> int:
    try:
        ida = IdaMcpClient(config.IDA_MCP_URL)
        health = ida.call("server_health")
    except IdaMcpError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    input_path = health.get("input_path")
    module = health.get("module") or "target"
    name = args.name or module

    # Resolve or create the target record from the binary IDA has loaded.
    if input_path and os.path.isfile(input_path):
        tgt = run_intake(input_path, name=name, source_available=args.source)
    else:
        print(f"warning: IDA input_path not on disk ({input_path!r}); "
              "creating minimal target from IDA metadata", file=sys.stderr)
        from .intake import Target
        tgt = Target(path=input_path or "", name=name,
                     sha256=health.get("sha256", ""), fmt="macho",
                     imagebase=health.get("imagebase", ""))

    with KB(_kb_path(name)) as kb:
        tid = _store_target(kb, tgt)
        print(f"[surface] target '{name}' id={tid} "
              f"({tgt.fmt}/{tgt.arch}, canary={tgt.mitigations.get('canary')})")
        summary = map_surfaces(ida, kb, tid, decompile_cap=args.max_lines,
                               verbose=True)
    _print_summary(summary)
    return 0


def cmd_apk(args) -> int:
    apk_path = os.path.abspath(args.apk)
    if not os.path.isfile(apk_path):
        print(f"error: no such file {apk_path}", file=sys.stderr)
        return 2

    # 1. extract + manifest (A.1). Read package from badging first (no extract)
    # so we can extract straight into the per-package workdir.
    print("[apk] A.1 extract + manifest ...")
    package = apk_extract.badging(apk_path)["package"] \
        or os.path.splitext(os.path.basename(apk_path))[0]
    workdir = os.path.join(TARGETS_DIR, package)
    os.makedirs(workdir, exist_ok=True)
    ex = apk_extract.run(apk_path, workdir)
    print(f"[apk] package={package} abis={ex['abis']} "
          f"libs={len(ex['native_libs'])} entry_points={len(ex['entry_points'])}")

    # 2. jadx + dexdump context (A.2)
    print("[apk] A.2 jadx + dexdump (decompiling, may take ~1 min) ...")
    ctx = jadx_context.run(apk_path, workdir, do_jadx=not args.no_jadx)
    print(f"[apk] native_methods={len(ctx['native_methods'])} "
          f"loaded_libs={ctx['loaded_libraries']} jadx_out={ctx['jadx_out']}")

    # 3. JNI mapping against the primary (native-host) ABI lib (A.3)
    methods = ctx["native_methods"]
    primary_abi = ex["abi_plan"][0]["abi"] if ex["abi_plan"] else (
        ex["abis"][0] if ex["abis"] else None)
    abi_libs = [l for l in ex["native_libs"] if l["abi"] == primary_abi]
    ida = None
    if args.ida:
        try:
            ida = IdaMcpClient(config.IDA_MCP_URL)
            ida.call("server_health")
        except IdaMcpError as e:
            print(f"[apk] IDA not available for dynamic JNI ({e}); static only")
            ida = None
    if abi_libs and methods:
        res = jni_map.run_multi([l["extracted_path"] for l in abi_libs], methods, ida=ida)
        print(f"[apk] A.3 JNI map ({primary_abi}, {len(abi_libs)} lib(s)): "
              f"static={res['static']} dynamic={res['dynamic']} "
              f"unresolved={res['unresolved']}")

    # A.2b input-flow / controllability (only fuzz natives we can drive)
    if methods and ctx.get("dex_paths"):
        exported_classes = {"L" + e["name"].replace(".", "/") + ";"
                            for e in ex["entry_points"] if e.get("exported")}
        print("[apk] A.2b taint/reachability (dexdump call-graph) ...")
        fres = flow.run(ctx["dex_paths"], methods, exported_classes)
        print(f"[apk] controllable natives: {fres['controllable']} "
              f"(of {len(methods)}; {fres['methods_parsed']} java methods parsed)")

    # 4. persist to KB
    with KB(_kb_path(package)) as kb:
        aid = kb.upsert_apk(
            package=package, path=apk_path, sha256=ex["sha256"],
            version_name=ex["meta"]["version_name"],
            version_code=ex["meta"]["version_code"],
            min_sdk=ex["meta"]["min_sdk"], target_sdk=ex["meta"]["target_sdk"],
            launchable_activity=ex["meta"]["launchable_activity"],
            abis=ex["abis"], abi_plan=ex["abi_plan"],
            meta={"jadx_out": ctx["jadx_out"], "loaded_libraries": ctx["loaded_libraries"]})
        kb.clear_apk_children(aid)   # idempotent re-ingest
        kb.add_native_libs(aid, ex["native_libs"])
        kb.add_entry_points(aid, ex["entry_points"])
        kb.add_native_methods(aid, methods)
        for m in methods:
            flow_info = {
                "controllable": m.get("controllable", False),
                "reachable": m.get("reachable", False),
                "controlled_args": m.get("controlled_args", []),
                "sources": m.get("flow_sources", []),
                "n_callsites": m.get("n_callsites", 0),
            }
            kb.update_native_method(
                aid, m["java_class"], m["java_method"],
                native_symbol=m.get("native_symbol"),
                native_addr=m.get("native_addr"),
                registration=m.get("registration", "unresolved"),
                source_args=json.dumps(flow_info))
        summary = kb.summarize_apk(aid)
    _print_apk_summary(summary)
    return 0


def _print_apk_summary(s: dict) -> None:
    print("\n=== APK ===")
    print(f"  {s['package']}  v{s['version']}  minSdk={s['min_sdk']} "
          f"targetSdk={s['target_sdk']}")
    print(f"  launch: {s['launchable_activity']}")
    print(f"  abis: {s['abis']}")
    print(f"  abi plan: {s['abi_plan']}")
    print(f"  counts: {s['counts']}")
    print("=== Exported entry points ===")
    for e in s["exported_entry_points"][:20]:
        print(f"  [{e['component_type']}] {e['name']}")
    if not s["exported_entry_points"]:
        print("  (none)")
    print("=== Native methods (JNI)  [ranked: controllable first] ===")
    for m in s["native_methods"]:
        sym = m["native_symbol"] or "(unresolved)"
        fl = m.get("flow", {})
        if fl.get("controllable"):
            tag = f"CONTROLLABLE arg{fl.get('controlled_args')} <- {fl.get('sources')}"
        elif fl.get("reachable"):
            tag = "reachable (args not attacker-controlled)"
        else:
            tag = "not reachable from exported entry"
        args = ",".join(m.get("arg_types", []))
        print(f"  [{m['registration']:7s}] {m['java_class']}.{m['java_method']}({args})")
        print(f"            -> {sym} @ {m.get('native_addr')}  | {tag}")
    fuzz = [m for m in s["native_methods"] if m.get("flow", {}).get("controllable")]
    print(f"=== Fuzz targets (controllable): {len(fuzz)} ===")
    for m in fuzz:
        print(f"  {m['java_class']}.{m['java_method']}  arg(s)={m['flow']['controlled_args']} "
              f"sym={m['native_symbol']}")


def cmd_fuzzrun(args) -> int:
    """Container-side worker: fuzz + triage the controllable natives -> findings."""
    from . import hunt
    s = hunt.fuzzrun(TARGETS_DIR, ROOTFS, args.name, budget_s=args.budget,
                     use_angr=args.angr, fuzz_all=getattr(args, "fuzz_all", False))
    print(hunt.render_report(s))
    return 0


def cmd_brain(args) -> int:
    """Offline-brain helper: list pending agent prompts, answer one, or clear.

    Point VRA_OFFLINE_DIR at a dir, run `vra plan`/`vra agent`, then the model
    steps that aren't answered yet land here. Answer each (write its JSON object)
    and re-run — the loop completes identically to the API path."""
    from .agent import offline
    bdir = args.dir or os.environ.get("VRA_OFFLINE_DIR") or os.path.join(PROJECT_ROOT, "brain")
    if args.clear:
        print(f"cleared {offline.clear_pending(bdir)} pending prompt(s)")
        return 0
    if args.answer:
        with open(args.file) as fh:
            obj = json.load(fh)
        offline.answer(bdir, args.answer, obj)
        print(f"answered {args.answer}")
        return 0
    pend = offline.list_pending(bdir)
    print(f"[brain] dir={bdir}  pending={len(pend)}")
    for p in pend:
        mode = next((ln for ln in p["system"].splitlines() if "MODE:" in ln), "")
        req = p["schema"].get("required", [])
        print(f"\n  --- {p['key']}  {mode.strip()}")
        print(f"      required: {req}")
        print("      " + p["user"][:300].replace("\n", "\n      "))
    return 0


def cmd_insitu(args) -> int:
    """In-situ Frida fuzz of one native on a booted device/emulator (real JNIEnv).

    Stages the extracted .so into the app's code_cache (SELinux-mappable), loads
    it with frida, resolves the symbol, and drives it with mutated inputs. Needs
    the emulator booted with a matching frida-server and the app installed."""
    from .fuzz.frida_harness import fuzz_in_situ, stage_lib
    from .fuzz.seeds import seeds as mk_seeds
    host_so = os.path.join(TARGETS_DIR, args.name, "libs", args.abi, args.so)
    if not os.path.isfile(host_so):
        print(f"error: no extracted lib at {host_so} (run `vra apk` first)",
              file=sys.stderr)
        return 2
    print(f"[insitu] staging {args.so} into {args.name} code_cache ...")
    device_so = stage_lib(args.name, host_so)
    sd = mk_seeds(host_so)
    print(f"[insitu] {args.name} {args.symbol} ({args.arg}) via frida, "
          f"{args.execs} execs — device_so={device_so}")
    res = fuzz_in_situ(args.name, device_so, args.symbol, sd,
                       arg_kind=args.arg, execs=args.execs)
    print(f"[insitu] execs={res.execs}  {res.note}")
    if not res.crashes:
        print("  no in-situ faults (native stayed alive on all inputs)")
    for c in res.crashes:
        print(f"  CRASH pc={c.fault.get('pc')} addr={c.fault.get('address')} "
              f"type={c.fault.get('type')}  input={c.input[:48].hex()}")
    return 0


def cmd_hunt(args) -> int:
    """End-to-end: Phase A on host, then fuzz+triage in the vra-fuzz container."""
    apk_path = os.path.abspath(args.apk)
    if not os.path.isfile(apk_path):
        print(f"error: no such file {apk_path}", file=sys.stderr)
        return 2
    print("[hunt] === Phase A (host): extract / jadx / jni / flow ===")
    rc = cmd_apk(argparse.Namespace(apk=apk_path, no_jadx=args.no_jadx, ida=False))
    if rc != 0:
        return rc
    pkg = apk_extract.badging(apk_path)["package"] or \
        os.path.splitext(os.path.basename(apk_path))[0]
    docker = shutil.which("docker") or "/usr/local/bin/docker"
    print(f"\n[hunt] === Phase 4/5 (container): fuzz + triage {pkg} ===")
    cmd = [docker, "run", "--rm", "-v", f"{PROJECT_ROOT}:/work", "-e", "PYTHONPATH=/work",
           "-w", "/work", FUZZ_IMAGE, "python3", "-m", "vra", "_fuzzrun",
           "--name", pkg, "--budget", str(args.budget)]
    if args.angr:
        cmd.append("--angr")
    rc = subprocess.run(cmd).returncode
    # host-side IDA Hex-Rays enrichment (if the .so is open in IDA)
    from . import hunt
    from .android import ida_decompile
    with KB(_kb_path(pkg)) as kb:
        aid = kb.get_apk(package=pkg)["id"]
        msg = ida_decompile.enrich_findings(kb, aid, pkg, TARGETS_DIR)
        print(f"\n[hunt] {msg}")
        if msg.startswith("IDA enrichment"):
            print(hunt.report_from_kb(kb, aid))
    return rc


def cmd_agent(args) -> int:
    """Full autonomous agent: ingest -> (LLM) plan -> fuzz/triage -> (LLM) assess."""
    from .agent import loop
    apk_path = os.path.abspath(args.apk)
    if not os.path.isfile(apk_path):
        print(f"error: no such file {apk_path}", file=sys.stderr)
        return 2
    print("[agent] === Phase A: ingest ===")
    if cmd_apk(argparse.Namespace(apk=apk_path, no_jadx=args.no_jadx, ida=False)) != 0:
        return 1
    pkg = apk_extract.badging(apk_path)["package"]
    print("\n[agent] === understanding + research strategy ===")
    with KB(_kb_path(pkg)) as kb:
        aid = kb.get_apk(package=pkg)["id"]
        plan = loop.plan_phase(kb, aid)
    print(loop.render(plan, {}))
    print("\n[agent] === fuzz + triage (container) ===")
    docker = shutil.which("docker") or "/usr/local/bin/docker"
    cmd = [docker, "run", "--rm", "-v", f"{PROJECT_ROOT}:/work", "-e", "PYTHONPATH=/work",
           "-w", "/work", FUZZ_IMAGE, "python3", "-m", "vra", "_fuzzrun",
           "--name", pkg, "--budget", str(args.budget), "--angr"]
    subprocess.run(cmd)
    from .android import ida_decompile
    with KB(_kb_path(pkg)) as kb:
        aid = kb.get_apk(package=pkg)["id"]
        print("\n[agent] === IDA Hex-Rays root-cause enrichment ===")
        print("[agent] " + ida_decompile.enrich_findings(kb, aid, pkg, TARGETS_DIR))
        assessment = loop.assess_findings(kb, aid)
    if assessment:
        print("\n" + loop.render({"strategy": None, "structure": {}}, assessment)
              .split("===", 1)[-1])
    return 0


def cmd_plan(args) -> int:
    name = args.name
    if not name:
        # default to the first APK-type target dir with an apks row
        for cand in sorted(os.listdir(TARGETS_DIR)) if os.path.isdir(TARGETS_DIR) else []:
            with KB(_kb_path(cand)) as kb:
                if kb.get_apk():
                    name = cand
                    break
    if not name:
        print("no APK ingested yet; run `vra apk <file>` first", file=sys.stderr)
        return 1

    with KB(_kb_path(name)) as kb:
        apk = kb.get_apk(package=name) or kb.get_apk()
        if not apk:
            print(f"no APK in KB for '{name}'", file=sys.stderr)
            return 1
        aid = apk["id"]
        structure = appmodel.build_structure(kb, aid)
        kb.set_app_model(aid, "structure", structure)
        print(appmodel.render(structure))

        if args.no_llm:
            print("\n(--no-llm: skipped LLM understanding/strategy)")
            return 0
        if not agent_llm.available():
            print("\n[plan] LLM not available — set ANTHROPIC_API_KEY (or write it "
                  "to ./.anthropic_key) to generate understanding + strategy.",
                  file=sys.stderr)
            return 0
        print("\n[plan] asking the model to understand the app + plan research ...")
        try:
            lm = agent_llm.LLM()
            result = strategy.strategize(lm, structure)
        except agent_llm.LLMUnavailable as e:
            print(f"[plan] LLM error: {e}", file=sys.stderr)
            return 2
        kb.set_app_model(aid, "understanding", result.get("app_understanding", {}))
        kb.set_research_plan(aid, result.get("research_plan", {}), lm.model)
        print("\n" + strategy.render_plan(result))
    return 0


def cmd_show(args) -> int:
    name = args.name or _first_target_name()
    if not name:
        print("no targets yet", file=sys.stderr)
        return 1
    with KB(_kb_path(name)) as kb:
        t = kb.get_target(name=name)
        if not t:
            print(f"no target '{name}'", file=sys.stderr)
            return 1
        _print_summary(kb.summarize(t["id"]))
    return 0


def cmd_targets(args) -> int:
    if not os.path.isdir(TARGETS_DIR):
        print("(none)")
        return 0
    for name in sorted(os.listdir(TARGETS_DIR)):
        p = _kb_path(name)
        if os.path.isfile(p):
            with KB(p) as kb:
                t = kb.get_target(name=name)
                if t:
                    print(f"{name:30s} {t['fmt']}/{t['arch']}  {t['sha256'][:12]}")
    return 0


def _first_target_name():
    if not os.path.isdir(TARGETS_DIR):
        return None
    for name in sorted(os.listdir(TARGETS_DIR)):
        if os.path.isfile(_kb_path(name)):
            return name
    return None


def _print_summary(s: dict) -> None:
    t = s["target"]
    print("\n=== Target ===")
    print(f"  {t['name']}  {t['fmt']}/{t['arch']} ({t['bits']}-bit) "
          f"source={t['source_available']}")
    print(f"  mitigations: {t['mitigations']}")
    print("=== Counts ===")
    print(f"  {s['counts']}")
    print(f"=== Surfaces by category ===\n  {s['surfaces_by_category']}")
    print("=== Top surfaces (deterministic prior ranking) ===")
    if not s["top_surfaces"]:
        print("  (none found)")
    for r in s["top_surfaces"]:
        flag = "<-input" if r["reads_input_source"] else ""
        print(f"  [{r['base_score']:3d}] {r['sink']:14s} {r['sink_category']:9s} "
              f"in {r['func_name']} @ {r['func_addr']} {flag}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="vra", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    pn = sub.add_parser("new", help="intake a binary file")
    pn.add_argument("binary")
    pn.add_argument("--name")
    pn.add_argument("--source", action="store_true", help="source available")
    pn.set_defaults(func=cmd_new)

    ps = sub.add_parser("surface", help="map attack surface of IDA-loaded binary")
    ps.add_argument("--name")
    ps.add_argument("--source", action="store_true")
    ps.add_argument("--max-lines", type=int, default=1500,
                    dest="max_lines", help="decompilation cap per surface func")
    ps.set_defaults(func=cmd_surface)

    pa = sub.add_parser("apk", help="Phase A: ingest an APK (extract/jadx/jni)")
    pa.add_argument("apk")
    pa.add_argument("--no-jadx", action="store_true",
                    help="skip jadx decompile (dexdump only, faster)")
    pa.add_argument("--ida", action="store_true",
                    help="use live IDA for dynamic RegisterNatives resolution")
    pa.set_defaults(func=cmd_apk)

    ph = sub.add_parser("hunt", help="end-to-end: ingest APK, fuzz controllable natives, triage")
    ph.add_argument("apk")
    ph.add_argument("--budget", type=float, default=30.0, help="seconds per target")
    ph.add_argument("--no-jadx", action="store_true")
    ph.add_argument("--angr", action="store_true", help="concolic hand-off on plateau")
    ph.set_defaults(func=cmd_hunt)

    pf = sub.add_parser("_fuzzrun", help="(internal) container-side fuzz+triage worker")
    pf.add_argument("--name", required=True)
    pf.add_argument("--budget", type=float, default=30.0)
    pf.add_argument("--angr", action="store_true")
    pf.add_argument("--fuzz-all", action="store_true", dest="fuzz_all",
                    help="drive every data-bearing arg, not just proven-controllable")
    pf.set_defaults(func=cmd_fuzzrun)

    pi = sub.add_parser("insitu", help="experimental: in-situ Frida fuzz of one "
                        "native on a booted device/emulator (real JNIEnv/libc)")
    pi.add_argument("--name", required=True, help="app package")
    pi.add_argument("--so", required=True, help="library file name, e.g. libfoo.so")
    pi.add_argument("--symbol", required=True, help="native export, e.g. Java_...")
    pi.add_argument("--arg", choices=["bytearray", "string"], default="bytearray")
    pi.add_argument("--abi", default="arm64-v8a", help="abi dir under targets/<pkg>/libs")
    pi.add_argument("--execs", type=int, default=2000)
    pi.set_defaults(func=cmd_insitu)

    pag = sub.add_parser("agent", help="§8 full autonomous agent: plan + hunt + assess")
    pag.add_argument("apk")
    pag.add_argument("--budget", type=float, default=25.0)
    pag.add_argument("--no-jadx", action="store_true")
    pag.set_defaults(func=cmd_agent)

    pp = sub.add_parser("plan", help="§8 agent: map app structure + research strategy")
    pp.add_argument("--name", help="target package (default: first ingested APK)")
    pp.add_argument("--no-llm", action="store_true",
                    help="only build the deterministic structure map")
    pp.set_defaults(func=cmd_plan)

    pb = sub.add_parser("brain", help="offline-brain: list/answer/clear pending "
                        "agent prompts (Claude Code answers instead of the API)")
    pb.add_argument("--dir", help="brain dir (default $VRA_OFFLINE_DIR or ./brain)")
    pb.add_argument("--answer", metavar="KEY", help="store an answer for KEY")
    pb.add_argument("--file", help="JSON file with the answer object (with --answer)")
    pb.add_argument("--clear", action="store_true", help="delete pending prompts")
    pb.set_defaults(func=cmd_brain)

    psh = sub.add_parser("show", help="print KB summary")
    psh.add_argument("--name")
    psh.set_defaults(func=cmd_show)

    pt = sub.add_parser("targets", help="list known targets")
    pt.set_defaults(func=cmd_targets)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
