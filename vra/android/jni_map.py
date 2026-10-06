"""Phase A.3 — JNI mapping: Java native method <-> native address (§10 A.3).

Two registration styles (both must be handled):
  - Static: symbol name encodes class+method (Java_pkg_Class_method). Resolve by
    reconstructing the mangled symbol and looking it up in the .so exports.
  - Dynamic: JNI_OnLoad calls RegisterNatives({name, sig, fnPtr}[]). The symbol
    table has no Java_* names, so we recover the table via IDA MCP, anchored on
    the method-name strings we already know from the DEX.

Static resolution needs only the .so file (nm/lief). Dynamic needs the .so
loaded in the live IDA instance.
"""
from __future__ import annotations

import re
import subprocess
from typing import Optional

from .. import env


# -- JNI name mangling (static) --------------------------------------------
def _mangle(s: str, is_class: bool) -> str:
    if is_class:
        s = s.replace(".", "/")
    out = []
    for ch in s:
        if ch in "/.":
            out.append("_")
        elif ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        elif ch.isalnum():
            out.append(ch)
        else:
            out.append("_0%04x" % ord(ch))
    return "".join(out)


def jni_symbol(java_class: str, java_method: str,
               overload_args: Optional[str] = None) -> str:
    base = "Java_" + _mangle(java_class, True) + "_" + _mangle(java_method, False)
    if overload_args is not None:
        base += "__" + _mangle(overload_args, False)
    return base


def exported_symbols(lib_path: str) -> dict[str, str]:
    """name -> '0x<addr>' for defined (exported) symbols. nm reads ELF on macOS."""
    syms: dict[str, str] = {}
    try:
        out = subprocess.run(["nm", "-D", lib_path], capture_output=True,
                             text=True, timeout=120).stdout
    except Exception:
        out = ""
    for line in out.splitlines():
        m = re.match(r"^([0-9a-fA-F]+)\s+[TtWwBbDd]\s+(\S+)$", line.strip())
        if m:
            syms[m.group(2)] = "0x" + m.group(1).lstrip("0").rjust(1, "0")
    if syms:
        return syms
    # fallback: lief
    try:
        import lief  # type: ignore
        b = lief.parse(lib_path)
        for s in getattr(b, "dynamic_symbols", []) or b.symbols:
            if s.name and getattr(s, "value", 0):
                syms[s.name] = hex(s.value)
    except Exception:
        pass
    return syms


def _lib_shortname(lib_path: str) -> str:
    base = lib_path.rsplit("/", 1)[-1]
    if base.startswith("lib"):
        base = base[3:]
    if base.endswith(".so"):
        base = base[:-3]
    return base


def resolve_static(lib_path: str, methods: list[dict]) -> int:
    """Fill native_symbol/native_addr/registration for statically-bound methods."""
    syms = exported_symbols(lib_path)
    lib_short = _lib_shortname(lib_path)
    resolved = 0
    for m in methods:
        short = jni_symbol(m["java_class"], m["java_method"])
        hit = short if short in syms else None
        if not hit:
            sig = m.get("jni_signature", "")
            if "(" in sig and ")" in sig:
                args = sig[sig.index("(") + 1:sig.index(")")]
                long = jni_symbol(m["java_class"], m["java_method"], args)
                hit = long if long in syms else None
        if hit:
            m["native_symbol"] = hit
            m["native_addr"] = syms[hit]
            m["registration"] = "static"
            if not m.get("native_lib"):
                m["native_lib"] = lib_short
            resolved += 1
    return resolved


# -- Dynamic RegisterNatives recovery via IDA MCP ---------------------------
def resolve_dynamic_via_ida(ida, methods: list[dict], *, verbose: bool = True) -> int:
    """String-anchored recovery of dynamically-registered natives.

    Technique: each JNINativeMethod entry is {char* name, char* sig, void* fn}.
    We locate the method-name string in the .so, find the data xref to it (the
    `name` field), then read the two pointers that follow to get the signature
    string and the function pointer.

    Requires the target .so to be the binary currently loaded in IDA. Validated
    against a RegisterNatives target (e.g. UnCrackable-Level4); for statically
    bound targets this is a no-op because resolve_static already matched.
    """
    log = (lambda *a: print("[jni_map:dyn]", *a)) if verbose else (lambda *a: None)
    ptr = 8  # 64-bit; dynamic libs on Android are LP64 for arm64-v8a/x86_64
    resolved = 0
    for m in methods:
        if m.get("registration") == "static" or m.get("native_addr"):
            continue
        name = m["java_method"]
        try:
            hits = ida.call("search_text", pattern=name, limit=20, regex=False)
        except Exception as e:
            log(f"search failed for {name}: {e}")
            continue
        for h in (hits.get("data", []) if isinstance(hits, dict) else hits) or []:
            saddr = h.get("addr") if isinstance(h, dict) else None
            if not saddr:
                continue
            # data xref to the string = candidate `name` field of the struct
            try:
                xr = ida.call("xrefs_to", addrs=saddr, limit=20)
            except Exception:
                continue
            for group in (xr if isinstance(xr, list) else [xr]):
                for ref in group.get("xrefs", []):
                    if ref.get("type") not in ("data", None):
                        continue
                    entry = ref.get("addr")
                    try:
                        sig_ptr = ida.call("get_int", addr=_add(entry, ptr), size=ptr)
                        fn_ptr = ida.call("get_int", addr=_add(entry, 2 * ptr), size=ptr)
                    except Exception:
                        continue
                    fn = _as_hex(fn_ptr)
                    if fn:
                        m["native_addr"] = fn
                        m["registration"] = "dynamic"
                        sig = _read_cstr(ida, _as_hex(sig_ptr))
                        if sig:
                            m["jni_signature"] = sig
                        resolved += 1
                        log(f"{m['java_class']}.{name} -> fn {fn}")
                        break
                if m.get("native_addr"):
                    break
            if m.get("native_addr"):
                break
    return resolved


def _add(addr: str, off: int) -> str:
    return hex(int(str(addr), 16) + off)


def _as_hex(v) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, dict):
        v = v.get("value", v.get("result"))
    try:
        n = int(str(v), 0)
        return hex(n) if n else None
    except (ValueError, TypeError):
        return None


def _read_cstr(ida, addr: Optional[str]) -> Optional[str]:
    if not addr:
        return None
    try:
        r = ida.call("get_string", addrs=addr)
        if isinstance(r, list) and r:
            r = r[0]
        if isinstance(r, dict):
            return r.get("value") or r.get("string")
        return r if isinstance(r, str) else None
    except Exception:
        return None


def run(target_lib_path: str, methods: list[dict], ida=None,
        verbose: bool = True) -> dict:
    """Resolve methods against one native lib (static first, then dynamic/IDA)."""
    return run_multi([target_lib_path], methods, ida=ida, verbose=verbose)


def run_multi(lib_paths: list, methods: list[dict], ida=None,
              verbose: bool = True) -> dict:
    """Resolve methods against EVERY native lib for the ABI (a real app ships
    several .so, and a method is a static export of exactly one of them). Each
    method is matched against each lib until it resolves; `resolve_static` stamps
    the owning `native_lib` so the fuzzer later loads the correct .so."""
    n_static = 0
    for lp in lib_paths:
        pending = [m for m in methods if not m.get("native_addr")]
        if not pending:
            break
        n_static += resolve_static(lp, pending)
    n_dynamic = 0
    unresolved = [m for m in methods if not m.get("native_addr")]
    if unresolved and ida is not None:
        n_dynamic = resolve_dynamic_via_ida(ida, unresolved, verbose=verbose)
    return {
        "static": n_static,
        "dynamic": n_dynamic,
        "unresolved": sum(1 for m in methods if not m.get("native_addr")),
        "total": len(methods),
    }
