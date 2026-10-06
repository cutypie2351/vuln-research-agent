"""Phase A.2 — App context via jadx + dexdump (§10 A.2).

Two jobs:
  - dexdump: authoritative enumeration of `native` methods (class, name, exact
    JNI descriptor, arg types). This is the deterministic ground truth.
  - jadx: decompile DEX -> Java so the model can later trace the input flow
    (intent/provider/file -> which byte[]/String reaches which native arg).
    We also grep the sources for System.loadLibrary() to map methods to libs.

The model's value-add (connecting a manifest entry point to a native argument)
happens later over the jadx output; here we only extract facts.
"""
from __future__ import annotations

import glob
import os
import re
import subprocess
import zipfile
from typing import Optional

from .. import env

# JNI type descriptor -> readable
_JNI_PRIM = {"Z": "boolean", "B": "byte", "C": "char", "S": "short",
             "I": "int", "J": "long", "F": "float", "D": "double", "V": "void"}


def parse_descriptor(desc: str) -> tuple[list[str], str]:
    """'([BLjava/lang/String;)Z' -> (['byte[]','String'], 'boolean')."""
    args: list[str] = []
    i = desc.index("(") + 1
    end = desc.index(")")
    body, ret = desc[i:end], desc[end + 1:]

    def one(s: str, p: int) -> tuple[str, int]:
        arr = 0
        while s[p] == "[":
            arr += 1
            p += 1
        if s[p] == "L":
            e = s.index(";", p)
            t = s[p + 1:e].split("/")[-1]
            p = e + 1
        else:
            t = _JNI_PRIM.get(s[p], s[p])
            p += 1
        return t + "[]" * arr, p

    p = 0
    while p < len(body):
        t, p = one(body, p)
        args.append(t)
    rt, _ = one(ret, 0) if ret else ("void", 0)
    return args, rt


def extract_dex(apk_path: str, out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    with zipfile.ZipFile(apk_path) as z:
        for info in z.infolist():
            if re.match(r"classes\d*\.dex$", info.filename):
                dst = os.path.join(out_dir, info.filename)
                with z.open(info) as s, open(dst, "wb") as f:
                    f.write(s.read())
                paths.append(dst)
    return paths


def native_methods_from_dex(dex_paths: list[str]) -> list[dict]:
    """Parse dexdump -f output for methods with the NATIVE access flag."""
    dexdump = env.require("dexdump", env.dexdump())
    methods: list[dict] = []
    for dex in dex_paths:
        out = subprocess.run([dexdump, "-f", dex], capture_output=True,
                             text=True, encoding="utf-8", errors="replace").stdout
        cur_class: Optional[str] = None
        name = typ = access = None
        for line in out.splitlines():
            s = line.strip()
            if s.startswith("Class descriptor"):
                m = re.search(r"'L(.+);'", s)
                cur_class = m.group(1).replace("/", ".") if m else None
            elif s.startswith("name "):
                name = _qval(s)
            elif s.startswith("type "):
                typ = _qval(s)
            elif s.startswith("access "):
                access = s
                if typ and name and cur_class and "NATIVE" in access and "(" in (typ or ""):
                    try:
                        args, ret = parse_descriptor(typ)
                    except Exception:
                        args, ret = [], "?"
                    methods.append({
                        "java_class": cur_class, "java_method": name,
                        "jni_signature": typ, "arg_types": args, "ret_type": ret,
                    })
                name = typ = access = None
    # dedup
    seen = set()
    uniq = []
    for m in methods:
        k = (m["java_class"], m["java_method"], m["jni_signature"])
        if k not in seen:
            seen.add(k)
            uniq.append(m)
    return uniq


def _qval(line: str) -> Optional[str]:
    m = re.search(r":\s*'(.*)'", line)
    return m.group(1) if m else None


def run_jadx(apk_path: str, out_dir: str, timeout: int = 420) -> Optional[str]:
    """Decompile to Java for later model reasoning. Best-effort."""
    jadx = env.jadx()
    if not jadx:
        return None
    src = os.path.join(out_dir, "jadx")
    os.makedirs(src, exist_ok=True)
    try:
        subprocess.run([jadx, "--no-res", "-d", src, apk_path],
                       capture_output=True, text=True, env=env.java_env(),
                       timeout=timeout)
    except subprocess.TimeoutExpired:
        pass  # partial output is still useful
    return src if os.path.isdir(os.path.join(src, "sources")) else src


def loaded_libraries(jadx_src: Optional[str]) -> list[str]:
    """Grep decompiled Java for System.loadLibrary("x") -> ['x']."""
    libs: set[str] = set()
    if not jadx_src or not os.path.isdir(jadx_src):
        return []
    for root, _, files in os.walk(jadx_src):
        for fn in files:
            if not fn.endswith(".java"):
                continue
            try:
                with open(os.path.join(root, fn), "r", errors="ignore") as fh:
                    txt = fh.read()
            except OSError:
                continue
            for m in re.finditer(r'loadLibrary\s*\(\s*"([^"]+)"', txt):
                libs.add(m.group(1))
    return sorted(libs)


def run(apk_path: str, out_dir: str, do_jadx: bool = True) -> dict:
    dex_dir = os.path.join(out_dir, "dex")
    dex_paths = extract_dex(apk_path, dex_dir)
    methods = native_methods_from_dex(dex_paths)
    jadx_src = run_jadx(apk_path, out_dir) if do_jadx else None
    libs = loaded_libraries(jadx_src)
    # If exactly one native library is loaded, attribute methods to it.
    sole = libs[0] if len(libs) == 1 else None
    for m in methods:
        m["native_lib"] = sole
        m["registration"] = "unresolved"
    return {
        "dex_paths": dex_paths,
        "jadx_out": jadx_src,
        "loaded_libraries": libs,
        "native_methods": methods,
    }
