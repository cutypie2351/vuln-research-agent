"""Phase A.1 — APK intake + native extraction (§10 A.1).

Extracts native `.so` per ABI, derives the ABI fuzzing plan, and parses the
manifest (via aapt2) for the attacker-controlled entry points (exported
components, deep links). Deterministic facts only — the model later reasons
over the Java flow to connect an entry point to a native argument.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import zipfile
from typing import Optional

from .. import env

TARGET_ABIS = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]
COMPONENTS = {"activity", "activity-alias", "service", "receiver", "provider"}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def plan_abis(abis: list[str]) -> list[dict]:
    """ABI fuzzing strategy (§10 A.1). On an Intel host x86_64 runs fastest;
    arm64 goes through emulation (qiling/qemu) for ABI-specific bugs."""
    have = set(abis)
    plan: list[dict] = []
    if "x86_64" in have:
        plan.append({"abi": "x86_64", "mode": "native-host"})
    elif "x86" in have:
        plan.append({"abi": "x86", "mode": "native-host"})
    if "arm64-v8a" in have:
        plan.append({"abi": "arm64-v8a", "mode": "qemu-or-qiling"})
    elif "armeabi-v7a" in have:
        plan.append({"abi": "armeabi-v7a", "mode": "qemu-or-qiling"})
    return plan


def extract_native(apk_path: str, out_dir: str) -> list[dict]:
    """Extract every lib/<abi>/*.so to out_dir/<abi>/<name>."""
    libs: list[dict] = []
    with zipfile.ZipFile(apk_path) as z:
        for info in z.infolist():
            n = info.filename
            m = re.match(r"lib/([^/]+)/(.+\.so)$", n)
            if not m:
                continue
            abi, name = m.group(1), os.path.basename(m.group(2))
            dst_dir = os.path.join(out_dir, abi)
            os.makedirs(dst_dir, exist_ok=True)
            dst = os.path.join(dst_dir, name)
            with z.open(info) as src, open(dst, "wb") as fh:
                fh.write(src.read())
            libs.append({"abi": abi, "name": name, "rel_path": n,
                         "extracted_path": dst, "sha256": _sha256(dst),
                         "is_target": 1})
    return libs


# -- aapt2 badging ----------------------------------------------------------
def badging(apk_path: str) -> dict:
    aapt2 = env.require("aapt2", env.aapt2())
    out = subprocess.run([aapt2, "dump", "badging", apk_path],
                         capture_output=True, text=True, env=env.java_env()).stdout
    meta: dict = {"package": None, "version_name": None, "version_code": None,
                  "min_sdk": None, "target_sdk": None, "launchable_activity": None,
                  "native_code": []}
    m = re.search(r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'", out)
    if m:
        meta["package"], meta["version_code"], meta["version_name"] = m.groups()
    m = re.search(r"sdkVersion:'(\d+)'", out)
    if m:
        meta["min_sdk"] = int(m.group(1))
    m = re.search(r"targetSdkVersion:'(\d+)'", out)
    if m:
        meta["target_sdk"] = int(m.group(1))
    m = re.search(r"launchable-activity: name='([^']+)'", out)
    if m:
        meta["launchable_activity"] = m.group(1)
    m = re.search(r"native-code: (.+)", out)
    if m:
        meta["native_code"] = re.findall(r"'([^']+)'", m.group(1))
    return meta


# -- manifest xmltree -> entry points --------------------------------------
_RE_ELEM = re.compile(r"^(\s*)E: ([\w\-]+)")
# Attribute names can be namespaced URLs (http://.../android:name) and carry a
# (0x..) resource-id suffix before '='. Capture the full name, strip to local.
_RE_ATTR = re.compile(r'^(\s*)A: (\S+?)(?:\(0x[0-9A-Fa-f]+\))?=(.*)$')


def _attr_val(raw: str) -> str:
    raw = raw.strip()
    m = re.search(r'"(.*)"\s*(?:\(Raw:.*)?$', raw)
    if m:
        return m.group(1)
    return raw


def _truthy(v: str) -> bool:
    v = v.strip().lower()
    return v in ("true", "0xffffffff", "-1") or v.endswith("0xffffffff")


def parse_manifest(apk_path: str) -> list[dict]:
    """Parse exported components + deep-link schemes from the binary manifest."""
    aapt2 = env.require("aapt2", env.aapt2())
    out = subprocess.run(
        [aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", apk_path],
        capture_output=True, text=True, env=env.java_env()).stdout

    # Build a lightweight element stack by indentation depth.
    stack: list[dict] = []   # each: {tag, depth, attrs:{}, has_filter, schemes:[], actions:[]}
    comps: list[dict] = []

    def close_to(depth: int):
        while stack and stack[-1]["depth"] >= depth:
            el = stack.pop()
            _attach(el)

    def _attach(el: dict):
        # propagate intent-filter info up to the nearest component
        if el["tag"] == "intent-filter":
            for anc in reversed(stack):
                if anc["tag"] in COMPONENTS:
                    anc["has_filter"] = True
                    anc["actions"].extend(el["actions"])
                    anc["schemes"].extend(el["schemes"])
                    break
        elif el["tag"] in COMPONENTS:
            comps.append(el)

    for line in out.splitlines():
        em = _RE_ELEM.match(line)
        if em:
            depth = len(em.group(1))
            close_to(depth)
            stack.append({"tag": em.group(2), "depth": depth, "attrs": {},
                          "has_filter": False, "schemes": [], "actions": []})
            continue
        am = _RE_ATTR.match(line)
        if am and stack:
            name = am.group(2).split(":")[-1]
            val = _attr_val(am.group(3))
            top = stack[-1]
            top["attrs"][name] = val
            if top["tag"] == "action" and name == "name":
                # attach to enclosing intent-filter
                for anc in reversed(stack):
                    if anc["tag"] == "intent-filter":
                        anc["actions"].append(val)
                        break
            if top["tag"] == "data" and name in ("scheme", "host"):
                for anc in reversed(stack):
                    if anc["tag"] == "intent-filter":
                        anc["schemes"].append(val)
                        break
    close_to(-1)

    eps: list[dict] = []
    for el in comps:
        attrs = el["attrs"]
        name = attrs.get("name", "")
        exported_attr = attrs.get("exported")
        if exported_attr is not None:
            exported = _truthy(exported_attr)
        else:
            # pre-S default: exported iff it declares an intent-filter
            exported = el["has_filter"]
        eps.append({
            "component_type": el["tag"].replace("-alias", ""),
            "name": name,
            "exported": int(exported),
            "permission": attrs.get("permission"),
            "intent_filters": sorted(set(el["actions"])),
            "schemes": sorted(set(s for s in el["schemes"] if s)),
        })
    return eps


def run(apk_path: str, out_dir: str) -> dict:
    """Full Phase A.1: returns apk meta + native_libs + entry_points + abi_plan."""
    os.makedirs(out_dir, exist_ok=True)
    meta = badging(apk_path)
    libs = extract_native(apk_path, os.path.join(out_dir, "libs"))
    abis = sorted({l["abi"] for l in libs}) or meta.get("native_code", [])
    eps = parse_manifest(apk_path)
    pkg = meta.get("package") or ""
    for e in eps:                      # expand relative component names (.Foo -> pkg.Foo)
        if e["name"].startswith("."):
            e["name"] = pkg + e["name"]
        elif "." not in e["name"] and pkg:
            e["name"] = pkg + "." + e["name"]
    return {
        "apk_path": os.path.abspath(apk_path),
        "sha256": _sha256(apk_path),
        "meta": meta,
        "abis": abis,
        "abi_plan": plan_abis(abis),
        "native_libs": libs,
        "entry_points": eps,
    }
