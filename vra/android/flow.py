"""Phase A.2b — input-flow / controllability analysis (§10 A.2).

Enumerating native methods is not enough: we must only fuzz natives whose
arguments an attacker can actually control. This module answers, per native
method: is it REACHABLE from an exported entry point, and which arguments are
TAINTED by an attacker-controlled source?

Technique: a lightweight inter-procedural backward taint over Dalvik bytecode
(`dexdump -d`). For each native call site we take the register holding each
argument and walk backward to its definition:
  - const* / fill-array-data        -> CONSTANT        (not controllable)
  - iget/sget                       -> FIELD           (usually not)
  - move-result of a SOURCE api     -> SOURCE          (controllable)
  - move-result of a TRANSFORM      -> recurse into the transform's input
  - a method parameter register     -> recurse into the callers (inter-proc)
If any argument resolves to a source (or to the external parameter of an
exported component's lifecycle handler), the native is a real fuzz target.

Deterministic first pass; the model later refines arg-level taint + grammar
over the jadx Java. No heavy deps (androguard/cryptography) — just dexdump.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from .. import env

MAX_DEPTH = 8

# Attacker-controlled sources (substring match against the invoke ref).
SOURCES = (
    "Landroid/content/Intent;.getStringExtra", "Landroid/content/Intent;.getByteArrayExtra",
    "Landroid/content/Intent;.getIntExtra", "Landroid/content/Intent;.getLongExtra",
    "Landroid/content/Intent;.getExtras", "Landroid/content/Intent;.getData",
    "Landroid/content/Intent;.getParcelableExtra", "Landroid/content/Intent;.getSerializableExtra",
    "Landroid/content/Intent;.getCharSequenceExtra", "Landroid/content/Intent;.getBundleExtra",
    "Landroid/content/Intent;.getStringArrayExtra", "Landroid/content/Intent;.getDataString",
    "Landroid/os/Bundle;.get", "Landroid/os/BaseBundle;.get",
    "Landroid/net/Uri;.getQueryParameter", "Landroid/net/Uri;.getPathSegments",
    "Landroid/net/Uri;.getLastPathSegment", "Landroid/net/Uri;.getPath",
    "Landroid/widget/EditText;.getText", "Landroid/widget/TextView;.getText",
    "Ljava/io/InputStream;.read", "Ljava/io/BufferedReader;.readLine",
    "Ljava/io/FileInputStream;.read", "Ljava/io/DataInputStream;.read",
    "Landroid/content/ContentResolver;.openInputStream",
    "Ljava/net/URLConnection;.getInputStream", "Ljava/net/Socket;.getInputStream",
)

# Taint-preserving transforms: recurse into the receiver/first register.
TRANSFORMS = (
    ".getBytes:", ".toString:", ".toCharArray:", ".trim:", ".substring:",
    ".toByteArray:", ".clone:", ".copyOf:", ".copyOfRange:", ".append:",
    "Ljava/util/Base64$Decoder;.decode", "Landroid/util/Base64;.decode",
    "Ljava/lang/String;.valueOf:", "Ljava/lang/String;.<init>:",
)

# External-input parameters of exported component lifecycle handlers.
LIFECYCLE_EXTERNAL = {
    "onCreate", "onStart", "onStartCommand", "onNewIntent", "onReceive",
    "onHandleIntent", "onBind", "onRebind", "query", "insert", "update",
    "delete", "openFile", "call", "getType",
}
EXTERNAL_TYPES = ("Landroid/content/Intent;", "Landroid/os/Bundle;", "Landroid/net/Uri;")

_RE_INSN = re.compile(r"^\s*[0-9a-f]+:\s+[0-9a-f ]+\|([0-9a-f]+): (.+?)(?:\s+//.*)?$")
_RE_VREG = re.compile(r"v(\d+)")


@dataclass
class Insn:
    off: str
    mnemonic: str
    regs: list[int]
    ref: str          # Lclass;.method:(sig)ret  or field ref, or ""
    raw: str


@dataclass
class Method:
    key: str                     # Lclass;.name:(sig)ret
    cls: str
    name: str
    desc: str
    is_static: bool
    registers: int = 0
    ins: int = 0
    insns: list = field(default_factory=list)

    def param_regs(self) -> list[int]:
        """Register numbers holding incoming params (incl. `this`), in order."""
        start = self.registers - self.ins
        return list(range(start, self.registers))


class Dex:
    def __init__(self):
        self.methods: dict[str, Method] = {}
        self.callers: dict[str, list[tuple[str, int]]] = {}  # callee_key -> [(caller_key, insn_idx)]

    @classmethod
    def from_dexdump(cls, dex_paths: list[str]) -> "Dex":
        self = cls()
        dexdump = env.require("dexdump", env.dexdump())
        for dp in dex_paths:
            out = subprocess.run([dexdump, "-d", dp], capture_output=True,
                                 text=True, encoding="utf-8", errors="replace").stdout
            self._parse(out)
        self._build_callers()
        return self

    def _parse(self, out: str) -> None:
        cur_cls = None
        m: Optional[Method] = None
        pending = {}  # name/type/access/registers/ins while building a method
        for line in out.splitlines():
            s = line.strip()
            if s.startswith("Class descriptor"):
                mm = re.search(r"'(L.+;)'", s)
                cur_cls = mm.group(1) if mm else None
                continue
            if s.startswith("name "):
                pending = {"name": _q(s)}
                m = None
                continue
            if s.startswith("type ") and "name" in pending:
                pending["type"] = _q(s)
                continue
            if s.startswith("access ") and "type" in pending:
                pending["access"] = s
                continue
            if s.startswith("registers"):
                pending["registers"] = _num(s)
                continue
            if s.startswith("ins  ") or re.match(r"ins\s*:", s):
                pending["ins"] = _num(s)
                # method code starts; create Method
                if cur_cls and pending.get("name") and pending.get("type"):
                    key = f"{cur_cls}.{pending['name']}:{pending['type']}"
                    m = Method(key=key, cls=cur_cls, name=pending["name"],
                               desc=pending["type"],
                               is_static="STATIC" in pending.get("access", ""),
                               registers=pending.get("registers", 0),
                               ins=pending.get("ins", 0))
                    self.methods[key] = m
                continue
            im = _RE_INSN.match(line)
            if im and m is not None:
                text = im.group(2).strip()
                mnem = text.split(" ", 1)[0]
                regs = [int(x) for x in _RE_VREG.findall(_regs_part(text))]
                ref = _ref_part(text)
                m.insns.append(Insn(off=im.group(1), mnemonic=mnem, regs=regs,
                                    ref=ref, raw=text))

    def _build_callers(self) -> None:
        for key, m in self.methods.items():
            for i, ins in enumerate(m.insns):
                if ins.mnemonic.startswith("invoke") and ins.ref:
                    callee = _norm_ref(ins.ref)
                    self.callers.setdefault(callee, []).append((key, i))

    # -- reachability ------------------------------------------------------
    def reachable_from(self, method_key: str, root_classes: set[str],
                       max_nodes: int = 4000) -> Optional[str]:
        """Reverse-BFS callers; return a caller class in root_classes if any."""
        seen = {method_key}
        q = [method_key]
        while q and len(seen) < max_nodes:
            cur = q.pop()
            for caller_key, _ in self.callers.get(cur, []):
                if caller_key in seen:
                    continue
                cm = self.methods.get(caller_key)
                if cm and cm.cls in root_classes:
                    return cm.cls
                seen.add(caller_key)
                q.append(caller_key)
        return None


# -- backward taint ---------------------------------------------------------
# Instructions whose FIRST register operand is a source, not a destination —
# they must not be treated as a definition of that register.
_NON_DEF = ("invoke", "if-", "goto", "packed-switch", "sparse-switch", "return",
            "throw", "monitor-", "aput", "iput", "sput", "fill-array-data",
            "check-cast", "nop")


def _def_index(m: Method, reg: int, before: int) -> Optional[int]:
    """Most recent instruction (< before) that WRITES `reg` (dest = first vreg)."""
    for i in range(before - 1, -1, -1):
        ins = m.insns[i]
        if ins.mnemonic.startswith(_NON_DEF):
            continue   # these read reg[0]; results land via move-result
        if ins.regs and ins.regs[0] == reg:
            return i
    return None


def _prev_invoke(m: Method, before: int) -> Optional[Insn]:
    for i in range(before - 1, -1, -1):
        if m.insns[i].mnemonic.startswith("invoke"):
            return m.insns[i]
    return None


def trace(dex: Dex, method_key: str, reg: int, before: int,
          depth: int, visited: set) -> dict:
    """Classify the origin of `reg` at position `before` in method_key."""
    if depth > MAX_DEPTH:
        return {"kind": "unknown", "detail": "max-depth"}
    m = dex.methods.get(method_key)
    if not m:
        return {"kind": "unknown", "detail": "no-method"}
    vkey = (method_key, reg, before)
    if vkey in visited:
        return {"kind": "cycle"}
    visited.add(vkey)

    di = _def_index(m, reg, before)
    if di is not None:
        ins = m.insns[di]
        mn = ins.mnemonic
        if mn.startswith("const"):
            return {"kind": "const", "detail": ins.raw}
        if mn.startswith("move-result"):
            inv = _prev_invoke(m, di)
            if inv:
                if any(src in inv.ref for src in SOURCES):
                    return {"kind": "source", "detail": _norm_ref(inv.ref)}
                if any(t in inv.ref for t in TRANSFORMS) and inv.regs:
                    return trace(dex, method_key, inv.regs[0], di, depth, visited)
                # unknown producer: taint flows if any of its inputs are tainted
                for r in inv.regs:
                    res = trace(dex, method_key, r, di, depth + 1, visited)
                    if res["kind"] in ("source", "entry-param"):
                        return res
                return {"kind": "unknown", "detail": _norm_ref(inv.ref)}
            return {"kind": "unknown", "detail": "move-result-no-invoke"}
        if mn.startswith("move"):
            if len(ins.regs) >= 2:
                return trace(dex, method_key, ins.regs[1], di, depth, visited)
            return {"kind": "unknown", "detail": mn}
        if mn.startswith(("iget", "sget")):
            return {"kind": "field", "detail": ins.ref}
        if mn.startswith("fill-array-data") or mn.startswith("filled-new-array"):
            return {"kind": "const", "detail": "array-data"}
        if mn.startswith("new-array"):
            return {"kind": "array", "detail": ins.raw}
        return {"kind": "def", "detail": mn}

    # not defined here -> is it a parameter?
    pregs = m.param_regs()
    if reg in pregs:
        pidx = pregs.index(reg)             # 0 = this (if non-static)
        # is this an exported-lifecycle external param?
        jidx = pidx if m.is_static else pidx - 1
        if m.name in LIFECYCLE_EXTERNAL and jidx >= 0:
            arg_types = _desc_args(m.desc)
            if jidx < len(arg_types) and arg_types[jidx] in EXTERNAL_TYPES:
                return {"kind": "entry-param", "detail": f"{m.name}:{arg_types[jidx]}"}
        # inter-procedural: recurse into callers
        for caller_key, idx in dex.callers.get(method_key, []):
            cm = dex.methods.get(caller_key)
            if not cm:
                continue
            callsite = cm.insns[idx]
            if pidx < len(callsite.regs):
                actual = callsite.regs[pidx]
                res = trace(dex, caller_key, actual, idx, depth + 1, visited)
                if res["kind"] in ("source", "entry-param"):
                    res = dict(res)
                    res.setdefault("via", []).append(caller_key)
                    return res
        return {"kind": "param", "detail": f"idx{jidx}"}
    return {"kind": "unknown", "detail": "undefined"}


def analyze(dex: Dex, native_methods: list[dict], exported_classes: set[str]) -> None:
    """Annotate each native method dict in place with controllability info."""
    for nm in native_methods:
        key_prefix = f"L{nm['java_class'].replace('.', '/')};.{nm['java_method']}:"
        # Native methods have no body, so resolve their callee keys from the
        # invoke refs recorded in the call graph, not from dex.methods.
        callee_keys = [c for c in dex.callers if c.startswith(key_prefix)]
        n_args = len(nm.get("arg_types", []))
        controlled, verdicts, n_callsites, reachable = [], [], 0, False
        for callee_key in callee_keys:
            if dex.reachable_from(callee_key, exported_classes):
                reachable = True
            for caller_key, idx in dex.callers.get(callee_key, []):
                cm = dex.methods.get(caller_key)
                if not cm:
                    continue
                n_callsites += 1
                if cm.cls in exported_classes:
                    reachable = True
                cs = cm.insns[idx]
                # invoke-static has no receiver register; others pass `this` first
                base = 0 if cs.mnemonic.startswith("invoke-static") else 1
                for j in range(n_args):
                    if base + j < len(cs.regs):
                        res = trace(dex, caller_key, cs.regs[base + j], idx, 0, set())
                        verdicts.append({"arg": j, "from": caller_key, **res})
                        if res["kind"] in ("source", "entry-param") and j not in controlled:
                            controlled.append(j)
        nm["reachable"] = bool(reachable or n_callsites)
        nm["controlled_args"] = sorted(controlled)
        nm["controllable"] = bool(controlled)
        nm["flow_sources"] = sorted({v["detail"] for v in verdicts
                                     if v["kind"] in ("source", "entry-param")})
        nm["flow_verdicts"] = verdicts
        nm["n_callsites"] = n_callsites


# -- small parsing helpers --------------------------------------------------
def _q(line: str) -> Optional[str]:
    m = re.search(r":\s*'(.*)'", line)
    return m.group(1) if m else None


def _num(line: str) -> int:
    m = re.search(r":\s*(\d+)", line)
    return int(m.group(1)) if m else 0


def _regs_part(text: str) -> str:
    m = re.search(r"\{([^}]*)\}", text)
    if m:
        rng = m.group(1)
        # expand ranges like "v0 .. v4"
        rm = re.match(r"v(\d+)\s*\.\.\s*v(\d+)", rng.strip())
        if rm:
            return " ".join(f"v{i}" for i in range(int(rm.group(1)), int(rm.group(2)) + 1))
        return rng
    # non-brace forms: const v0, #..  / iget v0, v1, ..  -> take the vregs before any ref
    head = text.split(",")
    return " ".join(p for p in head if _RE_VREG.search(p))


def _ref_part(text: str) -> str:
    m = re.search(r"(L[\w/$]+;\.[^ ]+|L[\w/$]+;->[^ ]+)", text)
    return m.group(1) if m else ""


def _norm_ref(ref: str) -> str:
    return ref.replace(";->", ";.")


def _desc_args(desc: str) -> list[str]:
    inside = desc[desc.find("(") + 1:desc.find(")")]
    out, i = [], 0
    while i < len(inside):
        arr = ""
        while i < len(inside) and inside[i] == "[":
            arr += "["
            i += 1
        if i >= len(inside):
            break
        if inside[i] == "L":
            e = inside.find(";", i)
            out.append(arr + inside[i:e + 1])
            i = e + 1
        else:
            out.append(arr + inside[i])
            i += 1
    return out


def run(dex_paths: list[str], native_methods: list[dict],
        exported_classes: set[str]) -> dict:
    dex = Dex.from_dexdump(dex_paths)
    analyze(dex, native_methods, exported_classes)
    return {
        "methods_parsed": len(dex.methods),
        "controllable": [m["java_method"] for m in native_methods if m.get("controllable")],
    }
