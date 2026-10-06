"""Static vuln-research pass (§3, §7) — reason about code, don't just fuzz.

For each controllable native, disassemble the function and look for the sinks
where memory-corruption bugs are born (memcpy/strcpy/sprintf/alloca/size-driven
malloc...). Each hit is a bug-class HYPOTHESIS (candidate bug the fuzzer then
tries to confirm), and the constants referenced in the function are harvested
into the fuzz dictionary so fuzzing starts magic-aware (smart, not generic).

Deterministic (objdump + regex) so it runs in the container with no key/IDA;
the LLM static-audit and IDA Hex-Rays decompilation enrich this when available.
"""
from __future__ import annotations

import re
import struct
import subprocess
from typing import Optional

# sink (canonical, underscore-stripped) -> (bug class, severity hint)
_SINKS = {
    "memcpy": ("buffer-overflow (memcpy)", "high"),
    "memmove": ("buffer-overflow (memmove)", "high"),
    "strcpy": ("buffer-overflow (strcpy)", "high"),
    "strcat": ("buffer-overflow (strcat)", "high"),
    "stpcpy": ("buffer-overflow (stpcpy)", "high"),
    "sprintf": ("buffer-overflow (sprintf)", "high"),
    "vsprintf": ("buffer-overflow (vsprintf)", "high"),
    "gets": ("buffer-overflow (gets)", "critical"),
    "strncpy": ("bounded-copy — check length (strncpy)", "medium"),
    "strncat": ("bounded-copy — check length (strncat)", "medium"),
    "read": ("raw read into buffer", "medium"),
    "recv": ("raw recv into buffer", "medium"),
    "alloca": ("stack allocation with controlled size (alloca)", "high"),
    "malloc": ("size-controlled heap allocation (malloc)", "medium"),
    "calloc": ("size-controlled heap allocation (calloc)", "medium"),
    "realloc": ("size-controlled heap allocation (realloc)", "medium"),
    "printf": ("format string (printf)", "medium"),
    "sscanf": ("parse into buffer (sscanf)", "medium"),
}

_RE_PLT = re.compile(r"call.*<_?([A-Za-z_][A-Za-z0-9_]*)@plt>")
_RE_IMM = re.compile(r"[$,]0x([0-9a-fA-F]{2,16})\b")


def _canon(name: str) -> str:
    n = name.lstrip("_")
    return n[:-4] if n.endswith("_chk") else n


def _encode(v: int) -> list:
    out = []
    if v == 0:
        return out
    for fmt in ("<I", "<Q", "<H"):
        w = struct.calcsize(fmt)
        out.append(struct.pack(fmt, v & ((1 << (8 * w)) - 1)))
    return out


def static_scan(so_path: str, native_symbol: str) -> dict:
    """Disassemble one function; return {hypotheses, dict_consts}."""
    try:
        out = subprocess.run(
            ["objdump", "-d", f"--disassemble={native_symbol}", so_path],
            capture_output=True, text=True, timeout=60).stdout
    except Exception:
        return {"hypotheses": [], "dict_consts": []}
    hyps, consts = [], set()
    for line in out.splitlines():
        m = _RE_PLT.search(line)
        if m:
            canon = _canon(m.group(1))
            if canon in _SINKS:
                bc, sev = _SINKS[canon]
                off = line.strip().split(":", 1)[0].strip()
                hyps.append({"sink": canon, "bug_class": bc, "severity": sev,
                             "offset": off})
        for im in _RE_IMM.findall(line):
            try:
                v = int(im, 16)
                if 0 < v < (1 << 64):
                    consts.update(_encode(v))
            except ValueError:
                pass
    # de-dup hypotheses by sink
    seen, uniq = set(), []
    for h in hyps:
        if h["sink"] not in seen:
            seen.add(h["sink"]); uniq.append(h)
    return {"hypotheses": uniq, "dict_consts": [c for c in consts if c.strip(b"\x00")]}
