"""Phase 5 — triage, classification, documentation (§6, §7).

Turns one raw crashing input into a documented, reproducible finding:
  - minimize   — shrink the input while it still crashes with the same bug key
  - reproduce  — re-run N times for determinism
  - introspect — registers, faulting instruction (capstone), symbolized backtrace
  - classify   — bug class + severity from the oracle's fault
  - report     — JSON + human-readable

Operates on a live FuzzHarness (reused across runs via context restore).
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field, asdict
from typing import Optional

from ..fuzz.engine import FuzzHarness, crash_key

# bug class + base severity by oracle hint / access
_CLASS = {
    "heap-overflow": ("heap-buffer-overflow", "high"),
    "heap-underflow": ("heap-buffer-underflow", "high"),
    "use-after-free": ("use-after-free", "high"),
    "pc-control/stack-overflow": ("stack-buffer-overflow (return-address overwrite)",
                                  "critical"),
    "oob-write": ("out-of-bounds write", "high"),
    "oob-read": ("out-of-bounds read", "medium"),
    "oob-fetch": ("control-flow hijack", "critical"),
}


@dataclass
class Finding:
    bug_class: str
    severity: str
    access: str
    fault_addr: int
    fault_pc: int
    faulting_insn: str
    reproducible: bool
    repro_rate: str
    min_input_len: int
    min_input_hex: str
    backtrace: list = field(default_factory=list)
    registers: dict = field(default_factory=dict)
    bug_key: str = ""
    notes: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def render(self) -> str:
        L = [f"[{self.severity.upper()}] {self.bug_class}",
             f"  access       : {self.access} @ {self.fault_addr:#x}",
             f"  fault pc     : {self.fault_pc:#x}  {self.faulting_insn}",
             f"  reproducible : {self.reproducible} ({self.repro_rate})",
             f"  min reproducer: {self.min_input_len} bytes  {self.min_input_hex[:80]}"
             + ("..." if len(self.min_input_hex) > 80 else "")]
        if self.backtrace:
            L.append("  backtrace    :")
            L += [f"     {b}" for b in self.backtrace]
        if self.notes:
            L.append("  notes        : " + self.notes)
        return "\n".join(L)


class Triage:
    def __init__(self, harness: FuzzHarness, so_path: Optional[str] = None):
        self.h = harness
        self._syms = self._load_symbols(so_path or harness._sop)

    # -- helpers -----------------------------------------------------------
    def _still(self, data: bytes, key: str) -> bool:
        r = self.h.run(data)
        return bool(r.get("crash") and crash_key(self.h, r["fault"]) == key)

    def _load_symbols(self, so_path: str) -> list:
        try:
            import lief
            b = lief.parse(so_path)
            syms = [(s.name, int(s.value)) for s in b.symbols
                    if s.name and int(getattr(s, "value", 0)) > 0]
            return sorted(syms, key=lambda x: x[1])
        except Exception:
            return []

    def _symbolize(self, off: int) -> str:
        best = None
        for name, val in self._syms:
            if val <= off:
                best = (name, val)
            else:
                break
        if best:
            return f"{best[0]}+{off - best[1]:#x}"
        return f"{off:#x}"

    # -- steps -------------------------------------------------------------
    def minimize(self, data: bytes, key: str) -> bytes:
        cur = data
        step = max(1, len(cur) // 2)
        while step >= 1:
            while len(cur) - step > 0 and self._still(cur[:len(cur) - step], key):
                cur = cur[:len(cur) - step]
            step //= 2
        canon = bytes([0x41] * len(cur))        # canonicalize to 'A' if still crashes
        if canon and self._still(canon, key):
            cur = canon
        return cur

    def reproduce(self, data: bytes, key: str, tries: int = 6) -> tuple:
        hits = sum(1 for _ in range(tries) if self._still(data, key))
        return hits == tries, f"{hits}/{tries}"

    def disasm(self, pc: int) -> str:
        if not (self.h.image_lo <= pc < self.h.image_hi):
            return "(attacker-controlled PC — not in image; control-flow hijack)"
        try:
            import capstone
            code = bytes(self.h.ql.mem.read(pc, 16))
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            for insn in md.disasm(code, pc):
                return f"{insn.mnemonic} {insn.op_str}  ({self._symbolize(pc - self.h.base)})"
        except Exception as e:
            return f"(disasm failed: {e})"
        return "(no instruction decoded)"

    def backtrace(self, regs: dict, depth: int = 64) -> list:
        out = []
        rsp = regs.get("rsp")
        if not rsp:
            return out
        for i in range(depth):
            try:
                v = struct.unpack("<Q", self.h.ql.mem.read(rsp + i * 8, 8))[0]
            except Exception:
                break
            if self.h.image_lo <= v < self.h.image_hi:
                out.append(self._symbolize(v - self.h.base))
            if len(out) >= 8:
                break
        return out

    # -- orchestration -----------------------------------------------------
    def triage(self, crash_input: bytes) -> Optional[Finding]:
        r = self.h.run(crash_input)
        if not r.get("crash"):
            return None
        f = r["fault"]
        key = crash_key(self.h, f)
        hint = r.get("hint", "oob-" + f.get("access", "?"))
        bug_class, sev = _CLASS.get(hint, ("memory-corruption", "medium"))
        if f.get("access") == "read" and sev == "high":
            sev = "medium"       # read is less severe than write

        mn = self.minimize(crash_input, key)
        repro, rate = self.reproduce(mn, key)
        # re-run the minimized input to capture clean fault state
        rr = self.h.run(mn)
        ff = rr.get("fault", f) if rr.get("crash") else f
        regs = ff.get("regs", {})
        return Finding(
            bug_class=bug_class, severity=sev, access=ff.get("access", "?"),
            fault_addr=ff.get("addr", 0), fault_pc=ff.get("pc", 0),
            faulting_insn=self.disasm(ff.get("pc", 0)),
            reproducible=repro, repro_rate=rate,
            min_input_len=len(mn), min_input_hex=mn.hex(),
            backtrace=self.backtrace(regs), registers={k: hex(v) for k, v in regs.items()},
            bug_key=key, notes=hint)
