"""Logic-flaw oracle via control-flow divergence (§ catch logic bugs too).

Memory-corruption is caught by faults; a *logic* bug (auth bypass, license/flag
check that an attacker input flips) produces no fault — the program simply takes
the "you win" path it shouldn't. We make that observable:

  1. Statically mark "win" basic blocks — code that references a success-ish
     string ("granted", "valid", "unlocked", "flag", ...) or calls a sensitive
     sink (system/exec/fopen-for-write). These are the blocks a decision guards.
  2. During fuzzing, if an input reaches a win block that the seed corpus never
     did, the engine flags it (`run()["win"]`). That input drove a decision to
     the privileged side — a candidate logic-bypass, reported WITHOUT building
     an exploit.

This is heuristic and deterministic; it complements (does not replace) the
memory oracle and the model's static audit.
"""
from __future__ import annotations

import re

_WIN_STRINGS = (b"granted", b"grant", b"unlock", b"unlocked", b"valid", b"success",
                b"correct", b"authenticated", b"authorized", b"welcome", b"admin",
                b"root", b"flag", b"accepted", b"pass", b"bypass", b"premium",
                b"license", b"activated", b"approved", b"match")
_SINK_SYMBOLS = ("system", "execve", "execl", "execlp", "execvp", "popen",
                 "posix_spawn", "dlopen", "fopen", "open", "setuid", "chmod")


def win_blocks(harness, func_off: int, span: int = 0x2000) -> set:
    """Block addresses in [func_off, +span) that look like a success/privileged
    path. Returns absolute addresses (base-relative + harness.base)."""
    out = set()
    try:
        import capstone
    except Exception:
        return out
    base = harness.base
    try:
        code = bytes(harness.ql.mem.read(base + func_off, span))
    except Exception:
        return out

    win_str_addrs = _win_string_addrs(harness)
    sink_addrs = _sink_plt_targets(harness)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    for insn in md.disasm(code, base + func_off):
        if insn.id == capstone.x86.X86_INS_RET:
            continue
        # rip-relative lea/mov of a win-string address -> this block is a win
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and \
                    op.mem.base == capstone.x86.X86_REG_RIP:
                tgt = insn.address + insn.size + op.mem.disp
                if tgt in win_str_addrs:
                    out.add(insn.address)
        # direct call to a sensitive sink -> win
        if insn.id == capstone.x86.X86_INS_CALL and insn.operands:
            o = insn.operands[0]
            if o.type == capstone.x86.X86_OP_IMM and o.imm in sink_addrs:
                out.add(insn.address)
    return out


def _win_string_addrs(harness) -> set:
    """Absolute addresses of success-ish strings in the image's rodata/data."""
    addrs = set()
    try:
        import lief
        b = lief.parse(harness._sop)
        for sec in b.sections:
            if sec.name not in (".rodata", ".data", ".rdata") or not sec.size:
                continue
            data = bytes(sec.content)
            low = data.lower()
            for kw in _WIN_STRINGS:
                start = 0
                while True:
                    i = low.find(kw, start)
                    if i < 0:
                        break
                    addrs.add(harness.base + int(sec.virtual_address) + i)
                    start = i + 1
    except Exception:
        pass
    return addrs


def _sink_plt_targets(harness) -> set:
    """GOT/trampoline addresses our stubs resolved for sensitive sinks — a call
    into one of these is a privileged action."""
    out = set()
    try:
        import lief
        b = lief.parse(harness._sop)
        for rel in b.relocations:
            sym = rel.symbol.name if rel.has_symbol else ""
            key = sym.split("@")[0].lstrip("_")
            if key in _SINK_SYMBOLS:
                try:
                    import struct
                    got = harness.base + rel.address
                    out.add(struct.unpack("<Q", harness.ql.mem.read(got, 8))[0])
                except Exception:
                    pass
    except Exception:
        pass
    return out
