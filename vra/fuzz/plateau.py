"""Concolic hand-off on coverage plateau (§5 mechanism 3, Driller-style).

When a target is fuzzed and coverage stalls (no crash), the function almost
certainly has a hard gate (checksum / arithmetic constraint) the mutator can't
pass. We disassemble the function, find conditional-branch targets that fuzzing
never reached, and ask angr to solve for an input that gets there. Those become
new seeds — the fuzzer resumes from past the gate.
"""
from __future__ import annotations

from typing import List


def uncovered_branch_targets(harness, func_off: int, span: int = 0x800) -> List[int]:
    """Offsets (from image base) of branch targets fuzzing didn't cover."""
    try:
        import capstone
    except Exception:
        return []
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    base = harness.base
    try:
        code = bytes(harness.ql.mem.read(base + func_off, span))
    except Exception:
        return []
    out: list[int] = []
    for insn in md.disasm(code, base + func_off):
        if insn.id == capstone.x86.X86_INS_RET:
            break
        grps = set(insn.groups)
        if capstone.CS_GRP_JUMP in grps and insn.id != capstone.x86.X86_INS_JMP:
            tgt = insn.operands[0].imm if insn.operands else None
            ft = insn.address + insn.size
            for cand in (tgt, ft):
                if cand and base <= cand < harness.image_hi \
                        and cand not in harness.cov_global and (cand - base) not in out:
                    out.append(cand - base)
    return out


def angr_break(harness, so_path: str, func_off: int, *, timeout: float = 60.0,
               max_branches: int = 4, arg_len: int = 32) -> List[bytes]:
    """Solve for inputs reaching uncovered branches; return them as seeds."""
    from ..symbex.angr_solve import solve_reach
    targets = uncovered_branch_targets(harness, func_off)[:max_branches]
    seeds: list[bytes] = []
    per = max(timeout / max(len(targets), 1), 15.0)
    for off in targets:
        try:
            inp = solve_reach(so_path, func_off, off, arg_len=arg_len, timeout=per)
        except Exception:
            inp = None
        if inp:
            seeds.append(inp)
    return seeds
