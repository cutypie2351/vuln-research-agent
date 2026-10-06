"""CmpLog / RedQueen-lite (§5 mechanism 1): extract comparison values.

Runs one input while disassembling each in-image instruction; at every
comparison (cmp/sub/cmpxchg) it records both the immediate and the live register
operand values. Those become dictionary entries the fuzzer splices into inputs,
which cracks magic-byte / length checks (`if (magic == 0xCAFEBABE)`) without
hand-written dictionaries. Only run on promoted (new-coverage) inputs, never in
the hot loop.
"""
from __future__ import annotations

import struct


def _encode(v: int) -> list:
    v &= (1 << 64) - 1
    out = []
    for fmt in ("<I", "<Q", "<H"):
        try:
            out.append(struct.pack(fmt, v & ((1 << (8 * struct.calcsize(fmt))) - 1)))
        except Exception:
            pass
    return out


def collect_magics(harness, data: bytes, cap: int = 512) -> set:
    try:
        import capstone
        from capstone import x86 as csx86
    except Exception:
        return set()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    CMP = {capstone.x86.X86_INS_CMP, capstone.x86.X86_INS_SUB,
           capstone.x86.X86_INS_CMPXCHG, capstone.x86.X86_INS_TEST}
    vals: set = set()

    def hook(uc, addr, size, user=None):
        if not (harness.image_lo <= addr < harness.image_hi) or len(vals) > cap:
            return
        try:
            code = bytes(harness.ql.mem.read(addr, min(size, 15)))
        except Exception:
            return
        for insn in md.disasm(code, addr):
            if insn.id in CMP:
                for op in insn.operands:
                    if op.type == csx86.X86_OP_IMM and op.imm:
                        for b in _encode(op.imm):
                            vals.add(b)
                    elif op.type == csx86.X86_OP_REG:
                        try:
                            rv = getattr(harness.ql.arch.regs, insn.reg_name(op.reg))
                            if rv:
                                for b in _encode(rv):
                                    vals.add(b)
                        except Exception:
                            pass
            break

    hid = harness.ql.uc.hook_add(harness._uc.UC_HOOK_CODE, hook,
                                 begin=harness.image_lo, end=harness.image_hi)
    try:
        harness.run(data)
    finally:
        harness.ql.uc.hook_del(hid)
    # drop all-zero / trivial entries
    return {v for v in vals if v.strip(b"\x00")}
