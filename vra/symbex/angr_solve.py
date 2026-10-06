"""Phase 4 concolic hand-off (§5 mechanism 3): angr constraint solver.

When coverage-guided fuzzing (even with CmpLog) stalls on a hard branch —
checksums, arithmetic gates (`d[0]^d[1]==K`, `sum(d)==K`) — this solves for an
input that REACHES a target address, then feeds it back to the fuzzer as a seed.

Models the JNI boundary symbolically: a symbolic byte buffer behind a jbyteArray,
and SimProcedures for the JNIEnv accessors the native calls. Runs in the
vra-fuzz container (angr installed there).
"""
from __future__ import annotations

import time
from typing import Optional

# scratch addresses in angr's space
_BUF, _ENV, _ARR, _TBL = 0x6a000000, 0x6a100000, 0x6a200000, 0x6a300000
_GEN, _GAL, _GBE = 0x6a400000, 0x6a400100, 0x6a400200


def solve_reach(so_path: str, func_off: int, find_off: int, *,
                arg_len: int = 32, avoid_offs: Optional[list] = None,
                timeout: float = 90.0) -> Optional[bytes]:
    import angr
    try:
        import claripy
    except ImportError:
        claripy = angr.claripy      # angr 10.x vendors claripy under its namespace
    import logging
    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)

    proj = angr.Project(so_path, auto_load_libs=False)
    base = proj.loader.main_object.mapped_base
    func, find = base + func_off, base + find_off
    avoid = [base + a for a in (avoid_offs or [])]

    class GalProc(angr.SimProcedure):
        def run(self, env, arr):
            return arg_len

    class GbeProc(angr.SimProcedure):
        def run(self, env, arr, is_copy):
            return _BUF

    class GenProc(angr.SimProcedure):
        def run(self, *args):
            return 0

    proj.hook(_GAL, GalProc()); proj.hook(_GBE, GbeProc()); proj.hook(_GEN, GenProc())

    st = proj.factory.blank_state(addr=func)
    sym = claripy.BVS("inp", arg_len * 8)
    st.memory.store(_BUF, sym)
    st.memory.store(_ARR, claripy.BVV(arg_len, 32), endness="Iend_LE")
    st.memory.store(_ARR + 8, claripy.BVV(_BUF, 64), endness="Iend_LE")
    st.memory.store(_ENV, claripy.BVV(_TBL, 64), endness="Iend_LE")
    for i in range(300):
        st.memory.store(_TBL + i * 8, claripy.BVV(_GEN, 64), endness="Iend_LE")
    st.memory.store(_TBL + 171 * 8, claripy.BVV(_GAL, 64), endness="Iend_LE")
    st.memory.store(_TBL + 184 * 8, claripy.BVV(_GBE, 64), endness="Iend_LE")
    st.regs.rdi = _ENV
    st.regs.rsi = 0
    st.regs.rdx = _ARR

    simgr = proj.factory.simgr(st)
    t0 = time.time()
    while simgr.active and (time.time() - t0) < timeout:
        simgr.explore(find=find, avoid=avoid, num_find=1, n=1)
        if simgr.stashes.get("found"):
            break
    found = simgr.stashes.get("found") or []
    if found:
        return found[0].solver.eval(sym, cast_to=bytes)
    return None
