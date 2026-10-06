"""Generic JNI input model (§ Tier-2: fuzz every controllable argument/flow).

A native method is `jret Java_..._m(JNIEnv*, jclass/jobject, <args...>)`. Earlier
the harness only ever drove a single `byte[]`. Real natives take Strings, direct
`ByteBuffer`s, primitive arrays, and scalars (int/long/float/double/...), often
several at once — and any attacker-controllable one of them can be the bug.

This module turns a method's readable arg types + the flow analysis'
`controlled_args` into an `InputSpec`: the x86-64 SysV register/xmm/stack slot of
every argument, which ones the fuzzer drives, and how to pack one flat fuzz
buffer into the whole argument tuple. It is pure logic — the engine supplies a
tiny memory interface (`alloc_data`/`alloc_obj`/`write`) so this stays testable
without Qiling.

Flat-buffer layout (keeps the common single-`byte[]` case byte-identical to the
old harness, so existing results are preserved):
  [ fixed scalar section | variable blob section ]
  * each controllable scalar consumes 8 bytes up front (interpreted per width),
  * blobs take the remainder; with >1 blob each but the last is u16-length
    prefixed, the last takes the rest (so one dominant buffer stays contiguous
    for CmpLog/dictionary splicing).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

# readable arg type (from jadx_context.parse_descriptor) -> category + elem size
_GP = {"boolean": 1, "byte": 1, "char": 2, "short": 2, "int": 4, "long": 8}
_FP = {"float": 4, "double": 8}
_ARRAY_ELEM = {"byte[]": 1, "boolean[]": 1, "char[]": 2, "short[]": 2,
               "int[]": 4, "float[]": 4, "long[]": 8, "double[]": 8}
_STRING_TYPES = {"String", "CharSequence"}
_DIRECTBUF_TYPES = {"ByteBuffer"}

# Per-arch calling convention. env + thiz occupy the first two integer-arg
# registers; the java args begin at the third, so GP_REGS lists from there.
# FP_REGS are the vector regs the engine writes for float/double args.
ARCHES = {
    "x86_64": {"gp": ("rdx", "rcx", "r8", "r9"), "n_fp": 8, "fp_prefix": "xmm"},
    "arm64":  {"gp": ("x2", "x3", "x4", "x5", "x6", "x7"), "n_fp": 8, "fp_prefix": "v"},
}
GP_REGS = ARCHES["x86_64"]["gp"]           # default (x86_64) for back-compat
N_XMM = 8

# category constants
C_GP = "gp"              # integer/pointer scalar in a GP register
C_FP = "fp"              # float/double in an xmm register
C_BLOB = "blob"          # String / primitive array: {int32 len; int32 pad; ptr}
C_DIRECTBUF = "directbuf"  # java.nio direct ByteBuffer: {ptr data; int64 cap}
C_OBJECT = "object"      # opaque jobject: benign non-null pointer


@dataclass
class ArgSlot:
    idx: int                 # java arg index (0-based, after env/thiz)
    jtype: str               # readable type ("byte[]", "int", "String", ...)
    category: str            # C_GP | C_FP | C_BLOB | C_DIRECTBUF | C_OBJECT
    elem: int = 1            # element size (arrays/strings) or scalar width
    controllable: bool = True
    reg: Optional[str] = None   # GP register name, if category in (GP/BLOB/DIRECTBUF/OBJECT)
    xmm: Optional[int] = None   # xmm index, if FP
    stack_slot: Optional[int] = None  # 0-based stack arg position, if spilled


@dataclass
class InputSpec:
    slots: list = field(default_factory=list)
    is_static: bool = True

    # convenience views ----------------------------------------------------
    @property
    def ctrl_scalars(self):
        return [s for s in self.slots if s.controllable and s.category in (C_GP, C_FP)]

    @property
    def ctrl_blobs(self):
        return [s for s in self.slots if s.controllable
                and s.category in (C_BLOB, C_DIRECTBUF)]

    def summary(self) -> str:
        parts = []
        for s in self.slots:
            tag = "*" if s.controllable else ""
            loc = s.reg or (f"xmm{s.xmm}" if s.xmm is not None else f"stack{s.stack_slot}")
            parts.append(f"{s.jtype}{tag}@{loc}")
        return "(" + ", ".join(parts) + ")"


def categorize(jtype: str) -> "tuple[str, int]":
    if jtype in _GP:
        return C_GP, _GP[jtype]
    if jtype in _FP:
        return C_FP, _FP[jtype]
    if jtype in _ARRAY_ELEM:
        return C_BLOB, _ARRAY_ELEM[jtype]
    if jtype in _STRING_TYPES:
        return C_BLOB, 1
    if jtype in _DIRECTBUF_TYPES:
        return C_DIRECTBUF, 1
    if jtype.endswith("[]"):           # unknown object array -> treat as opaque
        return C_OBJECT, 8
    return C_OBJECT, 8


def build(arg_types: list, controlled_args: Optional[list] = None, *,
          is_static: bool = True, fuzz_all: bool = False,
          arch: str = "x86_64") -> InputSpec:
    """Assign calling-convention slots to every arg and mark which the fuzzer
    drives.

    `controlled_args` are java-arg indices the flow analysis proved controllable;
    if empty (or `fuzz_all`), every data-bearing arg is driven so nothing is
    missed. `arch` selects the register names so the same spec feeds either the
    x86-64 or the arm64 engine."""
    cc = ARCHES.get(arch, ARCHES["x86_64"])
    gp_regs, n_fp = cc["gp"], cc["n_fp"]
    ctrl = set(controlled_args or [])
    data_bearing = [i for i, t in enumerate(arg_types)
                    if categorize(t)[0] != C_OBJECT]
    if fuzz_all or not ctrl:
        ctrl = set(data_bearing) if data_bearing else set(range(len(arg_types)))

    slots, gp_i, fp_i, stack_i = [], 0, 0, 0
    for i, t in enumerate(arg_types):
        cat, elem = categorize(t)
        slot = ArgSlot(idx=i, jtype=t, category=cat, elem=elem,
                       controllable=(i in ctrl))
        if cat == C_FP:
            if fp_i < n_fp:
                slot.xmm = fp_i; fp_i += 1
            else:
                slot.stack_slot = stack_i; stack_i += 1
        else:
            if gp_i < len(gp_regs):
                slot.reg = gp_regs[gp_i]; gp_i += 1
            else:
                slot.stack_slot = stack_i; stack_i += 1
        slots.append(slot)
    return InputSpec(slots=slots, is_static=is_static)


# -- flat buffer <-> per-arg values -----------------------------------------
def decode(spec: InputSpec, data: bytes) -> dict:
    """Split the flat fuzz buffer into {arg_idx: raw_bytes} for controllable args.

    Scalars get their <=8 fixed bytes; blobs get their payload slice."""
    out, pos = {}, 0
    for s in spec.ctrl_scalars:
        out[s.idx] = data[pos:pos + 8]
        pos += 8
    rest = data[pos:]
    blobs = spec.ctrl_blobs
    for n, s in enumerate(blobs):
        if n == len(blobs) - 1:
            out[s.idx] = rest
        else:
            if len(rest) >= 2:
                ln = struct.unpack_from("<H", rest, 0)[0] % (len(rest) - 1 or 1)
                payload = rest[2:2 + ln]
                rest = rest[2 + ln:]
            else:
                payload = b""; rest = b""
            out[s.idx] = payload
    return out


@dataclass
class ArgPlan:
    gpr: dict = field(default_factory=dict)       # regname -> int
    xmm: dict = field(default_factory=dict)       # xmm idx -> (is_double, raw8)
    stack: list = field(default_factory=list)     # list of (stack_slot, int)


class MemIface:
    """Engine-supplied memory ops (so this module needs no Qiling)."""
    def alloc_data(self, n: int) -> int: raise NotImplementedError
    def alloc_obj(self, n: int) -> int: raise NotImplementedError
    def write(self, addr: int, data: bytes) -> None: raise NotImplementedError


def materialize(spec: InputSpec, data: bytes, mem: MemIface) -> ArgPlan:
    """Build the in-memory objects and compute each argument's register value."""
    decoded = decode(spec, data)
    plan = ArgPlan()
    for s in spec.slots:
        raw = decoded.get(s.idx, b"")
        if s.category == C_GP:
            val = int.from_bytes((raw + b"\x00" * 8)[:8], "little")
            val &= (1 << (8 * s.elem)) - 1 if s.elem < 8 else (1 << 64) - 1
            _place_int(plan, s, val)
        elif s.category == C_FP:
            if s.elem == 4:
                raw8 = struct.pack("<f", _as_float(raw, 4))
                raw8 += b"\x00" * 4
            else:
                raw8 = struct.pack("<d", _as_float(raw, 8))
            plan.xmm[s.xmm] = (s.elem == 8, raw8)
        elif s.category == C_BLOB:
            _place_int(plan, s, _mk_array_obj(s, raw, mem))
        elif s.category == C_DIRECTBUF:
            _place_int(plan, s, _mk_directbuf(raw, mem))
        else:  # C_OBJECT — benign non-null pointer to a small zero object
            _place_int(plan, s, mem.alloc_obj(16))
    return plan


def _place_int(plan: ArgPlan, slot: ArgSlot, val: int) -> None:
    if slot.reg:
        plan.gpr[slot.reg] = val
    else:
        plan.stack.append((slot.stack_slot, val))


def _mk_array_obj(slot: ArgSlot, payload: bytes, mem: MemIface) -> int:
    """{int32 element_count; int32 pad; ptr data}. For a String, data is the
    NUL-terminated UTF-8 and the count is the byte length (GetStringUTFLength)."""
    is_string = slot.jtype in _STRING_TYPES
    body = payload + b"\x00" if is_string else payload
    count = len(payload) if is_string else len(payload) // slot.elem
    data_addr = mem.alloc_data(max(len(body), 1))
    mem.write(data_addr, body or b"\x00")
    obj = mem.alloc_obj(16)
    mem.write(obj, struct.pack("<iI", count, 0) + struct.pack("<Q", data_addr))
    return obj


def _mk_directbuf(payload: bytes, mem: MemIface) -> int:
    """{ptr data; int64 capacity} for GetDirectBufferAddress/Capacity."""
    data_addr = mem.alloc_data(max(len(payload), 1))
    mem.write(data_addr, payload or b"\x00")
    obj = mem.alloc_obj(16)
    mem.write(obj, struct.pack("<Q", data_addr) + struct.pack("<q", len(payload)))
    return obj


def _as_float(raw: bytes, width: int) -> float:
    try:
        if width == 4:
            return struct.unpack("<f", (raw + b"\x00" * 4)[:4])[0]
        return struct.unpack("<d", (raw + b"\x00" * 8)[:8])[0]
    except Exception:
        return 0.0
