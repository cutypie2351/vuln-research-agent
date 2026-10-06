"""Phase 3 — Qiling isolated JNI harness (§10 A.4/A.6).

Executes one JNI native from an Android `.so` under Qiling (bionic rootfs),
with everything the native needs modeled in Python:

  - **JNIEnv** — a table of function pointers (index = struct-offset/8). Each
    modeled entry points to a hooked trampoline implementing it in Python
    (GetArrayLength, GetByteArrayElements, GetStringUTFChars, ...).
  - **libc imports** — Qiling loads the `.so` alone, so every JUMP_SLOT is
    unresolved. We auto-discover them by name (lief) and bind each GOT entry to
    a Python stub: a real bump-malloc / strncpy / strstr, and benign no-ops for
    the rest. Anti-tamper (ptrace/fork/pthread) is neutralized here (§10 A.7).
  - **jbyteArray / jstring** — modeled as {int32 len; ptr data}; our JNIEnv
    accessors read that layout.

This runs in the vra-fuzz container (qiling + unicorn). `run_once` executes a
single input; the unicornafl fuzzing loop builds on the same setup.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

# JNIEnv index (= offset/8) -> our accessor name.
JNI_GETARRAYLENGTH = 171
JNI_GETBYTEARRAYELEMENTS = 184
JNI_GETSTRINGUTFCHARS = 169
JNI_GETSTRINGUTFLENGTH = 168


@dataclass
class HarnessSpec:
    so_path: str
    rootfs: str
    symbol_addr: int            # file/vaddr offset of the target native
    arg_kind: str = "bytearray"  # "bytearray" | "string"
    # optional target-specific unlocks (RE insight / model-supplied):
    unlock: list = field(default_factory=list)   # [(offset, int32_value)]
    goodbye_internal: dict = field(default_factory=dict)  # {symbol: off} self-refs


class QilingJniHarness:
    def __init__(self, spec: HarnessSpec):
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
        self.spec = spec
        self.ql = Qiling([spec.so_path], spec.rootfs, verbose=QL_VERBOSE.OFF)
        self.base = self.ql.loader.load_address
        self.hits = {"GetArrayLength": 0, "GetByteArrayElements": 0,
                     "GetStringUTFChars": 0}
        self._heap_cur = self.ql.mem.map_anywhere(32 * 1024 * 1024)
        self._wire_libc()
        self._wire_jnienv()
        self._wire_fs()
        for off, val in spec.unlock:
            self.ql.mem.write(self.base + off, struct.pack("<i", val))

    # -- low-level helpers -------------------------------------------------
    def _w(self, a, b): self.ql.mem.write(a, b)
    def _r(self, a, n): return self.ql.mem.read(a, n)
    def _u64(self, a): return struct.unpack("<Q", self._r(a, 8))[0]

    def halloc(self, n: int) -> int:
        p = self._heap_cur
        self._heap_cur = (p + max(n, 1) + 15) & ~15
        return p

    def _ret(self, rv: int):
        ql = self.ql
        rsp = ql.arch.regs.rsp
        ra = self._u64(rsp)
        ql.arch.regs.rsp = rsp + 8
        ql.arch.regs.rax = rv & (2 ** 64 - 1)
        ql.arch.regs.rip = ra

    def _cstr(self, a: int) -> bytes:
        out = bytearray()
        while True:
            c = self._r(a, 1)
            if c == b"\x00":
                return bytes(out)
            out += c
            a += 1

    # -- libc stub layer (GOT patching) ------------------------------------
    def _libc_stubs(self) -> dict[str, Callable]:
        ql = self.ql

        def malloc(q): self._ret(self.halloc(q.arch.regs.rdi))
        def calloc(q):
            n = q.arch.regs.rdi * q.arch.regs.rsi
            p = self.halloc(n); self._w(p, b"\x00" * max(n, 1)); self._ret(p)
        def strncpy(q):
            d, s, n = q.arch.regs.rdi, q.arch.regs.rsi, q.arch.regs.rdx
            src = self._r(s, n); nul = src.find(b"\x00")
            self._w(d, src if nul < 0 else src[:nul] + b"\x00" * (n - nul))
            self._ret(d)
        def strstr(q):
            h = self._cstr(q.arch.regs.rdi); nd = self._cstr(q.arch.regs.rsi)
            i = h.find(nd); self._ret(q.arch.regs.rdi + i if i >= 0 else 0)
        def zero(q): self._ret(0)
        def neg1(q): self._ret(2 ** 64 - 1)
        def _exit(q): q.emu_stop()

        # name -> impl. Anti-tamper (fork/pthread_create) return failure so the
        # native skips its tamper branch; ptrace/wait/etc. are benign.
        return {
            "malloc": malloc, "calloc": calloc, "realloc": malloc,
            "strncpy": strncpy, "strstr": strstr,
            "fopen": zero, "fgets": zero, "fclose": zero, "fread": zero,
            "usleep": zero, "raise": zero, "_exit": _exit, "abort": _exit,
            "__cxa_finalize": zero, "__cxa_atexit": zero, "__android_log_print": zero,
            "pthread_create": neg1, "pthread_exit": zero, "__stack_chk_fail": zero,
            "fork": neg1, "getppid": zero, "ptrace": zero, "waitpid": zero,
        }

    def _wire_libc(self):
        import lief
        b = lief.parse(self.spec.so_path)
        stubs = self._libc_stubs()
        # one trampoline page; a distinct hooked addr per resolved import
        tr = self.ql.mem.map_anywhere(0x4000)
        i = 0
        bound = []
        for rel in b.relocations:
            sym = rel.symbol.name if rel.has_symbol else ""
            if not sym:
                continue
            key = sym.split("@")[0].lstrip("_")  # "malloc@LIBC" -> "malloc"
            # internal self-refs (e.g. goodbye) resolve inside the lib
            if key in self.spec.goodbye_internal:
                self._w(self.base + rel.address,
                        struct.pack("<Q", self.base + self.spec.goodbye_internal[key]))
                continue
            impl = stubs.get(key) or stubs.get(sym.split("@")[0])
            if impl is None:
                continue
            addr = tr + i * 16; i += 1
            self._w(addr, b"\xc3")
            self.ql.hook_address(impl, addr)
            self._w(self.base + rel.address, struct.pack("<Q", addr))
            bound.append(key)
        self.bound_libc = bound

    # -- JNIEnv layer ------------------------------------------------------
    def _wire_jnienv(self):
        ql = self.ql
        jt = ql.mem.map_anywhere(0x1000)
        gen, glen, gbe, guc = jt + 0x10, jt + 0x20, jt + 0x30, jt + 0x40
        for a in (gen, glen, gbe, guc):
            self._w(a, b"\xc3")

        def h_gen(q): self._ret(0)
        def h_len(q):
            arr = q.arch.regs.rsi; self.hits["GetArrayLength"] += 1
            self._ret(struct.unpack("<i", self._r(arr, 4))[0])
        def h_gbe(q):
            arr = q.arch.regs.rsi; self.hits["GetByteArrayElements"] += 1
            self._ret(self._u64(arr + 8))
        def h_guc(q):
            s = q.arch.regs.rsi; self.hits["GetStringUTFChars"] += 1
            self._ret(self._u64(s + 8))

        ql.hook_address(h_gen, gen); ql.hook_address(h_len, glen)
        ql.hook_address(h_gbe, gbe); ql.hook_address(h_guc, guc)

        tbl = ql.mem.map_anywhere(300 * 8)
        for k in range(300):
            self._w(tbl + k * 8, struct.pack("<Q", gen))
        self._w(tbl + JNI_GETARRAYLENGTH * 8, struct.pack("<Q", glen))
        self._w(tbl + JNI_GETBYTEARRAYELEMENTS * 8, struct.pack("<Q", gbe))
        self._w(tbl + JNI_GETSTRINGUTFCHARS * 8, struct.pack("<Q", guc))
        self.env = ql.mem.map_anywhere(8)
        self._w(self.env, struct.pack("<Q", tbl))

    def _wire_fs(self):
        from unicorn.x86_const import UC_X86_REG_FS_BASE
        tls = self.ql.mem.map_anywhere(0x1000)
        self.ql.uc.reg_write(UC_X86_REG_FS_BASE, tls)

    # -- argument modeling + execution -------------------------------------
    def make_arg(self, data: bytes) -> int:
        d = self.halloc(len(data)); self._w(d, data or b"\x00")
        arr = self.halloc(16)
        self._w(arr, struct.pack("<i", len(data)) + b"\x00" * 4 + struct.pack("<Q", d))
        return arr

    def run_once(self, data: bytes, timeout: int = 30_000_000) -> dict:
        ql = self.ql
        for k in self.hits:
            self.hits[k] = 0
        arg = self.make_arg(data)
        ret_trap = ql.mem.map_anywhere(0x100)
        rsp = (ql.arch.regs.rsp & ~0xf) - 8
        self._w(rsp, struct.pack("<Q", ret_trap)); ql.arch.regs.rsp = rsp
        ql.arch.regs.rdi = self.env
        ql.arch.regs.rsi = 0
        ql.arch.regs.rdx = arg
        ql.emu_start(self.base + self.spec.symbol_addr, ret_trap, timeout=timeout)
        return {"ret": ql.arch.regs.rax, "hits": dict(self.hits)}
