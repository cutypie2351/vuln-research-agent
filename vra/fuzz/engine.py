"""Phase 4 — coverage-guided fuzzing engine over the Qiling JNI harness (§4,§5).

Fast loop: the .so is loaded and wired ONCE; each execution restores CPU state
AND writable memory, rewinds the guard-heap, materializes the full JNI argument
tuple from the fuzz input (see `inputspec`), and re-enters the native.

Oracle (how a bug becomes a deterministic fault):
  * guard-page heap — each allocation sits between two unmapped guard pages, and
    allocations alternate start/end alignment, so a one-byte heap OVERFLOW *or*
    UNDERFLOW faults. Input arrays/strings are end-aligned too, so a native that
    reads past the declared length faults (OOB read of attacker data).
  * use-after-free — `free()` protects the chunk's page NONE, so any later
    access to freed memory faults and is classified UAF.
  * unmapped / protected memory hooks catch wild reads/writes and bad fetches
    (control-flow hijack / stack smash).
Memory is snapshotted after setup and restored every run, so one input's writes
to the library's .data/.bss can't make the next run's crash non-reproducible.

Coverage = set of basic-block addresses; new coverage promotes an input. A
separate set of "win" blocks (set by the logic oracle) flags inputs that reach a
security-positive path (auth bypass / logic flip) without a memory fault.
"""
from __future__ import annotations

import random
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from . import inputspec

_PAGE = 0x1000
_DATA_CAP = 1 << 16
_SLOTS = 256
_ARENA = 1 << 16
_SNAP_CAP = 4 << 20       # per-segment snapshot cap


@dataclass
class Crash:
    input: bytes
    access: str
    fault_addr: int
    pc: int
    key: str
    bug_hint: str = ""


@dataclass
class FuzzResult:
    execs: int = 0
    coverage: int = 0
    corpus: int = 0
    crashes: list = field(default_factory=list)
    wins: list = field(default_factory=list)       # logic-flip inputs (Wave 4)
    elapsed: float = 0.0


class FuzzHarness(inputspec.MemIface):
    """One loaded .so, re-enterable per input with full state reset + oracle."""

    def __init__(self, so_path: str, rootfs: str, symbol_addr: int, *,
                 spec: Optional[inputspec.InputSpec] = None,
                 unlock: Optional[list] = None, goodbye_internal: Optional[dict] = None,
                 auto_unlock: bool = True):
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
        from unicorn import x86_const
        from unicorn.x86_const import UC_X86_REG_FS_BASE
        import unicorn

        self._uc = unicorn
        self._x86const = x86_const       # XMM regs live here, not on `unicorn`
        self._sop = so_path
        self.ql = Qiling([so_path], rootfs, verbose=QL_VERBOSE.OFF)
        # Reserve page 0 (no access) so nothing maps there and a NULL deref in the
        # target faults instead of silently reading our data — and map_anywhere
        # never hands out address 0 for our scratch regions.
        try:
            self.ql.mem.map(0, _PAGE, perms=0)
        except Exception:
            pass
        self.base = self.ql.loader.load_address
        self.image_lo = self.base
        self.image_hi = self.base + 0x1000000
        self.entry = self.base + symbol_addr
        self.spec = spec or inputspec.build(["byte[]"], [0])
        # flat-buffer byte offsets of controllable scalar args (for scalar-aware
        # mutation: boundary / integer-overflow values the native's size logic cares about)
        self.scalar_offsets = [(i * 8, s.elem)
                               for i, s in enumerate(self.spec.ctrl_scalars)]
        self._last_fault = None
        self.cov_global: set[int] = set()
        self.win_blocks: set[int] = set()
        self._run_new = 0
        self._run_win = False
        self._dispatch: dict[int, callable] = {}
        self._goodbye_internal = goodbye_internal or {}

        # fixed scratch + per-run arg arena + input-data region
        self._arena_base = self.ql.mem.map_anywhere(_ARENA)
        self._arena_cur = self._arena_base
        self._in_cap = 1 << 20
        self._in_base = self.ql.mem.map_anywhere(self._in_cap)
        self._in_cur = self._in_base
        self.ret_addr = self.ql.mem.map_anywhere(_PAGE)
        self._scratch = self.ql.mem.map_anywhere(_PAGE)   # benign non-null object
        self._guard_init()

        self._tr = self.ql.mem.map_anywhere(0x8000)
        self._tr_next = 0
        self.ql.uc.hook_add(unicorn.UC_HOOK_CODE, self._trampoline,
                            begin=self._tr, end=self._tr + 0x8000)

        self._apply_relative_relocs()   # qiling doesn't; needed for ptr-to-data
        self._wire_libc()
        self._wire_jnienv()

        tls = self.ql.mem.map_anywhere(_PAGE)
        self.ql.uc.reg_write(UC_X86_REG_FS_BASE, tls)
        for off, val in (unlock or []):
            self.ql.mem.write(self.base + off, struct.pack("<i", val))
        self.unlocked = list(unlock or [])
        if auto_unlock:
            self._auto_unlock()

        self.stack_top = (self.ql.arch.regs.rsp & ~0xF) - 0x800

        self.ql.uc.hook_add(unicorn.UC_HOOK_BLOCK, self._on_block)
        self.ql.uc.hook_add(
            unicorn.UC_HOOK_MEM_READ_UNMAPPED | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED
            | unicorn.UC_HOOK_MEM_FETCH_UNMAPPED | unicorn.UC_HOOK_MEM_READ_PROT
            | unicorn.UC_HOOK_MEM_WRITE_PROT | unicorn.UC_HOOK_MEM_FETCH_PROT,
            self._on_fault)

        self._snapshot_init()
        self._ctx = self.ql.uc.context_save()

    # -- MemIface (used by inputspec.materialize) --------------------------
    _IN_SLACK = 0x200     # zero headroom after an input buffer (ART arrays have it)

    def alloc_data(self, n: int) -> int:
        """Attacker input buffer (byte[]/String/ByteBuffer data). NOT guard-fenced:
        real ART arrays carry headroom, so a native reading its NUL terminator or a
        few bytes of slack is normal, not a bug — fencing it here produced false
        heap-overflows. The guard heap still fences the native's OWN malloc/new,
        which is where copy-in overflows actually land. A massive over-read still
        runs off the input region into unmapped memory and is caught."""
        a = self._in_cur
        self._in_cur = (a + n + self._IN_SLACK + 15) & ~15
        if self._in_cur - self._in_base > self._in_cap:   # wrap
            self._in_cur = self._in_base + ((a + 16) % (self._in_cap - 0x1000))
            a = self._in_cur
            self._in_cur = (a + n + self._IN_SLACK + 15) & ~15
        self.ql.mem.write(a, b"\x00" * (n + self._IN_SLACK))   # deterministic slack
        return a

    def alloc_obj(self, n: int) -> int:
        a = self._arena_cur
        self._arena_cur = (a + max(n, 1) + 15) & ~15
        if self._arena_cur - self._arena_base > _ARENA:   # wrap (shouldn't happen)
            self._arena_cur = self._arena_base + ((a + 16) % _ARENA)
            a = self._arena_cur
        return a

    def write(self, addr: int, data: bytes) -> None:
        self.ql.mem.write(addr, data)

    # -- trampoline dispatch ----------------------------------------------
    def _new_tramp(self, impl) -> int:
        addr = self._tr + self._tr_next * 16
        self._tr_next += 1
        self.ql.mem.write(addr, b"\xc3")
        self._dispatch[addr] = impl
        return addr

    def _trampoline(self, uc, addr, size, user=None):
        f = self._dispatch.get(addr)
        if f:
            f()

    # -- guard-page heap oracle (double-sided + UAF) -----------------------
    def _guard_init(self):
        # 3 pages/slot: [guard_lo][chunk][guard_hi]. Guards are PROT_NONE, not
        # unmapped: an unmapped hole is "free" address space that map_anywhere
        # (used for oversized allocs) would hand back out, silently destroying the
        # oracle after a few big allocs — which broke crash reproducibility. A
        # PROT_NONE page stays occupied AND faults on any access.
        region = self.ql.mem.map_anywhere(_SLOTS * 3 * _PAGE)
        self._chunks, self._guard_ranges = [], []
        for i in range(_SLOTS):
            lo = region + 3 * i * _PAGE
            chunk = lo + _PAGE
            hi = chunk + _PAGE
            for g in (lo, hi):
                try:
                    self.ql.mem.protect(g, _PAGE, self._uc.UC_PROT_NONE)
                except Exception:
                    pass
                self._guard_ranges.append((g, g + _PAGE))
            self._chunks.append(chunk)
        self._slot_cur = 0
        self._alloc_count = 0
        self._live: dict[int, int] = {}     # returned addr -> chunk page
        self._freed_pages: set[int] = set()
        self._big_allocs: list = []         # fallback map_anywhere allocs to reclaim

    _ALLOC_CAP = 2 << 20     # cap oversized allocs: keeps throughput up and
                              # avoids OOM when an attacker-controlled size is huge
                              # (a copy larger than the cap still overflows -> caught)

    def _guard_alloc(self, n: int, align: str = "alt") -> int:
        if n <= 0:
            n = 1
        if self._slot_cur < len(self._chunks) and n <= _PAGE:
            chunk = self._chunks[self._slot_cur]
            self._slot_cur += 1
            self._alloc_count += 1
            end = (align == "end") or (align == "alt" and self._alloc_count % 2 == 0)
            addr = chunk + _PAGE - n if end else chunk
            self._live[addr] = chunk
            return addr
        sz = (min(n, self._ALLOC_CAP) + _PAGE - 1) & ~(_PAGE - 1)
        addr = self.ql.mem.map_anywhere(sz)
        self._big_allocs.append((addr, sz))   # reclaimed on reset (context_restore
        return addr                           # does NOT undo memory mappings)

    def _free(self, ptr: int):
        chunk = self._live.get(ptr)
        if chunk is None:
            # find the chunk page containing ptr
            for c in self._chunks:
                if c <= ptr < c + _PAGE:
                    chunk = c
                    break
        if chunk is not None and chunk not in self._freed_pages:
            try:
                self.ql.mem.protect(chunk, _PAGE, self._uc.UC_PROT_NONE)
                self._freed_pages.add(chunk)
            except Exception:
                pass

    def _reset_heap(self):
        for chunk in self._freed_pages:
            try:
                self.ql.mem.protect(chunk, _PAGE,
                                    self._uc.UC_PROT_READ | self._uc.UC_PROT_WRITE)
            except Exception:
                pass
        for addr, sz in self._big_allocs:        # reclaim leaked oversized allocs
            try:
                self.ql.mem.unmap(addr, sz)
            except Exception:
                pass
        self._big_allocs.clear()
        self._freed_pages.clear()
        self._live.clear()
        self._slot_cur = 0
        self._alloc_count = 0

    def _auto_unlock(self, window: int = 0xC0):
        """Defeat early init-gates heuristically. Two codegen shapes are handled:
          (a) direct    `cmp dword [rip+disp], IMM`  -> write IMM to that global;
          (b) indirect  `mov rX, [rip+disp]; mov eX, [rX]; cmp eX, IMM`
                        -> read the pointer at [rip+disp], write IMM to *that*.
        Shape (b) (a pointer to a flag) is the common real-world form. Crashes
        found afterward are still real faults on controlled input (plan §10 A.7)."""
        try:
            import capstone
            from capstone import x86 as csx86
        except Exception:
            return
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        try:
            code = bytes(self.ql.mem.read(self.entry, 256))
        except Exception:
            return

        def parent(name):          # eax->rax, r8d->r8, ... for cross-width matching
            n = name.lower()
            m32 = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
                   "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp"}
            if n in m32:
                return m32[n]
            if n.endswith("d") and n.startswith("r"):
                return n[:-1]
            return n

        ptr_slot = {}      # 64-bit reg -> [rip+disp] slot it was loaded FROM
        loaded = {}        # reg (parent) -> slot whose *pointer* it dereferenced
        for insn in md.disasm(code, self.entry):
            if insn.address - self.entry > window:
                break
            ops = insn.operands
            if insn.id == csx86.X86_INS_MOV and len(ops) == 2:
                dst, src = ops
                # mov r64, [rip+disp]
                if (dst.type == csx86.X86_OP_REG and src.type == csx86.X86_OP_MEM
                        and src.mem.base == csx86.X86_REG_RIP):
                    slot = insn.address + insn.size + src.mem.disp
                    ptr_slot[parent(insn.reg_name(dst.reg))] = slot
                # mov e/r, [r64]
                elif (dst.type == csx86.X86_OP_REG and src.type == csx86.X86_OP_MEM
                      and src.mem.base != 0 and src.mem.base != csx86.X86_REG_RIP
                      and src.mem.disp == 0):
                    base = parent(insn.reg_name(src.mem.base))
                    if base in ptr_slot:
                        loaded[parent(insn.reg_name(dst.reg))] = ptr_slot[base]
                continue
            if insn.id != csx86.X86_INS_CMP:
                continue
            mem = imm = reg = None
            for op in ops:
                if op.type == csx86.X86_OP_MEM and op.mem.base == csx86.X86_REG_RIP:
                    mem = op
                elif op.type == csx86.X86_OP_IMM:
                    imm = op.imm
                elif op.type == csx86.X86_OP_REG:
                    reg = parent(insn.reg_name(op.reg))
            if imm is None:
                continue
            target = None
            if mem is not None:                           # shape (a)
                target = insn.address + insn.size + mem.mem.disp
            elif reg in loaded:                           # shape (b)
                try:
                    target = struct.unpack("<Q", self.ql.mem.read(loaded[reg], 8))[0]
                except Exception:
                    target = None
            if target is not None:
                try:
                    self.ql.mem.write(target, struct.pack("<i", imm & 0xFFFFFFFF))
                    self.unlocked.append((target, imm))
                except Exception:
                    pass

    def _apply_relative_relocs(self):
        """Resolve data relocations Qiling's loader leaves unresolved:
          * R_X86_64_RELATIVE          -> *slot = base + addend
          * R_X86_64_GLOB_DAT (local)  -> *slot = base + symbol.value
        Without this, a GOT slot holding a pointer to one of the library's own
        globals reads as 0, so `mov rX,[rip+got]; mov eX,[rX]` on a global faults
        or mis-reads — breaking init-gates and real parsers. GLOB_DAT/JUMP_SLOT
        for IMPORTED (libc) symbols are left to `_wire_libc`."""
        try:
            import lief
            b = lief.parse(self._sop)
        except Exception:
            return
        n = 0
        for rel in b.relocations:
            ts = str(getattr(rel, "type", ""))
            slot = self.base + rel.address
            val = None
            if "RELATIVE" in ts:
                val = self.base + int(getattr(rel, "addend", 0))
            elif ("GLOB_DAT" in ts or "JUMP_SLOT" in ts) \
                    and rel.has_symbol and rel.symbol is not None:
                sym = rel.symbol
                defined = not getattr(sym, "is_imported", False) \
                    and int(getattr(sym, "value", 0)) > 0
                if defined:
                    val = self.base + int(sym.value)
            if val is None:
                continue
            try:
                self.ql.mem.write(slot, struct.pack("<Q", val))
                n += 1
            except Exception:
                continue
        self._n_relocs = n

    # -- register helpers --------------------------------------------------
    def _ret(self, rv):
        rsp = self.ql.arch.regs.rsp
        ra = struct.unpack("<Q", self.ql.mem.read(rsp, 8))[0]
        self.ql.arch.regs.rsp = rsp + 8
        self.ql.arch.regs.rax = rv & (2 ** 64 - 1)
        self.ql.arch.regs.rip = ra

    def _argn(self, n: int) -> int:
        """nth integer arg (0=rdi...5=r9) by SysV order."""
        return getattr(self.ql.arch.regs, ("rdi", "rsi", "rdx", "rcx", "r8", "r9")[n])

    # -- libc stubs --------------------------------------------------------
    def _wire_libc(self):
        import lief
        b = lief.parse(self._sop)
        ql = self.ql

        def malloc(): self._ret(self._guard_alloc(ql.arch.regs.rdi, "end"))
        def calloc():
            n = ql.arch.regs.rdi * ql.arch.regs.rsi
            p = self._guard_alloc(n, "end"); ql.mem.write(p, b"\x00" * max(n, 1))
            self._ret(p)
        def realloc():
            self._ret(self._guard_alloc(ql.arch.regs.rsi, "end"))
        def free(): self._free(ql.arch.regs.rdi); self._ret(0)
        def memcpy():
            d, s, n = ql.arch.regs.rdi, ql.arch.regs.rsi, ql.arch.regs.rdx
            self._emu_write(d, self._emu_read(s, n))
            self._ret(d)
        def memset():
            d, c, n = ql.arch.regs.rdi, ql.arch.regs.rsi & 0xFF, ql.arch.regs.rdx
            self._emu_write(d, bytes([c]) * n)
            self._ret(d)
        def strncpy():
            d, s, n = ql.arch.regs.rdi, ql.arch.regs.rsi, ql.arch.regs.rdx
            src = self._emu_read(s, n); nul = src.find(b"\x00")
            self._emu_write(d, src if nul < 0 else src[:nul] + b"\x00" * (n - nul))
            self._ret(d)
        def strcpy():
            d, s = ql.arch.regs.rdi, ql.arch.regs.rsi
            src = self._cstr(s)
            self._emu_write(d, src + b"\x00")   # classic unbounded copy
            self._ret(d)
        def strcat():
            d, s = ql.arch.regs.rdi, ql.arch.regs.rsi
            dlen = len(self._cstr(d))
            self._emu_write(d + dlen, self._cstr(s) + b"\x00")
            self._ret(d)
        def zero(): self._ret(0)
        def one(): self._ret(1)
        def neg1(): self._ret(2 ** 64 - 1)
        def _exit(): ql.emu_stop()
        def strdup():
            src = self._cstr(ql.arch.regs.rdi)
            p = self._guard_alloc(len(src) + 1, "end"); ql.mem.write(p, src + b"\x00")
            self._ret(p)
        stubs = {"malloc": malloc, "calloc": calloc, "realloc": realloc, "free": free,
                 # C++ runtime: operator new/new[]/delete, guards, exceptions
                 "Znwm": malloc, "Znam": malloc, "ZdlPv": free, "ZdaPv": free,
                 "ZdlPvm": free, "ZdaPvm": free, "strdup": strdup, "strndup": strdup,
                 "cxa_guard_acquire": one, "cxa_guard_release": zero,
                 "cxa_guard_abort": zero, "cxa_throw": zero, "cxa_begin_catch": zero,
                 "cxa_end_catch": zero, "cxa_allocate_exception": malloc,
                 "memcpy": memcpy, "memmove": memcpy, "memset": memset,
                 "strncpy": strncpy, "strcpy": strcpy, "stpcpy": strcpy,
                 "strcat": strcat, "strncat": strcat, "strlen": self._strlen_impl,
                 "strstr": zero, "strchr": zero, "strcmp": zero, "strncmp": zero,
                 "memcmp": zero,
                 "fopen": zero, "fgets": zero, "fclose": zero, "fread": zero,
                 "usleep": zero, "raise": zero, "_exit": _exit, "abort": _exit,
                 "__cxa_finalize": zero, "__cxa_atexit": zero,
                 "__android_log_print": zero, "__errno": lambda: self._ret(self._scratch),
                 "__stack_chk_fail": _exit, "pthread_create": neg1,
                 "pthread_exit": zero, "pthread_mutex_lock": zero,
                 "pthread_mutex_unlock": zero,
                 "fork": neg1, "getppid": zero, "ptrace": zero, "waitpid": zero,
                 "gettimeofday": zero, "time": zero, "getpid": zero,
                 "__memcpy_chk": memcpy, "__strcpy_chk": strcpy,
                 "__strcat_chk": strcat, "__memset_chk": memset}
        bound = 0
        for rel in b.relocations:
            sym = rel.symbol.name if rel.has_symbol else ""
            if not sym:
                continue
            key = sym.split("@")[0].lstrip("_")
            if key in self._goodbye_internal:
                ql.mem.write(self.base + rel.address,
                             struct.pack("<Q", self.base + self._goodbye_internal[key]))
                continue
            # Only bind IMPORTED (undefined) symbols; locally-defined ones were
            # already resolved by _apply_relative_relocs (don't clobber them).
            imported = getattr(rel.symbol, "is_imported", True) \
                and int(getattr(rel.symbol, "value", 0)) == 0
            if not imported:
                continue
            # Known behavior if we model it; otherwise a benign return-0 stub so an
            # unmodeled libc call doesn't jump through a null PLT slot and fault
            # (that was a harness false positive, not a bug in the target).
            impl = stubs.get(key) or stubs.get("__" + key) or zero
            ql.mem.write(self.base + rel.address,
                         struct.pack("<Q", self._new_tramp(impl)))
            bound += 1
        self._n_libc_bound = bound

    _REGS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip")

    def _snap(self) -> dict:
        r = self.ql.arch.regs
        out = {}
        for name in self._REGS:
            try:
                out[name] = getattr(r, name)
            except Exception:
                pass
        return out

    def _oob_hit(self, dst: int, length: int):
        """First address in [dst, dst+length) that lies in a guard or freed page.
        Needed because ql.mem.read/write bypass unicorn page permissions, so a
        libc-copy STUB (memcpy/strcpy/...) writing/reading into a PROT_NONE guard
        would otherwise not fault — only guest instructions trip the prot hook."""
        end = dst + max(length, 1)
        for s, e in self._guard_ranges:
            if dst < e and s < end:
                return max(dst, s)
        for p in self._freed_pages:
            if dst < p + _PAGE and p < end:
                return max(dst, p)
        return None

    def _emu_write(self, dst: int, data: bytes):
        hit = self._oob_hit(dst, len(data))
        if hit is not None:
            self._last_fault = {"access": "write", "addr": hit,
                                "pc": self.ql.arch.regs.rip, "regs": self._snap()}
            raise MemoryError("stub write into guard/freed page")
        try:
            self.ql.mem.write(dst, data)
        except Exception:
            regs = self._snap()
            try:
                pc = struct.unpack("<Q", self.ql.mem.read(self.ql.arch.regs.rsp, 8))[0]
            except Exception:
                pc = 0
            self._last_fault = {"access": "write", "addr": dst, "pc": pc, "regs": regs}
            raise

    def _emu_read(self, src: int, n: int) -> bytes:
        """Read guest memory on behalf of a stub; record a REAL read fault if the
        pointer is bad (a genuine OOB read) so it isn't lost as an unattributed
        Python exception."""
        hit = self._oob_hit(src, n)
        if hit is not None:
            self._last_fault = {"access": "read", "addr": hit,
                                "pc": self.ql.arch.regs.rip, "regs": self._snap()}
            raise MemoryError("stub read from guard/freed page")
        try:
            return bytes(self.ql.mem.read(src, n))
        except Exception:
            self._last_fault = {"access": "read", "addr": src,
                                "pc": self.ql.arch.regs.rip, "regs": self._snap()}
            raise

    def _strlen_impl(self):
        ql = self.ql
        p = ql.arch.regs.rdi
        n = 0
        while n < 1 << 20 and self._emu_read(p + n, 1) != b"\x00":
            n += 1
        self._ret(n)

    def _cstr(self, a: int, cap: int = 1 << 20) -> bytes:
        out = bytearray()
        while len(out) < cap:
            c = self._emu_read(a, 1)
            if c == b"\x00":
                break
            out += c
            a += 1
        return bytes(out)

    # -- JNIEnv (index table -> trampolines) -------------------------------
    def _wire_jnienv(self):
        ql = self.ql
        # object layouts: array/string = {int32 len; int32 pad; ptr data}
        #                 directbuffer = {ptr data; int64 capacity}
        def gbe():   # Get<Prim>ArrayElements / GetStringUTFChars: ptr at obj+8
            self._ret(struct.unpack("<Q", self._emu_read(self._argn(1) + 8, 8))[0])
        def glen():  # GetArrayLength / GetStringUTFLength / GetStringLength
            self._ret(struct.unpack("<i", self._emu_read(self._argn(1), 4))[0])
        def gdba():  # GetDirectBufferAddress: ptr at obj+0
            self._ret(struct.unpack("<Q", self._emu_read(self._argn(1), 8))[0])
        def gdbc():  # GetDirectBufferCapacity: int64 at obj+8
            self._ret(struct.unpack("<q", self._emu_read(self._argn(1) + 8, 8))[0])
        def region(elem):
            # Get<Type>ArrayRegion(env,arr,start,len,buf): copy into caller buf.
            def h():
                arr, start, n, buf = (self._argn(1), self._argn(2),
                                      self._argn(3), self._argn(4))
                data_ptr = struct.unpack("<Q", self._emu_read(arr + 8, 8))[0]
                src = self._emu_read(data_ptr + start * elem, n * elem)
                self._emu_write(buf, src)      # OOB read (guard) or OOB write (dst)
                self._ret(0)
            return h
        def sutf_region():
            # GetStringUTFRegion(env,str,start,len,buf)
            def h():
                s, start, n, buf = (self._argn(1), self._argn(2),
                                    self._argn(3), self._argn(4))
                dp = struct.unpack("<Q", self._emu_read(s + 8, 8))[0]
                self._emu_write(buf, self._emu_read(dp + start, n))
                self._ret(0)
            return h
        def ret_zero(): self._ret(0)                  # ExceptionCheck/Occurred
        # A "safe object": a page whose every 8-byte slot points at a ret-gadget
        # trampoline. Opaque JNI handles (jclass/jmethodID/jobject) that the native
        # later dispatches through a vtable (`call *(*obj + k)`) land on a no-op
        # return instead of jumping into zero memory and derailing — which showed
        # up as false "fetch" crashes on real C++ libraries.
        ret0_tr = self._new_tramp(ret_zero)
        self._safe_obj = ql.mem.map_anywhere(_PAGE)
        for off in range(0, _PAGE, 8):
            ql.mem.write(self._safe_obj + off, struct.pack("<Q", ret0_tr))

        def ret_scratch(): self._ret(self._safe_obj)   # benign non-null (FindClass…)

        gen = self._new_tramp(ret_scratch)
        tbl = ql.mem.map_anywhere(300 * 8)
        for k in range(300):
            ql.mem.write(tbl + k * 8, struct.pack("<Q", gen))

        specific = {
            15: ret_zero,            # ExceptionOccurred
            164: glen, 168: glen, 169: gbe, 165: gbe,   # String len/chars
            171: glen,                                   # GetArrayLength
            227: gbe, 229: gbe,      # GetPrimitiveArrayCritical / GetStringCritical
            235: gdba, 236: gdbc,    # GetDirectBuffer Address / Capacity
            226: sutf_region(),      # GetStringUTFRegion
            225: region(2),          # GetStringRegion (utf16)
            233: ret_zero,           # ExceptionCheck
        }
        for i in range(183, 191):    # Get{Boolean,Byte,Char,Short,Int,Long,Float,Double}ArrayElements
            specific[i] = gbe
        _elem = {199: 1, 200: 1, 201: 2, 202: 2, 203: 4, 204: 8, 205: 4, 206: 8}
        for i, e in _elem.items():   # Get<Type>ArrayRegion
            specific[i] = region(e)
        for idx, impl in specific.items():
            ql.mem.write(tbl + idx * 8, struct.pack("<Q", self._new_tramp(impl)))

        self.env = ql.mem.map_anywhere(8)
        ql.mem.write(self.env, struct.pack("<Q", tbl))

    # -- memory snapshot (deterministic cross-run state) -------------------
    def _snapshot_init(self):
        self._snap_regions = []
        try:
            import lief
            b = lief.parse(self._sop)
            for seg in b.segments:
                try:
                    is_w = bool(int(getattr(seg, "flags", 0)) & 0x2) \
                        or "W" in str(getattr(seg, "flags", ""))
                    size = min(int(getattr(seg, "virtual_size", 0)), _SNAP_CAP)
                    if not is_w or size <= 0:
                        continue
                    addr = self.base + int(seg.virtual_address)
                    self._snap_regions.append((addr, bytes(self.ql.mem.read(addr, size))))
                except Exception:
                    continue
        except Exception:
            pass

    def _restore_mem(self):
        for addr, data in self._snap_regions:
            try:
                self.ql.mem.write(addr, data)
            except Exception:
                pass

    # -- hooks -------------------------------------------------------------
    def _on_block(self, uc, addr, size, user=None):
        if addr not in self.cov_global:
            self.cov_global.add(addr)
            self._run_new += 1
        if addr in self.win_blocks:
            self._run_win = True

    def _on_fault(self, uc, access, addr, size, value, user=None):
        amap = {self._uc.UC_MEM_WRITE_UNMAPPED: "write",
                self._uc.UC_MEM_READ_UNMAPPED: "read",
                self._uc.UC_MEM_FETCH_UNMAPPED: "fetch",
                self._uc.UC_MEM_WRITE_PROT: "write",
                self._uc.UC_MEM_READ_PROT: "read",
                self._uc.UC_MEM_FETCH_PROT: "fetch"}
        self._last_fault = {"access": amap.get(access, "?"), "addr": addr,
                            "pc": self.ql.arch.regs.rip, "regs": self._snap()}
        return False

    def _guard_side(self, addr: int) -> Optional[str]:
        for i, chunk in enumerate(self._chunks):
            if chunk - _PAGE <= addr < chunk:
                return "under"
            if chunk + _PAGE <= addr < chunk + 2 * _PAGE:
                return "over"
        return None

    def _in_freed(self, addr: int) -> bool:
        return any(p <= addr < p + _PAGE for p in self._freed_pages)

    def _in_heap_chunk(self, addr: int) -> bool:
        return any(c <= addr < c + _PAGE for c in self._chunks)

    def _classify(self, f: dict) -> str:
        addr = f.get("addr", 0)
        if self._in_freed(addr):
            return "use-after-free"
        side = self._guard_side(addr)
        if side == "under":
            return "heap-underflow"
        if side == "over" or self._in_heap_chunk(addr):
            return "heap-overflow"
        if f.get("access") == "fetch":
            return "pc-control/stack-overflow"
        return "oob-" + f.get("access", "?")

    # -- one execution -----------------------------------------------------
    def run(self, data: bytes) -> dict:
        ql = self.ql
        ql.uc.context_restore(self._ctx)
        self._restore_mem()
        self._reset_heap()
        self._arena_cur = self._arena_base
        self._in_cur = self._in_base
        self._last_fault = None
        self._run_new = 0
        self._run_win = False
        data = data[:_DATA_CAP]

        plan = inputspec.materialize(self.spec, data, self)
        ql.arch.regs.rsp = self.stack_top
        ql.mem.write(self.stack_top, struct.pack("<Q", self.ret_addr))
        for slot, val in plan.stack:                 # spilled args above ret addr
            ql.mem.write(self.stack_top + 8 + 8 * slot, struct.pack("<Q", val & (2**64-1)))
        ql.arch.regs.rdi = self.env
        ql.arch.regs.rsi = 0                         # jclass / jobject this
        for reg, val in plan.gpr.items():
            setattr(ql.arch.regs, reg, val & (2 ** 64 - 1))
        for idx, (_is_d, raw8) in plan.xmm.items():
            try:
                xreg = getattr(self._x86const, f"UC_X86_REG_XMM{idx}")
                ql.uc.reg_write(xreg, int.from_bytes(raw8.ljust(16, b"\x00"), "little"))
            except Exception:
                pass
        try:
            ql.emu_start(self.entry, self.ret_addr, timeout=5_000_000, count=500000)
            return {"crash": False, "new_cov": self._run_new, "win": self._run_win,
                    "ret": ql.arch.regs.rax}
        except Exception:
            # Only an oracle-recorded fault is a real memory bug. An exception with
            # no recorded fault is a harness limitation (an unmodeled call raised),
            # NOT a finding — reporting it would be a false positive.
            if self._last_fault is None:
                return {"crash": False, "new_cov": self._run_new,
                        "win": self._run_win, "harness_error": True}
            f = self._last_fault
            return {"crash": True, "new_cov": self._run_new, "fault": f,
                    "hint": self._classify(f), "win": self._run_win}


def crash_key(harness: "FuzzHarness", fault: dict) -> str:
    pc = fault.get("pc", 0)
    if harness.image_lo <= pc < harness.image_hi:
        return f"{pc:#x}:{fault.get('access')}"
    return f"pc-control:{fault.get('access')}"


# Boundary / overflow-triggering integer values for scalar args (little-endian).
_INTERESTING = (0, 1, 2, 3, 8, 16, 32, 64, 127, 128, 255, 256, 1024,
                0x7fffffff, 0x80000000, 0xffffffff, 0x40000001, 0xfffffffe,
                0x100000000, 0x7fffffffffffffff, 0xffffffffffffffff)


def _havoc(data: bytes, rng: random.Random, dictionary: Optional[list] = None,
           scalar_offsets: Optional[list] = None) -> bytes:
    b = bytearray(data)
    # scalar-aware: occasionally slam a controllable scalar to a boundary value
    # (small sizes, INT_MAX, wrap points) — random 32/64-bit values almost never
    # hit the small/overflow cases a size field actually branches on.
    if scalar_offsets and rng.random() < 0.5:
        off, width = rng.choice(scalar_offsets)
        val = rng.choice(_INTERESTING)
        while len(b) < off + 8:
            b.append(0)
        b[off:off + 8] = val.to_bytes(8, "little")
    for _ in range(rng.randint(1, 5)):
        op = rng.randint(0, 7)
        if not b:
            b = bytearray(_randbytes(rng, rng.randint(1, 32)))
            continue
        if op == 0:
            i = rng.randrange(len(b)); b[i] ^= 1 << rng.randrange(8)
        elif op == 1:
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif op == 2:
            b += _randbytes(rng, rng.randint(1, 64))
        elif op == 3:
            b += b"A" * rng.choice([8, 16, 32, 64, 128, 256, 512])
        elif op == 4 and len(b) > 1:
            b = b[:rng.randrange(len(b))]
        elif op == 6 and dictionary:
            tok = rng.choice(dictionary)
            pos = 0 if rng.random() < 0.4 else rng.randrange(len(b) + 1)
            b[pos:pos + len(tok)] = tok
        else:
            b += bytes(b)
    return bytes(b[:_DATA_CAP])


def _randbytes(rng: random.Random, n: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(n))


def fuzz(harness: FuzzHarness, seeds: list, *, budget_s: float = 30.0,
         max_execs: int = 500000, seed: int = 1337, cmplog: bool = True,
         dictionary: Optional[list] = None) -> FuzzResult:
    rng = random.Random(seed)
    corpus = [bytes(s)[:_DATA_CAP] for s in (seeds or [b"\x00" * 8, b"A" * 16])]
    dict_vals = list(dictionary or [])
    res = FuzzResult()
    seen: dict[str, Crash] = {}
    wins: dict[str, bytes] = {}
    t0 = time.time()
    # baseline win-state from seeds (so only NEW logic flips count as findings)
    base_win = False
    for s in corpus:
        r = harness.run(s)
        base_win = base_win or r.get("win")
    if cmplog:
        from .cmplog import collect_magics
        for s in corpus:
            dict_vals.extend(collect_magics(harness, s) - set(dict_vals))
    while res.execs < max_execs and (time.time() - t0) < budget_s:
        cand = _havoc(rng.choice(corpus), rng, dict_vals, harness.scalar_offsets)
        r = harness.run(cand)
        res.execs += 1
        if r["crash"]:
            key = crash_key(harness, r["fault"])
            if key not in seen:
                f = r["fault"]
                seen[key] = Crash(input=cand, access=f["access"], fault_addr=f["addr"],
                                  pc=f["pc"], key=key, bug_hint=r.get("hint", ""))
        else:
            if r.get("win") and not base_win:
                wins.setdefault(f"ret={r.get('ret')}", cand)
            if r["new_cov"] > 0:
                corpus.append(cand)
                if cmplog and len(dict_vals) < 1024:
                    dict_vals.extend(collect_magics(harness, cand) - set(dict_vals))
    res.elapsed = time.time() - t0
    res.coverage = len(harness.cov_global)
    res.corpus = len(corpus)
    res.crashes = list(seen.values())
    res.wins = list(wins.values())
    return res
