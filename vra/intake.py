"""Phase 1 — Intake (§2).

Determine format / arch / bits / mitigations for a target binary. This decides
downstream instrumentation strategy. Detection is file-based (independent of
IDA) so it also works before/around the RE backend.

Strategy:
  - Prefer `lief` when importable (richest, cross-format).
  - Otherwise fall back to a small stdlib magic/header sniffer, plus `otool`/
    `nm` for Mach-O mitigations on macOS.
  - Anything we cannot determine is reported as "unknown", never guessed.
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional

try:  # optional, richer backend
    import lief  # type: ignore
    _HAVE_LIEF = True
except Exception:  # pragma: no cover
    lief = None
    _HAVE_LIEF = False


# Mach-O magics (as read little-endian from the first 4 bytes on disk).
_MACHO_MAGICS = {0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE}
_MACHO_FAT = {0xCAFEBABE, 0xBEBAFEED, 0xCAFEBABF}
MH_PIE = 0x00200000

_CPU = {
    0x01000007: "x86_64", 0x00000007: "x86",
    0x0100000C: "aarch64", 0x0000000C: "arm",
}
_ELF_MACHINE = {0x3E: "x86_64", 0xB7: "aarch64", 0x28: "arm", 0x03: "x86",
                0x08: "mips", 0x15: "ppc64"}
_PE_MACHINE = {0x8664: "x86_64", 0x14C: "x86", 0xAA64: "aarch64", 0x1C0: "arm"}


@dataclass
class Target:
    path: str
    name: str
    sha256: str
    fmt: str = "unknown"            # macho / elf / pe / unknown
    arch: str = "unknown"
    bits: int = 0
    source_available: bool = False
    imagebase: str = ""
    input_vectors: list = field(default_factory=list)
    mitigations: dict = field(default_factory=dict)
    meta: dict = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def intake(path: str, name: Optional[str] = None,
           source_available: bool = False) -> Target:
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    name = name or os.path.basename(path)
    tgt = Target(path=path, name=name, sha256=sha256_file(path),
                 source_available=source_available)

    with open(path, "rb") as fh:
        head = fh.read(64)
    magic_le = struct.unpack("<I", head[:4])[0] if len(head) >= 4 else 0

    if magic_le in _MACHO_MAGICS or magic_le in _MACHO_FAT:
        tgt.fmt = "macho"
        _sniff_macho(path, head, magic_le, tgt)
    elif head[:4] == b"\x7fELF":
        tgt.fmt = "elf"
        _sniff_elf(head, tgt)
    elif head[:2] == b"MZ":
        tgt.fmt = "pe"
        _sniff_pe(path, head, tgt)

    if _HAVE_LIEF:
        _enrich_with_lief(path, tgt)
    return tgt


# -- Mach-O -----------------------------------------------------------------
def _sniff_macho(path: str, head: bytes, magic_le: int, tgt: Target) -> None:
    if magic_le in _MACHO_FAT:
        tgt.meta["fat"] = True
        archs = _fat_archs(path, magic_le)
        tgt.meta["fat_archs"] = archs
        # Prefer x86_64, then arm64, for the representative header parse.
        pref = next((a for a in archs if a["arch"] == "x86_64"),
                    archs[0] if archs else None)
        if pref:
            tgt.arch = pref["arch"]
            tgt.bits = 64 if "64" in pref["arch"] or pref["arch"] == "aarch64" else 32
            with open(path, "rb") as fh:
                fh.seek(pref["offset"])
                slice_head = fh.read(32)
            _parse_macho_header(slice_head, tgt)
        return
    _parse_macho_header(head, tgt)


def _parse_macho_header(head: bytes, tgt: Target) -> None:
    magic = struct.unpack("<I", head[:4])[0]
    is64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    tgt.bits = 64 if is64 else 32
    cputype = struct.unpack("<i", head[4:8])[0] & 0xFFFFFFFF
    tgt.arch = _CPU.get(cputype, tgt.arch if tgt.arch != "unknown" else "unknown")
    # 64-bit header: magic,cputype,cpusubtype,filetype,ncmds,sizeofcmds,flags,res
    flags = struct.unpack("<I", head[24:28])[0] if len(head) >= 28 else 0
    pie = bool(flags & MH_PIE)
    tgt.mitigations.update({
        "pie": pie,
        "nx": True,  # W^X is enforced on modern Mach-O
        "canary": _macho_has_canary(tgt.path),
        "arc": "unknown",
        "code_signature": _macho_signed(tgt.path),
    })


def _fat_archs(path: str, magic_le: int) -> list[dict]:
    is64 = magic_le == 0xCAFEBABF
    out: list[dict] = []
    with open(path, "rb") as fh:
        fh.read(4)
        nfat = struct.unpack(">I", fh.read(4))[0]
        entry = 32 if is64 else 20
        off_fmt = ">Q" if is64 else ">I"
        for _ in range(min(nfat, 32)):
            raw = fh.read(entry)
            if len(raw) < entry:
                break
            cputype = struct.unpack(">i", raw[0:4])[0] & 0xFFFFFFFF
            if is64:
                offset = struct.unpack(">Q", raw[8:16])[0]
            else:
                offset = struct.unpack(">I", raw[8:12])[0]
            out.append({"arch": _CPU.get(cputype, f"cpu:{cputype:#x}"),
                        "offset": offset})
    return out


def _macho_has_canary(path: str) -> Any:
    out = _run(["otool", "-Iv", path]) or _run(["nm", "-u", path])
    if out is None:
        return "unknown"
    return "stack_chk_guard" in out or "stack_chk_fail" in out


def _macho_signed(path: str) -> Any:
    if not shutil.which("codesign"):
        return "unknown"
    rc = subprocess.run(["codesign", "-dv", path], capture_output=True)
    return rc.returncode == 0


# -- ELF --------------------------------------------------------------------
def _sniff_elf(head: bytes, tgt: Target) -> None:
    ei_class = head[4]           # 1=32, 2=64
    ei_data = head[5]            # 1=LE, 2=BE
    tgt.bits = 64 if ei_class == 2 else 32
    endian = "<" if ei_data == 1 else ">"
    e_machine = struct.unpack(endian + "H", head[18:20])[0]
    e_type = struct.unpack(endian + "H", head[16:18])[0]
    tgt.arch = _ELF_MACHINE.get(e_machine, f"machine:{e_machine:#x}")
    # e_type: 2=ET_EXEC (no-PIE), 3=ET_DYN (PIE or shared lib)
    tgt.mitigations.update({"pie": e_type == 3, "nx": "unknown",
                            "canary": "unknown", "relro": "unknown"})
    tgt.meta["e_type"] = {2: "EXEC", 3: "DYN"}.get(e_type, e_type)


# -- PE ---------------------------------------------------------------------
def _sniff_pe(path: str, head: bytes, tgt: Target) -> None:
    with open(path, "rb") as fh:
        data = fh.read(1024)
    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    if e_lfanew + 6 <= len(data) and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
        machine = struct.unpack("<H", data[e_lfanew + 4:e_lfanew + 6])[0]
        tgt.arch = _PE_MACHINE.get(machine, f"machine:{machine:#x}")
        tgt.bits = 64 if tgt.arch in ("x86_64", "aarch64") else 32
    tgt.mitigations.update({"aslr": "unknown", "dep": "unknown",
                            "canary": "unknown"})


# -- lief enrichment --------------------------------------------------------
def _enrich_with_lief(path: str, tgt: Target) -> None:
    try:
        b = lief.parse(path)
        if b is None:
            return
        if tgt.imagebase == "":
            try:
                tgt.imagebase = hex(b.imagebase)
            except Exception:
                pass
        # lief gives reliable canary/nx on ELF where our sniffer said unknown.
        if tgt.fmt == "elf":
            syms = {s.name for s in b.symbols}
            if tgt.mitigations.get("canary") == "unknown":
                tgt.mitigations["canary"] = "__stack_chk_fail" in syms
    except Exception:
        pass


def _run(cmd: list[str]) -> Optional[str]:
    if not shutil.which(cmd[0]):
        return None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.stdout + r.stderr
    except Exception:
        return None
