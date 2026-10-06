"""Seed corpus + static dictionary from the target (§4 seeds/dictionary).

Static companion to CmpLog: pulls printable strings and rodata constants from
the .so to seed the corpus and prime the dictionary (magic bytes, format tags),
and synthesizes a few structural seeds from the JNI arg type. CmpLog then learns
the rest dynamically.
"""
from __future__ import annotations

import re
import struct

_ASCII = re.compile(rb"[ -~]{4,}")


def strings_from_so(so_path: str, limit: int = 2000) -> list:
    out = []
    try:
        import lief
        b = lief.parse(so_path)
        for sec in b.sections:
            if sec.name in (".rodata", ".data", ".rdata") and sec.size:
                data = bytes(sec.content)
                for m in _ASCII.finditer(data):
                    out.append(m.group(0))
                    if len(out) >= limit:
                        return out
    except Exception:
        pass
    return out


def dictionary(so_path: str) -> list:
    """Dictionary entries: short strings + their lengths as 4-byte LE ints."""
    toks = set()
    for s in strings_from_so(so_path):
        if 1 <= len(s) <= 32:
            toks.add(s)
    # common length/magic encodings
    for v in (0, 1, 8, 16, 24, 32, 64, 128, 255, 256, 1024):
        toks.add(struct.pack("<I", v))
        toks.add(struct.pack("<H", v & 0xFFFF))
    return list(toks)


def seeds(so_path: str, arg_type: str = "byte[]") -> list:
    """A small, diverse starter corpus for a byte[]/String argument."""
    base = [b"", b"\x00" * 4, b"A" * 8, b"A" * 16, b"A" * 24, b"A" * 64,
            bytes(range(32))]
    # a few short strings as realistic seeds
    for s in strings_from_so(so_path)[:16]:
        if len(s) <= 64:
            base.append(s)
    # de-dup preserving order
    seen, out = set(), []
    for s in base:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out
