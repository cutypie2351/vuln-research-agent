"""Static configuration: IDA endpoint, sink/source catalogs, scoring.

These catalogs drive Phase 2 surface mapping (§3) and feed back into the
vuln-class oracle selection (§7). Names are matched underscore-insensitively
so the same catalog works for ELF (`memcpy`) and Mach-O (`_memcpy`).
"""
from __future__ import annotations

IDA_MCP_URL = "http://127.0.0.1:13337/mcp"

# Dangerous sinks grouped by the vuln classes they tend to produce (§7).
# category -> set of canonical (underscore-stripped) names.
SINK_CATEGORIES: dict[str, set[str]] = {
    "buffer": {
        "memcpy", "memmove", "strcpy", "strcat", "stpcpy", "bcopy",
        "sprintf", "vsprintf", "gets", "strncpy", "strncat", "strlcpy",
        "strlcat", "wmemcpy", "wcscpy", "wcscat",
    },
    "format": {
        "printf", "fprintf", "snprintf", "vsnprintf", "vprintf", "vfprintf",
        "syslog", "asprintf", "vasprintf", "dprintf",
    },
    "alloc": {
        "malloc", "calloc", "realloc", "reallocf", "alloca", "valloc",
        "aligned_alloc", "memalign", "posix_memalign",
    },
    "read_sink": {  # read primitives: both a sink and an input source
        "read", "recv", "recvfrom", "fread", "fgets", "scanf", "sscanf",
        "fscanf", "vscanf",
    },
    "exec": {
        "system", "popen", "execve", "execl", "execlp", "execvp", "execve",
        "posix_spawn",
    },
}

# Flat map: canonical name -> category, for quick lookup.
SINKS: dict[str, str] = {
    name: cat for cat, names in SINK_CATEGORIES.items() for name in names
}

# Input sources: where attacker-controlled bytes enter the program (§3).
INPUT_SOURCES: set[str] = {
    "read", "recv", "recvfrom", "fread", "fgets", "getenv", "scanf", "fscanf",
    "sscanf", "fgetc", "getchar", "getline", "getdelim", "mmap", "pread",
    "readv", "recvmsg",
}

# Deterministic base score per sink category (0-100). The model refines this
# later with reachability/grammar reasoning; this is just a stable prior so the
# KB can rank surfaces before any LLM call.
CATEGORY_BASE_SCORE: dict[str, int] = {
    "buffer": 70,
    "exec": 65,
    "format": 55,
    "read_sink": 50,
    "alloc": 45,
}
# Bonus when an input source reaches the same function as the sink.
INPUT_REACH_BONUS = 25


def canonical(symbol: str) -> str:
    """Strip leading underscores (Mach-O `_memcpy`, `___memcpy_chk` -> ...).

    Also strips a trailing `_chk` (FORTIFY variants) so `__memcpy_chk` maps to
    the `memcpy` catalog entry.
    """
    s = symbol.lstrip("_")
    if s.endswith("_chk"):
        s = s[: -len("_chk")]
    return s
