"""Target Knowledge Base (§1, §8) — the single source of truth per target.

Every tool reads/writes here; the LLM orchestrator only ever sees the compact
`summarize()` view, never raw decompilation dumps. One SQLite file per target
makes long, resumable runs reproducible.

Schema is created in full up front (including tables for later phases:
coverage/crashes/findings) so the DB shape is stable from day one, even though
the first step only populates intake + surface data.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Iterable, Optional

SCHEMA_VERSION = 4

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Phase 1: intake -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS targets (
    id              INTEGER PRIMARY KEY,
    name            TEXT UNIQUE,
    path            TEXT,
    sha256          TEXT,
    fmt             TEXT,          -- macho / elf / pe / unknown
    arch            TEXT,          -- x86_64 / aarch64 / ...
    bits            INTEGER,
    source_available INTEGER DEFAULT 0,
    imagebase       TEXT,
    mitigations     TEXT,          -- JSON
    input_vectors   TEXT,          -- JSON list (filled Phase 2+)
    meta            TEXT,          -- JSON (md5, module, segments, ...)
    apk_id          INTEGER REFERENCES apks(id),  -- NULL for standalone binaries
    abi             TEXT,          -- arm64-v8a / x86_64 / ... (for .so targets)
    created_at      REAL
);

-- Phase A: Android/APK front-end (§10) ------------------------------------
CREATE TABLE IF NOT EXISTS apks (
    id                  INTEGER PRIMARY KEY,
    package             TEXT UNIQUE,
    path                TEXT,
    sha256              TEXT,
    version_name        TEXT,
    version_code        TEXT,
    min_sdk             INTEGER,
    target_sdk          INTEGER,
    launchable_activity TEXT,
    abis                TEXT,      -- JSON list
    abi_plan            TEXT,      -- JSON: [{abi, mode}] fuzzing strategy
    meta                TEXT,      -- JSON
    created_at          REAL
);

CREATE TABLE IF NOT EXISTS native_libs (
    id             INTEGER PRIMARY KEY,
    apk_id         INTEGER REFERENCES apks(id),
    abi            TEXT,
    name           TEXT,          -- libfoo.so
    rel_path       TEXT,          -- lib/arm64-v8a/libfoo.so
    extracted_path TEXT,          -- on-disk path after extraction
    sha256         TEXT,
    is_target      INTEGER DEFAULT 1,
    target_id      INTEGER REFERENCES targets(id),  -- set after intake
    UNIQUE(apk_id, abi, name)
);

CREATE TABLE IF NOT EXISTS entry_points (
    id             INTEGER PRIMARY KEY,
    apk_id         INTEGER REFERENCES apks(id),
    component_type TEXT,          -- activity/service/receiver/provider
    name           TEXT,
    exported       INTEGER,
    permission     TEXT,
    intent_filters TEXT,          -- JSON (actions/categories)
    schemes        TEXT,          -- JSON (deep-link schemes/hosts)
    UNIQUE(apk_id, component_type, name)
);

CREATE TABLE IF NOT EXISTS native_methods (
    id             INTEGER PRIMARY KEY,
    apk_id         INTEGER REFERENCES apks(id),
    java_class     TEXT,          -- sg.vantagepoint.uncrackable3.CodeCheck
    java_method    TEXT,          -- bar
    jni_signature  TEXT,          -- (Ljava/lang/String;)Z   (from DEX if known)
    arg_types      TEXT,          -- JSON parsed arg types
    native_symbol  TEXT,          -- Java_sg_vantagepoint_..._bar
    native_lib     TEXT,          -- libfoo
    native_addr    TEXT,          -- resolved address (per-abi, filled by jni_map)
    registration   TEXT,          -- static / dynamic / unresolved
    source_args    TEXT,          -- JSON: which args are attacker-controlled (model)
    created_at     REAL,
    UNIQUE(apk_id, java_class, java_method, native_lib)
);

CREATE TABLE IF NOT EXISTS input_flows (
    id              INTEGER PRIMARY KEY,
    apk_id          INTEGER REFERENCES apks(id),
    entry_point_id  INTEGER REFERENCES entry_points(id),
    native_method_id INTEGER REFERENCES native_methods(id),
    controlled_arg  INTEGER,
    arg_type        TEXT,
    rationale       TEXT,          -- model-inferred linkage (filled later)
    created_at      REAL
);

-- Phase 2: static RE surface -----------------------------------------------
CREATE TABLE IF NOT EXISTS functions (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER REFERENCES targets(id),
    addr       TEXT,
    name       TEXT,
    size       INTEGER,
    UNIQUE(target_id, addr)
);

CREATE TABLE IF NOT EXISTS imports (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER REFERENCES targets(id),
    addr       TEXT,
    name       TEXT,
    module     TEXT,
    UNIQUE(target_id, name)
);

CREATE TABLE IF NOT EXISTS surfaces (
    id                 INTEGER PRIMARY KEY,
    target_id          INTEGER REFERENCES targets(id),
    sink               TEXT,      -- raw symbol as seen (e.g. _memcpy)
    sink_canonical     TEXT,      -- normalized (memcpy)
    sink_category      TEXT,      -- buffer/format/alloc/...
    func_name          TEXT,
    func_addr          TEXT,
    call_addr          TEXT,      -- call site
    reads_input_source INTEGER DEFAULT 0,
    base_score         INTEGER,   -- deterministic prior
    model_score        INTEGER,   -- filled by LLM later
    grammar            TEXT,      -- JSON, inferred input structure (later)
    decompiled         TEXT,      -- caller decompilation (model reads this)
    created_at         REAL,
    UNIQUE(target_id, sink, call_addr)
);

CREATE TABLE IF NOT EXISTS call_edges (
    id          INTEGER PRIMARY KEY,
    target_id   INTEGER REFERENCES targets(id),
    caller_addr TEXT,
    caller_name TEXT,
    callee_addr TEXT,
    callee_name TEXT,
    UNIQUE(target_id, caller_addr, callee_addr)
);

CREATE TABLE IF NOT EXISTS strings (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER REFERENCES targets(id),
    addr       TEXT,
    value      TEXT
);

-- Later phases (schema only for now) ---------------------------------------
CREATE TABLE IF NOT EXISTS coverage (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER REFERENCES targets(id),
    harness    TEXT,
    edges      INTEGER,
    at         REAL
);

CREATE TABLE IF NOT EXISTS crashes (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER REFERENCES targets(id),
    stack_hash TEXT,
    bug_class  TEXT,
    input_path TEXT,
    report     TEXT,
    at         REAL
);

CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER REFERENCES targets(id),
    apk_id     INTEGER REFERENCES apks(id),
    native_method TEXT,
    bug_class  TEXT,
    severity   TEXT,
    bug_key    TEXT,
    summary    TEXT,
    detail     TEXT,          -- JSON (full Finding)
    at         REAL,
    UNIQUE(apk_id, native_method, bug_key)
);

CREATE TABLE IF NOT EXISTS runs (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER REFERENCES targets(id),
    phase      TEXT,
    status     TEXT,
    notes      TEXT,          -- JSON
    started_at REAL,
    ended_at   REAL
);

-- Agent reasoning layer (§8): understanding + strategy ---------------------
CREATE TABLE IF NOT EXISTS app_model (
    id         INTEGER PRIMARY KEY,
    apk_id     INTEGER REFERENCES apks(id),
    kind       TEXT,          -- 'structure' (deterministic) | 'understanding' (LLM)
    model      TEXT,          -- JSON
    created_at REAL,
    UNIQUE(apk_id, kind)
);

CREATE TABLE IF NOT EXISTS research_plan (
    id         INTEGER PRIMARY KEY,
    apk_id     INTEGER REFERENCES apks(id),
    plan       TEXT,          -- JSON (prioritized targets, hypotheses, techniques)
    model_id   TEXT,          -- which LLM produced it
    created_at REAL
);

CREATE INDEX IF NOT EXISTS idx_surfaces_target ON surfaces(target_id);
CREATE INDEX IF NOT EXISTS idx_functions_target ON functions(target_id);
"""


class KB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(_SCHEMA)
        self._migrate()
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced by newer schema versions to pre-existing tables
        (CREATE IF NOT EXISTS won't alter an existing table)."""
        adds = {
            "targets": [("apk_id", "INTEGER"), ("abi", "TEXT")],
            "findings": [("apk_id", "INTEGER"), ("native_method", "TEXT"),
                         ("bug_key", "TEXT")],
        }
        for tbl, cols in adds.items():
            try:
                have = {r[1] for r in self.conn.execute(f"PRAGMA table_info({tbl})")}
            except Exception:
                continue
            for name, decl in cols:
                if name not in have:
                    try:
                        self.conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {name} {decl}")
                    except Exception:
                        pass
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "KB":
        return self

    def __exit__(self, *exc) -> None:
        self.conn.commit()
        self.close()

    # -- targets -----------------------------------------------------------
    def upsert_target(self, *, name: str, path: str, sha256: str, fmt: str,
                      arch: str, bits: int, source_available: bool,
                      imagebase: str, mitigations: dict, meta: dict) -> int:
        now = time.time()
        cur = self.conn.execute("SELECT id FROM targets WHERE name = ?", (name,))
        row = cur.fetchone()
        fields = dict(
            path=path, sha256=sha256, fmt=fmt, arch=arch, bits=bits,
            source_available=int(source_available), imagebase=imagebase,
            mitigations=json.dumps(mitigations), meta=json.dumps(meta),
        )
        if row:
            tid = row["id"]
            sets = ", ".join(f"{k} = ?" for k in fields)
            self.conn.execute(f"UPDATE targets SET {sets} WHERE id = ?",
                              (*fields.values(), tid))
        else:
            cols = ", ".join(["name", *fields.keys(), "input_vectors", "created_at"])
            qs = ", ".join(["?"] * (len(fields) + 3))
            self.conn.execute(
                f"INSERT INTO targets({cols}) VALUES ({qs})",
                (name, *fields.values(), json.dumps([]), now),
            )
            tid = self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        self.conn.commit()
        return tid

    def get_target(self, name: Optional[str] = None,
                   sha256: Optional[str] = None) -> Optional[sqlite3.Row]:
        if name:
            r = self.conn.execute("SELECT * FROM targets WHERE name = ?", (name,))
        elif sha256:
            r = self.conn.execute("SELECT * FROM targets WHERE sha256 = ?", (sha256,))
        else:
            r = self.conn.execute("SELECT * FROM targets ORDER BY id LIMIT 1")
        return r.fetchone()

    def list_targets(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM targets ORDER BY id").fetchall()

    def link_target_to_lib(self, lib_id: int, target_id: int) -> None:
        self.conn.execute("UPDATE native_libs SET target_id=? WHERE id=?",
                          (target_id, lib_id))
        self.conn.execute("UPDATE targets SET apk_id=(SELECT apk_id FROM native_libs "
                          "WHERE id=?), abi=(SELECT abi FROM native_libs WHERE id=?) "
                          "WHERE id=?", (lib_id, lib_id, target_id))
        self.conn.commit()

    # -- Phase A: APK-level ------------------------------------------------
    def upsert_apk(self, *, package: str, path: str, sha256: str,
                   version_name: str, version_code: str, min_sdk, target_sdk,
                   launchable_activity: str, abis: list, abi_plan: list,
                   meta: dict) -> int:
        now = time.time()
        row = self.conn.execute("SELECT id FROM apks WHERE package=?",
                               (package,)).fetchone()
        fields = dict(path=path, sha256=sha256, version_name=version_name,
                      version_code=str(version_code), min_sdk=_as_int(min_sdk),
                      target_sdk=_as_int(target_sdk),
                      launchable_activity=launchable_activity,
                      abis=json.dumps(abis), abi_plan=json.dumps(abi_plan),
                      meta=json.dumps(meta))
        if row:
            aid = row["id"]
            sets = ", ".join(f"{k}=?" for k in fields)
            self.conn.execute(f"UPDATE apks SET {sets} WHERE id=?",
                              (*fields.values(), aid))
        else:
            cols = ", ".join(["package", *fields.keys(), "created_at"])
            qs = ", ".join(["?"] * (len(fields) + 2))
            self.conn.execute(f"INSERT INTO apks({cols}) VALUES ({qs})",
                              (package, *fields.values(), now))
            aid = self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        self.conn.commit()
        return aid

    def clear_apk_children(self, apk_id: int) -> None:
        """Drop derived rows so re-ingesting an APK is idempotent."""
        for tbl in ("native_libs", "entry_points", "native_methods", "input_flows"):
            self.conn.execute(f"DELETE FROM {tbl} WHERE apk_id=?", (apk_id,))
        self.conn.commit()

    def get_apk(self, package: Optional[str] = None) -> Optional[sqlite3.Row]:
        if package:
            r = self.conn.execute("SELECT * FROM apks WHERE package=?", (package,))
        else:
            r = self.conn.execute("SELECT * FROM apks ORDER BY id LIMIT 1")
        return r.fetchone()

    def add_native_libs(self, apk_id: int, libs: Iterable[dict]) -> None:
        for l in libs:
            self.conn.execute(
                "INSERT OR IGNORE INTO native_libs(apk_id, abi, name, rel_path, "
                "extracted_path, sha256, is_target) VALUES (?,?,?,?,?,?,?)",
                (apk_id, l["abi"], l["name"], l.get("rel_path"),
                 l.get("extracted_path"), l.get("sha256"), int(l.get("is_target", 1))))
        self.conn.commit()

    def get_native_libs(self, apk_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM native_libs WHERE apk_id=? ORDER BY abi, name",
            (apk_id,)).fetchall()

    def add_entry_points(self, apk_id: int, eps: Iterable[dict]) -> None:
        for e in eps:
            self.conn.execute(
                "INSERT OR IGNORE INTO entry_points(apk_id, component_type, name, "
                "exported, permission, intent_filters, schemes) VALUES (?,?,?,?,?,?,?)",
                (apk_id, e["component_type"], e["name"], int(e.get("exported", 0)),
                 e.get("permission"), json.dumps(e.get("intent_filters", [])),
                 json.dumps(e.get("schemes", []))))
        self.conn.commit()

    def add_native_methods(self, apk_id: int, methods: Iterable[dict]) -> None:
        for m in methods:
            self.conn.execute(
                "INSERT OR IGNORE INTO native_methods(apk_id, java_class, java_method, "
                "jni_signature, arg_types, native_lib, registration, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (apk_id, m.get("java_class"), m.get("java_method"),
                 m.get("jni_signature"), json.dumps(m.get("arg_types", [])),
                 m.get("native_lib"), m.get("registration", "unresolved"),
                 time.time()))
        self.conn.commit()

    def update_native_method(self, apk_id: int, java_class: str, java_method: str,
                             **fields) -> None:
        if not fields:
            return
        sets = ", ".join(f"{k}=?" for k in fields)
        self.conn.execute(
            f"UPDATE native_methods SET {sets} WHERE apk_id=? AND java_class=? "
            "AND java_method=?",
            (*fields.values(), apk_id, java_class, java_method))
        self.conn.commit()

    def get_native_methods(self, apk_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM native_methods WHERE apk_id=? ORDER BY java_class, java_method",
            (apk_id,)).fetchall()

    # -- findings (Phase 5 output) ----------------------------------------
    def add_finding(self, apk_id: int, native_method: str, bug_class: str,
                    severity: str, bug_key: str, summary: str, detail: dict) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO findings(apk_id, native_method, bug_class, "
            "severity, bug_key, summary, detail, at) VALUES (?,?,?,?,?,?,?,?)",
            (apk_id, native_method, bug_class, severity, bug_key, summary,
             json.dumps(detail), time.time()))
        self.conn.commit()

    def get_findings(self, apk_id: int) -> list:
        rows = self.conn.execute(
            "SELECT native_method, bug_class, severity, summary, detail FROM findings "
            "WHERE apk_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 "
            "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END", (apk_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r); d["detail"] = json.loads(d["detail"] or "{}")
            out.append(d)
        return out

    def clear_findings(self, apk_id: int) -> None:
        self.conn.execute("DELETE FROM findings WHERE apk_id=?", (apk_id,))
        self.conn.commit()

    def attach_decompile(self, apk_id: int, native_method: str, decompiled: str) -> int:
        """Store IDA Hex-Rays decompilation into the detail of a method's findings."""
        rows = self.conn.execute(
            "SELECT id, detail FROM findings WHERE apk_id=? AND native_method=?",
            (apk_id, native_method)).fetchall()
        n = 0
        for r in rows:
            d = json.loads(r["detail"] or "{}")
            d["decompiled"] = decompiled
            self.conn.execute("UPDATE findings SET detail=? WHERE id=?",
                              (json.dumps(d), r["id"]))
            n += 1
        self.conn.commit()
        return n

    # -- agent reasoning layer --------------------------------------------
    def set_app_model(self, apk_id: int, kind: str, model: dict) -> None:
        self.conn.execute(
            "INSERT INTO app_model(apk_id, kind, model, created_at) VALUES (?,?,?,?) "
            "ON CONFLICT(apk_id, kind) DO UPDATE SET model=excluded.model, "
            "created_at=excluded.created_at",
            (apk_id, kind, json.dumps(model), time.time()))
        self.conn.commit()

    def get_app_model(self, apk_id: int, kind: str) -> Optional[dict]:
        r = self.conn.execute("SELECT model FROM app_model WHERE apk_id=? AND kind=?",
                             (apk_id, kind)).fetchone()
        return json.loads(r["model"]) if r else None

    def set_research_plan(self, apk_id: int, plan: dict, model_id: str) -> None:
        self.conn.execute(
            "INSERT INTO research_plan(apk_id, plan, model_id, created_at) "
            "VALUES (?,?,?,?)", (apk_id, json.dumps(plan), model_id, time.time()))
        self.conn.commit()

    def get_research_plan(self, apk_id: int) -> Optional[dict]:
        r = self.conn.execute(
            "SELECT plan FROM research_plan WHERE apk_id=? ORDER BY id DESC LIMIT 1",
            (apk_id,)).fetchone()
        return json.loads(r["plan"]) if r else None

    def summarize_apk(self, apk_id: int) -> dict:
        c = self.conn
        a = c.execute("SELECT * FROM apks WHERE id=?", (apk_id,)).fetchone()
        libs = c.execute("SELECT abi, name FROM native_libs WHERE apk_id=?",
                        (apk_id,)).fetchall()
        eps = c.execute("SELECT component_type, name, exported FROM entry_points "
                       "WHERE apk_id=? AND exported=1", (apk_id,)).fetchall()
        meths = c.execute("SELECT java_class, java_method, native_symbol, "
                         "native_addr, registration, arg_types, jni_signature, "
                         "source_args, native_lib "
                         "FROM native_methods WHERE apk_id=?", (apk_id,)).fetchall()
        meths = [dict(m) for m in meths]
        for m in meths:
            m["flow"] = json.loads(m.pop("source_args") or "{}")
            m["arg_types"] = json.loads(m["arg_types"] or "[]")
        meths.sort(key=lambda m: (not m["flow"].get("controllable"),
                                  not m["flow"].get("reachable")))
        return {
            "package": a["package"],
            "version": f'{a["version_name"]} ({a["version_code"]})',
            "min_sdk": a["min_sdk"], "target_sdk": a["target_sdk"],
            "launchable_activity": a["launchable_activity"],
            "abis": json.loads(a["abis"] or "[]"),
            "abi_plan": json.loads(a["abi_plan"] or "[]"),
            "native_libs": [dict(r) for r in libs],
            "exported_entry_points": [dict(r) for r in eps],
            "native_methods": meths,
            "counts": {
                "native_libs": len(libs),
                "exported_entry_points": len(eps),
                "native_methods": len(meths),
                "resolved_methods": sum(1 for m in meths if m["native_symbol"]),
                "controllable": sum(1 for m in meths if m["flow"].get("controllable")),
            },
        }

    # -- phase 2 writes ----------------------------------------------------
    def add_functions(self, target_id: int, funcs: Iterable[dict]) -> int:
        rows = [(target_id, f.get("addr"), f.get("name"),
                 _as_int(f.get("size"))) for f in funcs]
        self.conn.executemany(
            "INSERT OR IGNORE INTO functions(target_id, addr, name, size) "
            "VALUES (?,?,?,?)", rows)
        self.conn.commit()
        return len(rows)

    def add_imports(self, target_id: int, imps: Iterable[dict]) -> int:
        rows = [(target_id, i.get("addr"), i.get("imported_name") or i.get("name"),
                 i.get("module")) for i in imps]
        self.conn.executemany(
            "INSERT OR IGNORE INTO imports(target_id, addr, name, module) "
            "VALUES (?,?,?,?)", rows)
        self.conn.commit()
        return len(rows)

    def add_surface(self, target_id: int, **f: Any) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO surfaces(target_id, sink, sink_canonical, "
            "sink_category, func_name, func_addr, call_addr, reads_input_source, "
            "base_score, model_score, decompiled, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (target_id, f.get("sink"), f.get("sink_canonical"),
             f.get("sink_category"), f.get("func_name"), f.get("func_addr"),
             f.get("call_addr"), int(f.get("reads_input_source", 0)),
             f.get("base_score"), f.get("model_score"), f.get("decompiled"),
             time.time()))
        self.conn.commit()

    def add_call_edges(self, target_id: int, edges: Iterable[dict]) -> int:
        rows = [(target_id, e["caller_addr"], e.get("caller_name"),
                 e["callee_addr"], e.get("callee_name")) for e in edges]
        self.conn.executemany(
            "INSERT OR IGNORE INTO call_edges(target_id, caller_addr, "
            "caller_name, callee_addr, callee_name) VALUES (?,?,?,?,?)", rows)
        self.conn.commit()
        return len(rows)

    def add_strings(self, target_id: int, items: Iterable[dict]) -> int:
        rows = [(target_id, s.get("addr"), s.get("value")) for s in items]
        self.conn.executemany(
            "INSERT INTO strings(target_id, addr, value) VALUES (?,?,?)", rows)
        self.conn.commit()
        return len(rows)

    # -- provenance --------------------------------------------------------
    def start_run(self, target_id: int, phase: str) -> int:
        self.conn.execute(
            "INSERT INTO runs(target_id, phase, status, started_at) "
            "VALUES (?,?,?,?)", (target_id, phase, "running", time.time()))
        rid = self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        self.conn.commit()
        return rid

    def end_run(self, run_id: int, status: str, notes: Optional[dict] = None) -> None:
        self.conn.execute(
            "UPDATE runs SET status = ?, notes = ?, ended_at = ? WHERE id = ?",
            (status, json.dumps(notes or {}), time.time(), run_id))
        self.conn.commit()

    # -- orchestrator view (§8: summary, never raw data) -------------------
    def summarize(self, target_id: int) -> dict:
        c = self.conn
        tgt = c.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        n_funcs = c.execute("SELECT COUNT(*) FROM functions WHERE target_id=?",
                            (target_id,)).fetchone()[0]
        n_surf = c.execute("SELECT COUNT(*) FROM surfaces WHERE target_id=?",
                           (target_id,)).fetchone()[0]
        top = c.execute(
            "SELECT sink, sink_category, func_name, func_addr, reads_input_source, "
            "base_score FROM surfaces WHERE target_id=? "
            "ORDER BY base_score DESC, reads_input_source DESC LIMIT 15",
            (target_id,)).fetchall()
        by_cat = c.execute(
            "SELECT sink_category, COUNT(*) n FROM surfaces WHERE target_id=? "
            "GROUP BY sink_category ORDER BY n DESC", (target_id,)).fetchall()
        return {
            "target": {
                "name": tgt["name"], "fmt": tgt["fmt"], "arch": tgt["arch"],
                "bits": tgt["bits"], "source_available": bool(tgt["source_available"]),
                "mitigations": json.loads(tgt["mitigations"] or "{}"),
            },
            "counts": {"functions": n_funcs, "imports":
                       c.execute("SELECT COUNT(*) FROM imports WHERE target_id=?",
                                 (target_id,)).fetchone()[0],
                       "surfaces": n_surf,
                       "call_edges":
                       c.execute("SELECT COUNT(*) FROM call_edges WHERE target_id=?",
                                 (target_id,)).fetchone()[0],
                       "strings":
                       c.execute("SELECT COUNT(*) FROM strings WHERE target_id=?",
                                 (target_id,)).fetchone()[0]},
            "surfaces_by_category": {r["sink_category"]: r["n"] for r in by_cat},
            "top_surfaces": [dict(r) for r in top],
        }


def _as_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v), 0)  # handles "0x1ad"
    except (ValueError, TypeError):
        return None
