"""In-situ Frida harness (§10 A.5, Tier-1) — validated on a real Android app.

Runs the REAL `.so` inside the app on a booted emulator/device with the real
JNIEnv/libc/linker — no modeling. This crosses the fidelity ceiling the Qiling
harness hits on large C++/Flutter natives, resolves dynamically-registered
symbols for free (real loader), and doubles as a ground-truth confirmation of the
static taint verdict.

frida-17 notes (learned the hard way, 2026-10-06):
  * The built-in `Java` bridge was REMOVED in frida 17. We therefore do NOT use
    it: the JNIEnv is obtained straight from libart
    (`JNI_GetCreatedJavaVMs` -> `AttachCurrentThread`) and arguments are built
    through the JNIEnv function table by index (same indices the Qiling harness
    models), via `NativeFunction`.
  * The old `Module.getExportByName(null, …)` static is gone; use
    `Module.getGlobalExportByName`, `Module.load`, and instance
    `module.getExportByName`.
  * SELinux (enforcing) blocks mapping an executable from /data/local/tmp for the
    app domain. The lib is staged into the app's `code_cache` (app_data_file,
    which the app may map) with the app uid + a restorecon, then `Module.load`ed.

Crash detection: `Process.setExceptionHandler` catches SIGSEGV/SIGBUS/SIGILL and
reports the fault; recovery after a real fault isn't reliable, so the driver
respawns per crash (throughput path = AFL++ frida_mode; this is the
confirmation/triage path).
"""
from __future__ import annotations

import binascii
import os
import subprocess
from dataclasses import dataclass, field
from typing import Optional

# Bridge-free agent: libart JNIEnv + JNIEnv-vtable arg construction + call.
_AGENT_JS = r"""
'use strict';
var FAULT = null;
Process.setExceptionHandler(function (d) {
  FAULT = { type: d.type,
            address: d.address ? d.address.toString() : null,
            pc: (d.context && d.context.pc) ? d.context.pc.toString() : null };
  send({ event: 'crash', fault: FAULT });
  return false;                 // not handled -> process faults; driver respawns
});

var PS = Process.pointerSize;
function envFn(env, idx, ret, args) {
  var tbl = env.readPointer();
  return new NativeFunction(tbl.add(idx * PS).readPointer(), ret, args);
}
function getEnv() {
  var art = Process.getModuleByName('libart.so');
  var getVMs = new NativeFunction(art.getExportByName('JNI_GetCreatedJavaVMs'),
                                  'int', ['pointer', 'int', 'pointer']);
  var vmB = Memory.alloc(PS), nB = Memory.alloc(4);
  getVMs(vmB, 1, nB);
  var vm = vmB.readPointer();
  var attach = new NativeFunction(vm.readPointer().add(4 * PS).readPointer(),
                                  'int', ['pointer', 'pointer', 'pointer']);
  var eB = Memory.alloc(PS);
  attach(vm, eB, NULL);         // AttachCurrentThread -> JNIEnv for this thread
  return eB.readPointer();
}

var ENV = null, MOD = null, FN = null;
function hexToBuf(h) {
  var n = h.length / 2, buf = Memory.alloc(n ? n : 1);
  for (var i = 0; i < n; i++) buf.add(i).writeU8(parseInt(h.substr(i * 2, 2), 16));
  return { buf: buf, n: n };
}

rpc.exports = {
  setup: function (soPath, symbol) {
    MOD = Module.load(soPath);
    ENV = getEnv();
    var addr = MOD.getExportByName(symbol);
    FN = new NativeFunction(addr, 'pointer', ['pointer', 'pointer', 'pointer']);
    return { base: MOD.base.toString(), sym: addr.toString() };
  },
  runString: function (hexInput) {
    FAULT = null;
    var d = hexToBuf(hexInput);
    // Sanitize to valid Modified UTF-8 (printable ASCII): NewStringUTF under
    // CheckJNI ABORTS on malformed bytes, which would be a false "crash" in arg
    // construction, not a bug in the native. Byte values are mapped into
    // 0x20-0x7e. (Arbitrary bytes into a native belong on the byte[] path.)
    var cstr = Memory.alloc(d.n + 1);
    for (var i = 0; i < d.n; i++) {
      var b = d.buf.add(i).readU8() & 0x7f;
      if (b < 0x20 || b === 0x7f) b = 0x20 + (b % 0x5f);
      cstr.add(i).writeU8(b);
    }
    cstr.add(d.n).writeU8(0);
    var NewStringUTF = envFn(ENV, 167, 'pointer', ['pointer', 'pointer']);
    var js = NewStringUTF(ENV, cstr);
    try { return { ret: FN(ENV, NULL, js).toString(), fault: FAULT }; }
    catch (e) { return { err: String(e), fault: FAULT }; }
  },
  runByteArray: function (hexInput) {
    FAULT = null;
    var d = hexToBuf(hexInput);
    var NewByteArray = envFn(ENV, 176, 'pointer', ['pointer', 'int']);
    var SetRegion = envFn(ENV, 208, 'void',
                          ['pointer', 'pointer', 'int', 'int', 'pointer']);
    var arr = NewByteArray(ENV, d.n);
    if (d.n) SetRegion(ENV, arr, 0, d.n, d.buf);
    try { return { ret: FN(ENV, NULL, arr).toString(), fault: FAULT }; }
    catch (e) { return { err: String(e), fault: FAULT }; }
  }
};
"""


@dataclass
class FridaCrash:
    input: bytes
    fault: dict
    kind: str = "in-situ-fault"


@dataclass
class FridaResult:
    execs: int = 0
    crashes: list = field(default_factory=list)
    note: str = ""


def _adb() -> str:
    home = os.environ.get("ANDROID_HOME", "/Users/admin/Library/Android/sdk")
    return os.path.join(home, "platform-tools", "adb")


def stage_lib(package: str, host_so: str, *, adb: Optional[str] = None) -> str:
    """Copy an extracted .so into the app's code_cache (so the app domain may map
    it under SELinux) and return the on-device path. Needs `adb root`."""
    adb = adb or _adb()
    name = "vra_" + os.path.basename(host_so)
    tmp = f"/data/local/tmp/{name}"
    dd = f"/data/data/{package}"
    dev = f"{dd}/code_cache/{name}"
    subprocess.run([adb, "root"], capture_output=True)
    subprocess.run([adb, "wait-for-device"], capture_output=True)
    subprocess.run([adb, "push", host_so, tmp], capture_output=True)
    uid = subprocess.run([adb, "shell", "stat", "-c", "%u", dd],
                         capture_output=True, text=True).stdout.strip()
    subprocess.run([adb, "shell",
                    f"mkdir -p {dd}/code_cache; cp {tmp} {dev} && "
                    f"chown {uid}:{uid} {dev} && chmod 755 {dev} && "
                    f"restorecon {dev} 2>/dev/null"], capture_output=True)
    return dev


class FridaInSitu:
    """Drive one native in the real app. bytearray/string arg kinds supported."""

    def __init__(self, package: str, device_so: str, symbol: str, *,
                 arg_kind: str = "bytearray", device=None):
        import frida
        self._frida = frida
        self.package = package
        self.device_so = device_so
        self.symbol = symbol
        self.arg_kind = arg_kind
        self.device = device or frida.get_usb_device(timeout=10)
        self._session = self._script = self._pid = None
        self._crash = None

    def _spawn(self):
        self._crash = None
        self._pid = self.device.spawn([self.package])
        self._session = self.device.attach(self._pid)
        self._script = self._session.create_script(_AGENT_JS)
        self._script.on("message", self._on_message)
        self._script.load()
        self.device.resume(self._pid)
        import time
        time.sleep(1.5)                     # let ART come up before we attach a VM
        self._api().setup(self.device_so, self.symbol)

    def _api(self):
        return (self._script.exports_sync if hasattr(self._script, "exports_sync")
                else self._script.exports)

    def _on_message(self, message, data):
        if message.get("type") == "send":
            p = message.get("payload") or {}
            if p.get("event") == "crash":
                self._crash = p.get("fault")

    def _kill(self):
        try:
            if self._pid is not None:
                self.device.kill(self._pid)
        except Exception:
            pass
        self._session = self._pid = self._script = None

    def run(self, data: bytes) -> dict:
        if self._session is None:
            self._spawn()
        hexin = binascii.hexlify(data).decode()
        method = "run_byte_array" if self.arg_kind == "bytearray" else "run_string"
        try:
            out = getattr(self._api(), method)(hexin)
        except self._frida.core.RPCException:
            out = {"err": "rpc exception (native fault)"}
        except Exception as e:
            out = {"err": str(e)}
        if self._crash is not None:
            fault = self._crash             # SIGSEGV/SIGBUS/SIGILL via handler
            self._kill()
            return {"crash": True, "fault": fault}
        err = out.get("err") or ""
        # With VALID args, an abort/fatal from the native is a real bug too
        # (stack canary / FORTIFY / libc fatal / checked-JNI on corrupt state) —
        # setExceptionHandler doesn't see SIGABRT, so catch it here.
        if err and any(k in err.lower() for k in
                       ("abort", "fatal", "rpc exception", "sigabrt", "killed")):
            self._kill()
            return {"crash": True, "fault": {"type": "abort", "detail": err}}
        return {"crash": False, "ret": out.get("ret"), "error": err}

    def close(self):
        self._kill()


def fuzz_in_situ(package: str, device_so: str, symbol: str, seeds: list, *,
                 arg_kind: str = "bytearray", execs: int = 2000,
                 device=None) -> FridaResult:
    import random
    h = FridaInSitu(package, device_so, symbol, arg_kind=arg_kind, device=device)
    rng = random.Random(1337)
    corpus = [bytes(s) for s in (seeds or [b"A" * 16])]
    res = FridaResult()
    seen = set()
    try:
        for _ in range(execs):
            cand = _mutate(rng.choice(corpus), rng)
            r = h.run(cand)
            res.execs += 1
            if r.get("crash"):
                f = r["fault"] or {}
                key = f.get("pc") or f.get("address") or f.get("detail", "")[:60]
                if key not in seen:
                    seen.add(key)
                    res.crashes.append(FridaCrash(input=cand, fault=r["fault"]))
    finally:
        h.close()
    res.note = f"{len(res.crashes)} unique in-situ fault(s)"
    return res


def _mutate(data: bytes, rng) -> bytes:
    b = bytearray(data or b"A")
    for _ in range(rng.randint(1, 4)):
        op = rng.randint(0, 3)
        if op == 0 and b:
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        elif op == 1:
            b += b"A" * rng.choice([8, 32, 128, 512, 4096])
        elif op == 2 and len(b) > 1:
            b = b[:rng.randrange(len(b))]
        else:
            b += bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
    return bytes(b)
