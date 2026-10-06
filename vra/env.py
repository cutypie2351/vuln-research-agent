"""Tool discovery for the host toolchain (Android SDK, jadx, apktool, JDK).

Keeps subprocess call sites clean and avoids hardcoding paths. All Android
tooling was installed manually (no Homebrew on Intel macOS); locations are the
ones set up in ~/.zprofile.
"""
from __future__ import annotations

import functools
import glob
import os
import shutil
import subprocess
from typing import Optional

ANDROID_HOME = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") \
    or os.path.expanduser("~/Library/Android/sdk")

_EXTRA_BIN = ["/usr/local/bin"]


@functools.lru_cache(maxsize=1)
def java_home() -> Optional[str]:
    if os.environ.get("JAVA_HOME"):
        return os.environ["JAVA_HOME"]
    try:
        out = subprocess.run(["/usr/libexec/java_home", "-v", "17"],
                             capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


def java_env() -> dict:
    """Environment dict with JAVA_HOME + PATH set for java-based tools."""
    env = dict(os.environ)
    jh = java_home()
    if jh:
        env["JAVA_HOME"] = jh
        env["PATH"] = f"{jh}/bin:" + env.get("PATH", "")
    env["ANDROID_HOME"] = ANDROID_HOME
    env["ANDROID_SDK_ROOT"] = ANDROID_HOME
    return env


def _find(name: str, *candidates: str) -> Optional[str]:
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    p = shutil.which(name)
    if p:
        return p
    for d in _EXTRA_BIN:
        cand = os.path.join(d, name)
        if os.path.isfile(cand):
            return cand
    return None


@functools.lru_cache(maxsize=1)
def aapt2() -> Optional[str]:
    hits = sorted(glob.glob(os.path.join(ANDROID_HOME, "build-tools", "*", "aapt2")),
                  reverse=True)
    return _find("aapt2", *(hits[:1]))


@functools.lru_cache(maxsize=1)
def adb() -> Optional[str]:
    return _find("adb", os.path.join(ANDROID_HOME, "platform-tools", "adb"))


@functools.lru_cache(maxsize=1)
def emulator() -> Optional[str]:
    return _find("emulator", os.path.join(ANDROID_HOME, "emulator", "emulator"))


@functools.lru_cache(maxsize=1)
def dexdump() -> Optional[str]:
    hits = sorted(glob.glob(os.path.join(ANDROID_HOME, "build-tools", "*", "dexdump")),
                  reverse=True)
    return _find("dexdump", *(hits[:1]))


@functools.lru_cache(maxsize=1)
def jadx() -> Optional[str]:
    return _find("jadx", "/usr/local/bin/jadx", "/usr/local/jadx/bin/jadx")


@functools.lru_cache(maxsize=1)
def apktool() -> Optional[str]:
    return _find("apktool", "/usr/local/bin/apktool")


def require(tool_name: str, path: Optional[str]) -> str:
    if not path:
        raise RuntimeError(
            f"required tool '{tool_name}' not found. Check ANDROID_HOME "
            f"({ANDROID_HOME}) and ~/.zprofile.")
    return path
