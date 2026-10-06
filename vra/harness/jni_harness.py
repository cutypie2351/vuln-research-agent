"""Phase 3 — isolated JNI harness synthesis (§4, §10 A.4/A.6).

Generates a C harness that dlopen()s a native `.so`, builds a *fake JNIEnv*,
wraps fuzzer input as a jbyteArray / jstring, and calls one JNI native with a
controllable argument. Designed for the x86_64 ABI so it runs natively in the
Linux fuzzing container (fast); coverage on the uninstrumented `.so` comes from
AFL++ QEMU mode.

The key modeling trick (§10 A.6): a real JNIEnv is `JNINativeInterface**` — a
pointer to a table of ~230 function pointers called by *offset*. Rather than
pull in jni.h, we model the table as a flat `void* table[300]` and fill only
the entries the native actually calls (discovered from the disassembly /
jnitrace). env = &table. Native does `(*env)[off/8](...)`.

This generator covers the common crackme/parser shape: a single controllable
`byte[]` or `String` argument. Multi-arg and richer JNIEnv modeling are added
as targets require them.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# JNINativeInterface indices we model (index = struct offset / 8 on LP64).
JNI_IDX = {
    "GetStringUTFLength": 168,
    "GetStringUTFChars": 169,
    "ReleaseStringUTFChars": 170,
    "GetArrayLength": 171,
    "GetByteArrayElements": 184,
    "GetByteArrayRegion": 200,
    "ReleaseByteArrayElements": 192,
    "NewByteArray": 176,
    "NewStringUTF": 167,
    "FindClass": 6,
    "ExceptionCheck": 228,
    "ExceptionClear": 17,
}


@dataclass
class SetupCall:
    """A native call to run once before fuzzing (e.g. an init that unlocks state)."""
    symbol: str
    # arg kinds per parameter (after env, this): "bytearray_const" | "null" | "int"
    args: list = field(default_factory=list)
    const_bytes: bytes = b""     # for a bytearray_const argument


_HARNESS_C = r'''/* AUTO-GENERATED JNI fuzzing harness for %(method)s
 * target: %(so)s  symbol: %(symbol)s  controllable arg: %(carg)d (%(ctype)s)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#define TABLE_SZ 300
static void* jni_table[TABLE_SZ];

/* fake JNI object: a byte[] or a UTF string, modelled as {len,data}. */
typedef struct { int32_t len; unsigned char* data; } FakeArr;

#ifdef HARNESS_DEBUG
static int dbg_len=0, dbg_gbe=0;
#define DBG(x) (x)++
#else
#define DBG(x)
#endif

static int32_t j_GetArrayLength(void* env, void* a){ DBG(dbg_len); return a?((FakeArr*)a)->len:0; }
static void*   j_GetByteArrayElements(void* env, void* a, unsigned char* isCopy){
    DBG(dbg_gbe); if(isCopy)*isCopy=0; return a?((FakeArr*)a)->data:NULL; }
static void    j_ReleaseByteArrayElements(void* env, void* a, void* e, int m){}
static void    j_GetByteArrayRegion(void* env, void* a, int32_t start, int32_t len, void* buf){
    FakeArr* f=(FakeArr*)a; if(!f||!buf) return;
    if(start<0||len<0||start+len>f->len) return; memcpy(buf,f->data+start,len); }
static const char* j_GetStringUTFChars(void* env, void* s, unsigned char* isCopy){
    if(isCopy)*isCopy=0; return s?(const char*)((FakeArr*)s)->data:NULL; }
static int32_t j_GetStringUTFLength(void* env, void* s){ return s?((FakeArr*)s)->len:0; }
static void    j_ReleaseStringUTFChars(void* env, void* s, const char* c){}
static void*   j_generic(void){ return NULL; }

static void build_env(void){
    for(int i=0;i<TABLE_SZ;i++) jni_table[i]=(void*)j_generic;
    jni_table[%(i_len)d]=(void*)j_GetArrayLength;
    jni_table[%(i_gbe)d]=(void*)j_GetByteArrayElements;
    jni_table[%(i_rbe)d]=(void*)j_ReleaseByteArrayElements;
    jni_table[%(i_gbr)d]=(void*)j_GetByteArrayRegion;
    jni_table[%(i_guc)d]=(void*)j_GetStringUTFChars;
    jni_table[%(i_gul)d]=(void*)j_GetStringUTFLength;
    jni_table[%(i_ruc)d]=(void*)j_ReleaseStringUTFChars;
}

typedef long (*jnifn)(void* env, void* thiz, void* arg);

static unsigned char g_buf[1<<20];

int main(int argc, char** argv){
    build_env();
    void* table = (void*)jni_table;
    void* env = &table;                 /* JNIEnv* = &(ptr-to-table) */

    void* h = dlopen("%(so)s", RTLD_NOW | RTLD_GLOBAL);
    if(!h){ fprintf(stderr,"dlopen: %%s\n", dlerror()); return 1; }

%(setup)s
    jnifn fn = (jnifn)dlsym(h, "%(symbol)s");
    if(!fn){ fprintf(stderr,"dlsym %(symbol)s failed\n"); return 1; }

    /* read fuzzer input (AFL passes a file path as argv[1]; else stdin) */
    size_t n=0;
    if(argc>1){ FILE* f=fopen(argv[1],"rb"); if(f){ n=fread(g_buf,1,sizeof g_buf,f); fclose(f);} }
    else { n=fread(g_buf,1,sizeof g_buf,stdin); }

    FakeArr arg = { (int32_t)n, g_buf };
    long rv = fn(env, NULL, &arg);
#ifdef HARNESS_DEBUG
    fprintf(stderr, "[harness] ret=%%ld GetArrayLength=%%d GetByteArrayElements=%%d\n",
            rv, dbg_len, dbg_gbe);
#else
    (void)rv;
#endif
    return 0;
}
'''

_SETUP_BYTEARRAY = r'''    {
        static unsigned char _k%(n)d[] = {%(bytes)s};
        FakeArr _a%(n)d = { %(len)d, _k%(n)d };
        void (*_s%(n)d)(void*,void*,void*) = (void(*)(void*,void*,void*))dlsym(h,"%(sym)s");
        if(_s%(n)d) _s%(n)d(env, NULL, &_a%(n)d);
    }
'''


def generate(method: dict, so_path: str, controlled_arg: int = 0,
             setup_calls: list | None = None) -> str:
    """Emit C source for a harness around `method` in `so_path`."""
    arg_types = method.get("arg_types", [])
    ctype = arg_types[controlled_arg] if controlled_arg < len(arg_types) else "byte[]"

    setup_src = ""
    for i, sc in enumerate(setup_calls or []):
        if "bytearray_const" in sc.args:
            b = sc.const_bytes
            setup_src += _SETUP_BYTEARRAY % {
                "n": i, "sym": sc.symbol, "len": len(b),
                "bytes": ",".join(str(x) for x in b),
            }

    return _HARNESS_C % {
        "method": f"{method['java_class']}.{method['java_method']}",
        "so": so_path, "symbol": method["native_symbol"],
        "carg": controlled_arg, "ctype": ctype,
        "i_len": JNI_IDX["GetArrayLength"], "i_gbe": JNI_IDX["GetByteArrayElements"],
        "i_rbe": JNI_IDX["ReleaseByteArrayElements"], "i_gbr": JNI_IDX["GetByteArrayRegion"],
        "i_guc": JNI_IDX["GetStringUTFChars"], "i_gul": JNI_IDX["GetStringUTFLength"],
        "i_ruc": JNI_IDX["ReleaseStringUTFChars"],
        "setup": setup_src,
    }
