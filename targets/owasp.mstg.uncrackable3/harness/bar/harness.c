/* AUTO-GENERATED JNI fuzzing harness for sg.vantagepoint.uncrackable3.CodeCheck.bar
 * target: /work/targets/owasp.mstg.uncrackable3/libs/x86_64/libfoo.so  symbol: Java_sg_vantagepoint_uncrackable3_CodeCheck_bar  controllable arg: 0 (byte[])
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
    jni_table[171]=(void*)j_GetArrayLength;
    jni_table[184]=(void*)j_GetByteArrayElements;
    jni_table[192]=(void*)j_ReleaseByteArrayElements;
    jni_table[200]=(void*)j_GetByteArrayRegion;
    jni_table[169]=(void*)j_GetStringUTFChars;
    jni_table[168]=(void*)j_GetStringUTFLength;
    jni_table[170]=(void*)j_ReleaseStringUTFChars;
}

typedef long (*jnifn)(void* env, void* thiz, void* arg);

static unsigned char g_buf[1<<20];

int main(int argc, char** argv){
    build_env();
    void* table = (void*)jni_table;
    void* env = &table;                 /* JNIEnv* = &(ptr-to-table) */

    void* h = dlopen("/work/targets/owasp.mstg.uncrackable3/libs/x86_64/libfoo.so", RTLD_NOW | RTLD_GLOBAL);
    if(!h){ fprintf(stderr,"dlopen: %s\n", dlerror()); return 1; }

    {
        static unsigned char _k0[] = {112,105,122,122,97,112,105,122,122,97,112,105,122,122,97,112,105,122,122,97,112,105,122,122};
        FakeArr _a0 = { 24, _k0 };
        void (*_s0)(void*,void*,void*) = (void(*)(void*,void*,void*))dlsym(h,"Java_sg_vantagepoint_uncrackable3_MainActivity_init");
        if(_s0) _s0(env, NULL, &_a0);
    }

    jnifn fn = (jnifn)dlsym(h, "Java_sg_vantagepoint_uncrackable3_CodeCheck_bar");
    if(!fn){ fprintf(stderr,"dlsym Java_sg_vantagepoint_uncrackable3_CodeCheck_bar failed\n"); return 1; }

    /* read fuzzer input (AFL passes a file path as argv[1]; else stdin) */
    size_t n=0;
    if(argc>1){ FILE* f=fopen(argv[1],"rb"); if(f){ n=fread(g_buf,1,sizeof g_buf,f); fclose(f);} }
    else { n=fread(g_buf,1,sizeof g_buf,stdin); }

    FakeArr arg = { (int32_t)n, g_buf };
    long rv = fn(env, NULL, &arg);
#ifdef HARNESS_DEBUG
    fprintf(stderr, "[harness] ret=%ld GetArrayLength=%d GetByteArrayElements=%d\n",
            rv, dbg_len, dbg_gbe);
#else
    (void)rv;
#endif
    return 0;
}
