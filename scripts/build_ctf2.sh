#!/bin/bash
# Build the generic-input-model CTF suite (c7 String, c8 int+byte[], c9 ByteBuffer).
# Each is a real signed APK whose exported Activity passes an attacker-controlled
# value of the right TYPE into a native method, to exercise the new input model.
set -e
ROOT=/Users/admin/vuln-research-agent
export JAVA_HOME=$(/usr/libexec/java_home -v 17); export PATH="$JAVA_HOME/bin:$PATH"
BT=/Users/admin/Library/Android/sdk/build-tools/34.0.0
AJAR=/Users/admin/Library/Android/sdk/platforms/android-34/android.jar
OUT=$ROOT/scratch/ctf; mkdir -p "$OUT"

# $1=pkgid(no underscore) $2=csrc $3=native-decl $4=main-body
build() {
  id=$1; csrc=$2; decl=$3; body=$4; pkg="com.ctf.$id"; sym="Java_com_ctf_${id}_Chal_run"
  B=$ROOT/scratch/ctfbuild/$id; rm -rf "$B"; mkdir -p "$B/src/com/ctf/$id" "$B/out/lib/x86_64"
  chown -R 501:20 "$B"
  docker run --rm -v "$ROOT":/work vra-fuzz bash -lc \
    "clang -DJNIFUNC=$sym -I/work/scratch/ctf_src -shared -fPIC -O0 -fno-stack-protector \
     -o /work/scratch/ctfbuild/$id/out/lib/x86_64/lib$id.so /work/scratch/ctf_src/$csrc.c"
  cat > "$B/src/com/ctf/$id/MainActivity.java" <<EOF
package $pkg;
import android.app.Activity; import android.os.Bundle;
public class MainActivity extends Activity {
  @Override protected void onCreate(Bundle b){ super.onCreate(b);
$body
  } }
EOF
  cat > "$B/src/com/ctf/$id/Chal.java" <<EOF
package $pkg;
public class Chal { static { System.loadLibrary("$id"); } public native $decl }
EOF
  cat > "$B/AndroidManifest.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="$pkg">
  <application android:label="$id">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/>
      <category android:name="android.intent.category.LAUNCHER"/></intent-filter>
    </activity></application></manifest>
EOF
  javac -cp "$AJAR" -d "$B/classes" "$B"/src/com/ctf/$id/*.java
  "$BT/d8" --min-api 21 --lib "$AJAR" --output "$B/out" "$B"/classes/com/ctf/$id/*.class
  "$BT/aapt2" link --manifest "$B/AndroidManifest.xml" -I "$AJAR" --min-sdk-version 21 --target-sdk-version 28 -o "$B/base.apk"
  ( cd "$B/out" && zip -q -X ../base.apk classes.dex lib/x86_64/lib$id.so )
  "$BT/zipalign" -p -f 4 "$B/base.apk" "$B/aligned.apk"
  [ -f "$ROOT/scratch/ctfbuild/debug.ks" ] || keytool -genkeypair -keystore "$ROOT/scratch/ctfbuild/debug.ks" \
    -storepass android -keypass android -alias d -dname CN=ctf -keyalg RSA -keysize 2048 -validity 10000 2>/dev/null
  "$BT/apksigner" sign --ks "$ROOT/scratch/ctfbuild/debug.ks" --ks-pass pass:android --out "$OUT/$id.apk" "$B/aligned.apk" 2>/dev/null
  echo "built $OUT/$id.apk ($sym)"
}

build c7string c7string \
  'int run(String s);' \
  '    String s = getIntent().getStringExtra("s");
    if (s != null) new Chal().run(s);'

build c8multi c8multi \
  'int run(int n, byte[] d);' \
  '    int n = getIntent().getIntExtra("n", 0);
    byte[] d = getIntent().getByteArrayExtra("d");
    if (d != null) new Chal().run(n, d);'

build c9buffer c9buffer \
  'int run(java.nio.ByteBuffer b);' \
  '    byte[] d = getIntent().getByteArrayExtra("d");
    if (d != null) { java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocateDirect(d.length);
      bb.put(d); new Chal().run(bb); }'
