#!/bin/bash
set -e
ROOT=/Users/admin/vuln-research-agent
export JAVA_HOME=$(/usr/libexec/java_home -v 17); export PATH="$JAVA_HOME/bin:$PATH"
BT=/Users/admin/Library/Android/sdk/build-tools/34.0.0
AJAR=/Users/admin/Library/Android/sdk/platforms/android-34/android.jar
OUT=$ROOT/scratch/ctf; mkdir -p "$OUT"
build() {  # $1=pkgid (no underscore)  $2=csrc basename
  id=$1; csrc=$2; pkg="com.ctf.$id"; sym="Java_com_ctf_${id}_Chal_run"
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
    byte[] d = getIntent().getByteArrayExtra("d");
    if (d != null) new Chal().run(d); } }
EOF
  cat > "$B/src/com/ctf/$id/Chal.java" <<EOF
package $pkg;
public class Chal { static { System.loadLibrary("$id"); } public native int run(byte[] d); }
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
rm -f "$OUT"/*.apk "$OUT"/*.idsig
build c1stack      c1_stack
build c2heap       c2_heap
build c3offbyone   c3_offbyone
build c4magic      c4_magic
build c5constraint c5_constraint
build c6initgate   c6_initgate
