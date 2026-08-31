#!/usr/bin/env python3
"""Post-build APK optimizer for Rouge.

Rebuilds the APK produced by Gradle to shave off remaining dead weight
without changing the application package name, the launcher icon, or any
runtime behaviour:

  * drops META-INF/com/android/build/gradle/app-metadata.properties
  * deflates classes.dex / AndroidManifest.xml at maximum compression
    (Gradle stores classes.dex uncompressed)
  * re-encodes AndroidManifest.xml smaller (tools/manifest_golf.py): drops
    aapt2-injected informational attributes (versionName, compileSdkVersion,
    platformBuildVersion*, extractNativeLibs) and rebuilds the string pool as
    UTF-8 -- same element tree and runtime attributes; disable with
    --no-manifest-golf
  * keeps resources.arsc STORED when it carries resources, but drops it when
    it is only an empty stub (< 100 B, zero entries): if the manifest's icon
    and theme reference framework resources (@android:...), Android resolves
    them from the system table and the app installs fine without its own
    resources.arsc (verified on-device)
  * writes deterministic timestamps (no build-time entropy)
  * zipaligns (4-byte) and, with --sign, applies a byte-tight APK v2-only
    signature in pure Python (tools/v2sign.py, modeled on AOSP apksig) --
    ApkGolf-style: EC/RSA key, no v1 JAR signing, no reserved 4096-byte
    signing-block padding that apksigner adds.

Usage:
  python optimize_sign.py <input.apk> <output.apk> [options]

Options:
  --sign                 sign the output (v2 scheme; see tools/v2sign.py)
  --ks <file>            PKCS12 keystore path (contains key + certificate)
  --ks-pass <pass>       keystore password
  --no-zipalign          skip zipalign (debugging)
  --no-manifest-golf     keep the compiled AndroidManifest.xml as aapt2 made it
                         (default: re-encode it smaller; see tools/manifest_golf.py)

Output goes through <output.apk> only after every step succeeds.
Requires the python `cryptography` package for --sign.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

import manifest_golf  # same-directory helper; see tools/manifest_golf.py

APP_METADATA = "META-INF/com/android/build/gradle/app-metadata.properties"
ARSC = "resources.arsc"
STORED = {ARSC}
MANIFEST = "AndroidManifest.xml"


def sdk_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    props = os.path.join(os.path.dirname(here), "local.properties")
    if os.path.exists(props):
        with open(props, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"\s*sdk\.dir=(.+)$", line)
                if m:
                    p = m.group(1).strip().replace("\\:", ":")
                    p = p.replace("\\\\", os.sep).replace("\\", os.sep)
                    if os.path.isdir(p):
                        return p
    env = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    return env


def newest_build_tools(sdk):
    bt = os.path.join(sdk, "build-tools")

    def key(d):
        return [int(x) for x in re.findall(r"\d+", d)] + [0 if "rc" not in d else 1]

    return os.path.join(bt, sorted(os.listdir(bt), key=key)[-1])


def optimize(in_apk, out_apk, golf_manifest=True):
    with zipfile.ZipFile(in_apk) as zin, \
            zipfile.ZipFile(out_apk, "w", compresslevel=9) as zout:
        for info in zin.infolist():
            if info.filename == APP_METADATA:
                print(f"  drop {info.filename} ({info.file_size} B)")
                continue
            if info.filename == ARSC and info.file_size < 100:
                print(f"  drop {info.filename} ({info.file_size} B, empty "
                      "stub: icon/theme are framework resources)")
                continue
            data = zin.read(info.filename)
            if info.filename == MANIFEST and golf_manifest:
                golfed = manifest_golf.golf_manifest(data)
                if golfed != data:
                    print(f"  {info.filename}: {info.file_size} B raw -> "
                          f"{len(golfed)} B (golfed, see tools/manifest_golf.py)")
                    data = golfed
                else:
                    print(f"  {info.filename}: {info.file_size} B raw "
                          "(manifest golf skipped: rewrite failed or no win)")
            new = zipfile.ZipInfo(info.filename, date_time=(1980, 1, 1, 0, 0, 0))
            if info.filename in STORED or info.filename.endswith("/"):
                new.compress_type = zipfile.ZIP_STORED
            else:
                new.compress_type = zipfile.ZIP_DEFLATED
            new.external_attr = info.external_attr
            zout.writestr(new, data)
            verb = "stored" if new.compress_type == zipfile.ZIP_STORED else "deflated"
            print(f"  {info.filename}: {len(data)} B raw -> {verb}")


def run(cmd):
    print("  $ " + " ".join(cmd))
    subprocess.run(cmd, check=True)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--sign", action="store_true")
    ap.add_argument("--ks", help="PKCS12 keystore path")
    ap.add_argument("--ks-pass", help="keystore password")
    ap.add_argument("--no-zipalign", action="store_true")
    ap.add_argument("--no-manifest-golf", action="store_true",
                    help="keep the compiled AndroidManifest.xml as aapt2 made it")
    ap.add_argument("--build-tools", help="override build-tools dir")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        sys.exit(f"input not found: {args.input}")

    sdk = sdk_dir()
    bt = args.build_tools or (newest_build_tools(sdk) if sdk else None)
    if bt is None or not os.path.isdir(bt):
        sys.exit("cannot locate build-tools; pass --build-tools")
    zipalign = os.path.join(bt, "zipalign" + (".exe" if os.name == "nt" else ""))

    tmp = tempfile.mkdtemp(prefix="rouge-opt-")
    try:
        step1 = os.path.join(tmp, "optimized.apk")
        print(f"[1/3] repack {args.input} -> {step1}")
        optimize(args.input, step1, golf_manifest=not args.no_manifest_golf)

        step2 = step1
        if not args.no_zipalign:
            step2 = os.path.join(tmp, "aligned.apk")
            print("[2/3] zipalign -f 4")
            run([zipalign, "-f", "4", step1, step2])

        final = step2
        if args.sign:
            print("[3/3] v2-sign (manual, tight block)")
            if not args.ks or not args.ks_pass:
                sys.exit("--sign requires --ks and --ks-pass (PKCS12 keystore)")
            from cryptography.hazmat.primitives.serialization import pkcs12
            import v2sign
            with open(args.ks, "rb") as fh:
                key, cert, _extra = pkcs12.load_key_and_certificates(
                    fh.read(), args.ks_pass.encode())
            if key is None or cert is None:
                sys.exit("keystore contains no private key + certificate")
            cert_der = cert.public_bytes(
                __import__("cryptography").hazmat.primitives.serialization.Encoding.DER)
            # sign_apk_file writes only to args.output on success
            v2sign.sign_apk_file(final, args.output, key, cert_der)
            print(f"  signed -> {args.output}")
        else:
            shutil.copyfile(final, args.output)

        print(f"OK -> {args.output} ({os.path.getsize(args.output)} bytes)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
