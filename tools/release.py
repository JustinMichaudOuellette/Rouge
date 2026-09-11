#!/usr/bin/env python3
"""One-shot release helper for Rouge.

Generates a signing key (EC P-256 + minimal self-signed certificate) when
none exists, builds the release APK, applies the byte-tight optimization +
v2 signing (tools/optimize_sign.py), verifies the signature, installs the
result on a connected device via adb, and launches the app.

Usage:
  python tools/release.py [--ks <file>] [--ks-pass <pass>] [--apk-out <file>]
                          [--no-build] [--no-install] [--package <id>]
                          [--recert]

Defaults:
  keystore : <repo>/build/keys/release.p12        (auto-generated if absent)
  password : from --ks-pass, else <keystore>.pass (written when generated)
  apk out  : <repo>/rouge_final.apk                (override with --apk-out)

Notes:
  * The certificate is built by hand (tools/mincert.py): a version 1, no
    extensions, one-character-CommonName, UTCTime certificate.  It is 257 B
    where Android Studio/keytool would produce 700-900 B and
    cryptography.CertificateBuilder ~270 B, and it is half of the v2 signing
    block, so those bytes land directly in the APK.
  * Signing identity = the certificate, not the key: Android treats a
    re-issued certificate as a different signer, so change it only for fresh
    installs (uninstall required), never for published updates.  --recert
    re-issues an existing keystore's certificate as the minimal one.
  * If a brand-new keystore is generated, the signing identity is new, so
    previously installed builds must be uninstalled first.
  * Requires: JDK (gradle), python 'cryptography' package, Android SDK
    (zipalign/apksigner/adb) reachable via local.properties.
"""
import argparse
import hashlib
import os
import re
import secrets
import shutil
import string
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, pkcs12)

import mincert

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
OPTIMIZE_SIGN = os.path.join(TOOLS, "optimize_sign.py")
DEFAULT_KS = os.path.join(ROOT, "build", "keys", "release.p12")
DEFAULT_OUT = os.path.join(ROOT, "rouge_final.apk")


def sh(cmd, **kw):
    print("  $ " + " ".join(cmd) if isinstance(cmd, list) else "  $ " + cmd)
    return subprocess.run(cmd, check=True, **kw)


def sh_out(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def application_id():
    path = os.path.join(ROOT, "app", "build.gradle.kts")
    with open(path, encoding="utf-8") as fh:
        m = re.search(r'applicationId\s*=\s*"([^"]+)"', fh.read())
    if not m:
        sys.exit("could not read applicationId from app/build.gradle.kts")
    return m.group(1)


def sdk_dir():
    props = os.path.join(ROOT, "local.properties")
    if os.path.exists(props):
        with open(props, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"\s*sdk\.dir=(.+)$", line)
                if m:
                    p = m.group(1).strip().replace("\\:", ":")
                    p = p.replace("\\\\", os.sep).replace("\\", os.sep)
                    if os.path.isdir(p):
                        return p
    return os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")


def newest_build_tools(sdk):
    bt = os.path.join(sdk, "build-tools")

    def key(d):
        return [int(x) for x in re.findall(r"\d+", d)] + [0 if "rc" not in d else 1]

    return os.path.join(bt, sorted(os.listdir(bt), key=key)[-1])


def tool(name, *dirs):
    found = shutil.which(name)
    if found:
        return found
    for d in dirs:
        if not d:
            continue
        cand = os.path.join(d, name + (".exe" if os.name == "nt" else ""))
        if os.path.exists(cand):
            return cand
    return None


def _minimal_cert(key):
    """The smallest self-signed certificate the signer can carry.

    Built by hand (tools/mincert.py) rather than with CertificateBuilder: a
    version 1 certificate with no extensions, a one-character CommonName, no
    optional fields and UTCTime validity is 257 B instead of ~270-900 B, which
    is 9-30 B off the signed APK (the certificate is roughly half of the v2
    signing block).
    """
    der = mincert.build_best(key, cn=b"R")
    return x509.load_der_x509_certificate(der)


def recert(ks, ks_pass):
    """Re-issue the keystore's certificate as a minimal one."""
    _key, old_der = mincert.load(ks, ks_pass)
    _old, new_der = mincert.recert_keystore(ks, ks_pass, cn=b"R")
    if new_der == old_der:
        print(f"[cert] already minimal ({len(new_der)} B)")
        return
    print(f"[cert] re-issued: {len(old_der)} B -> {len(new_der)} B "
          f"({len(old_der) - len(new_der)} B off every future build)")
    print("       SHA-256 was "
          f"{hashlib.sha256(old_der).hexdigest()[:16]}... now "
          f"{hashlib.sha256(new_der).hexdigest()[:16]}...")
    print("       NOTE: a re-issued certificate is a NEW signing identity --")
    print("       an existing install must be uninstalled before it can be "
          "replaced.")


def ensure_keystore(ks, ks_pass):
    if os.path.exists(ks):
        return ks, ks_pass
    os.makedirs(os.path.dirname(ks) or ".", exist_ok=True)
    if not ks_pass:
        alphabet = string.ascii_letters + string.digits
        ks_pass = "".join(secrets.choice(alphabet) for _ in range(24))
        with open(ks + ".pass", "w", encoding="utf-8") as fh:
            fh.write(ks_pass)
        print(f"[key] generated random password -> {ks + '.pass'}")
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _minimal_cert(key)
    p12_bytes = pkcs12.serialize_key_and_certificates(
        b"release", key, cert, None, BestAvailableEncryption(ks_pass.encode()))
    with open(ks, "wb") as fh:
        fh.write(p12_bytes)
    print(f"[key] generated new EC P-256 keystore with minimal cert: {ks}")
    print("      NOTE: this is a NEW signing identity; updating an existing")
    print("      install with a different key requires an uninstall.")
    return ks, ks_pass


def load_keystore_password(ks, ks_pass):
    if ks_pass:
        return ks_pass
    pass_file = ks + ".pass"
    if os.path.exists(pass_file):
        with open(pass_file, encoding="utf-8") as fh:
            return fh.read().strip()
    sys.exit(f"no password: pass --ks-pass or create {pass_file}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ks", default=DEFAULT_KS)
    ap.add_argument("--ks-pass", default=None)
    ap.add_argument("--apk-out", default=DEFAULT_OUT)
    ap.add_argument("--package", default=None, help="override applicationId")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--no-install", action="store_true")
    ap.add_argument("--recert", action="store_true",
                    help="re-issue the keystore certificate as a minimal one "
                         "(smaller APK, but a NEW signing identity: an "
                         "existing install must be uninstalled first)")
    args = ap.parse_args()

    pkg = args.package or application_id()
    ks, ks_pass = ensure_keystore(args.ks, args.ks_pass)
    ks_pass = load_keystore_password(ks, ks_pass)
    if args.recert:
        recert(ks, ks_pass)
        if args.no_build and args.no_install:
            return

    if not args.no_build:
        print("[1/4] building release APK")
        gradlew = os.path.join(ROOT, "gradlew" + (".bat" if os.name == "nt" else ""))
        cmd = f'"{gradlew}" :app:assembleRelease --console=plain'
        if os.name == "nt":
            subprocess.run(cmd, cwd=ROOT, shell=True, check=True)
        else:
            sh([gradlew, ":app:assembleRelease", "--console=plain"], cwd=ROOT)

    unsigned = os.path.join(
        ROOT, "app", "build", "outputs", "apk", "release", "app-release-unsigned.apk")
    if not os.path.exists(unsigned):
        sys.exit(f"release APK not found at {unsigned} (build first)")

    print("[2/4] optimizing + v2-signing")
    sh([sys.executable, OPTIMIZE_SIGN, unsigned, args.apk_out,
        "--sign", "--ks", ks, "--ks-pass", ks_pass])

    print("[3/4] verifying signature")
    sdk = sdk_dir()
    if sdk:
        bt = newest_build_tools(sdk)
        apksigner = tool("apksigner", bt)
        if apksigner:
            # The shipped APK declares no minSdkVersion (the manifest golf step
            # drops it -- see tools/manifest_golf.py), so apksigner falls back
            # to minSdk 1 and then demands a v1 JAR signature this APK
            # deliberately does not have ("Missing META-INF/MANIFEST.MF").
            # Pin the min SDK so it verifies the v2 scheme that is present.
            subprocess.run([apksigner, "verify", "--min-sdk-version", "37",
                            "--print-certs", args.apk_out], check=True)
    else:
        print("  (SDK not found; skipped apksigner verify)")

    size = os.path.getsize(args.apk_out)
    print(f"[ok] signed APK: {args.apk_out} ({size} bytes)")

    if args.no_install:
        return
    print("[4/4] installing via adb")
    sdk = sdk_dir()
    adb = tool("adb", sdk and os.path.join(sdk, "platform-tools"))
    if not adb:
        sys.exit("adb not found")
    devices = sh_out([adb, "devices"]).stdout
    online = [ln.split()[0] for ln in devices.splitlines()[1:]
              if ln.strip() and ln.split()[-1] == "device"]
    if not online:
        sys.exit("no device connected (adb devices is empty)")
    print(f"  device: {online[0]}")
    res = sh_out([adb, "install", "-r", args.apk_out])
    if res.returncode != 0:
        print("  install -r failed (likely signature change); uninstalling "
              f"{pkg} and retrying")
        sh_out([adb, "uninstall", pkg])
        res = subprocess.run([adb, "install", args.apk_out])
        if res.returncode != 0:
            sys.exit("install failed")
    print(f"[ok] installed {pkg} on {online[0]}")

    print("  launching app")
    launched = False
    # resolve the launcher activity so we don't hardcode the component
    resolve = sh_out([adb, "shell", "cmd", "package", "resolve-activity",
                      "--brief", "-c", "android.intent.category.LAUNCHER", pkg])
    comp = ""
    for line in resolve.stdout.splitlines():
        line = line.strip()
        if line and " " not in line and "/" in line:
            comp = line  # e.g. ca.justinmo.r/.A
    if comp:
        launched = sh_out([adb, "shell", "am", "start", "-n", comp]).returncode == 0
    if not launched:
        launched = sh_out(
            [adb, "shell", "am", "start", "-n", f"{pkg}/.A"]).returncode == 0
    if launched:
        print(f"[ok] launched {pkg}")
    else:
        print("  warning: installed, but could not auto-launch the app")


if __name__ == "__main__":
    main()
