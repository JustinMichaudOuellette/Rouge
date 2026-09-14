#!/usr/bin/env python3
"""One-shot release helper for Rouge.

Generates a signing key (EC P-256 + minimal self-signed certificate) when
none exists, builds one optimized APK per requested minimum SDK, applies the
byte-tight optimization + v2 signing (tools/optimize_sign.py) to each,
verifies the signatures, installs the best-matching result on a connected
device via adb, and launches the app.

Usage:
  python tools/release.py [--min-sdks 37,34] [--ks <file>] [--ks-pass <pass>]
                          [--apk-out <file>] [--no-build] [--no-install]
                          [--package <id>] [--recert]

Default paths (all in the repository root):
  keystore  : <repo>/release.p12                    (auto-generated if absent)
  password  : from --ks-pass, else <keystore>.pass  (written when generated)
  cert SHA-256 : <keystore>.sha256                  (rewritten every run)
  apk out   : <repo>/rouge_final-min<SDK>.apk       (one per min SDK; the stem
                                                     follows --apk-out)

Minimum SDKs:
  --min-sdks takes a comma- or space-separated list of Android API levels
  (default 37,34) and builds the release variant once per value by passing
  -PminSdk=<n> to Gradle -- app/build.gradle.kts reads that property, so no
  file is edited between builds.  The floor is not cosmetic: R8/D8 compile
  against it, so a lower min SDK really does change the dex (34 here yields a
  1,676 B classes.dex against 37's 1,632 B; 2,033 B against 2,005 B signed).

  Levels below 24 are rejected rather than clamped: this pipeline ships APK
  Signature Scheme v2 only (tools/v2sign.py), which API 23 and below cannot
  verify, so an APK built there could not install on the devices it claims.

  With more than one level the output path gets the level inserted before its
  extension (rouge_final.apk -> rouge_final-min37.apk, rouge_final-min34.apk);
  a single level writes --apk-out verbatim.  Gradle always writes the same
  file (app/build/outputs/apk/release/app-release.apk), so each build is
  optimized and signed before the next one overwrites it, and the APK's own
  declared minSdkVersion is checked against the level that was asked for --
  the one failure this loop could otherwise hide is silently shipping the
  previous iteration's APK under the new name.

  Only one variant is installed (they share the package name), and it is the
  one matching the connected device: the highest built min SDK that is <= the
  device's ro.build.version.sdk, i.e. the most tightly optimized variant whose
  dex the device can still run.

Notes:
  * The keystore lives in the repository root, not under build/: `gradlew
    clean` (or Android Studio's Clean Project) deletes build/, and losing the
    signing key means never being able to update an installed or published
    copy again.  A keystore found at the old build/keys/release.p12 path is
    moved to the root rather than replaced by a freshly generated key.
  * <keystore>.sha256 holds the certificate's SHA-256 fingerprint exactly as
    the Play Console wants it (uppercase hex, colon-separated, no "SHA256:"
    prefix), so it can be pasted straight in.  It is rewritten on every run
    because --recert re-issues the certificate and the fingerprint *is* the
    signing identity.
  * The Gradle input is whatever `:app:assembleRelease` produced, found
    through AGP's app/build/outputs/apk/release/output-metadata.json -- the
    release build type carries a signingConfig (the debug key), so that file
    is app-release.apk, not app-release-unsigned.apk.
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
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, pkcs12)

import manifest_golf  # same-directory helper; see tools/manifest_golf.py
import mincert

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
OPTIMIZE_SIGN = os.path.join(TOOLS, "optimize_sign.py")
# In the repository root, not under build/: `gradlew clean` deletes build/,
# and the signing identity cannot be regenerated.
DEFAULT_KS = os.path.join(ROOT, "release.p12")
LEGACY_KS = os.path.join(ROOT, "build", "keys", "release.p12")
DEFAULT_OUT = os.path.join(ROOT, "rouge_final.apk")
RELEASE_DIR = os.path.join(ROOT, "app", "build", "outputs", "apk", "release")

# The minimum SDKs built when --min-sdks is not given.  Ordered newest first:
# the list order is also the order the APKs are built, and the first entry is
# the one a bare run would install on a device that satisfies all of them.
DEFAULT_MIN_SDKS = "37,34"

# APK Signature Scheme v2 -- the only scheme this pipeline emits -- arrived in
# API 24.  A lower --min-sdks would build an APK that cannot be verified on the
# very devices it is meant for, so it is refused instead of quietly clamped.
MIN_V2_SDK = 24


def sh(cmd, **kw):
    print("  $ " + " ".join(cmd) if isinstance(cmd, list) else "  $ " + cmd)
    # The child writes to the same fd, so flush our buffered lines first or
    # they show up after its output when stdout is a pipe (not a terminal).
    sys.stdout.flush()
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


def compile_sdk():
    """The module's compileSdk, or None if it cannot be read."""
    path = os.path.join(ROOT, "app", "build.gradle.kts")
    try:
        with open(path, encoding="utf-8") as fh:
            m = re.search(r"compileSdk\s*=\s*(\d+)", fh.read())
    except OSError:
        return None
    return int(m.group(1)) if m else None


def parse_min_sdks(values):
    """Flatten --min-sdks into an ordered, de-duplicated list of API levels.

    Both spellings work -- `--min-sdks 37,34` and `--min-sdks 37 34` -- because
    argparse collects the values and the split happens here; duplicates are
    dropped rather than built twice (the second build would overwrite the
    first's APK and cost a full Gradle round for nothing).
    """
    levels = []
    for value in values:
        for part in str(value).split(","):
            part = part.strip()
            if not part:
                continue
            if not part.isdigit():
                sys.exit(f"--min-sdks: not an Android API level: {part!r}")
            level = int(part)
            if level not in levels:
                levels.append(level)
    if not levels:
        sys.exit("--min-sdks: empty list")
    top = compile_sdk()
    for level in levels:
        if level < MIN_V2_SDK:
            sys.exit(
                f"--min-sdks: {level} is below API {MIN_V2_SDK}, the oldest "
                "release this pipeline can sign\n"
                "       (it emits APK Signature Scheme v2 only -- see "
                "tools/v2sign.py -- which API 23\n"
                "       and below cannot verify, so the APK would not install "
                "on the devices it targets)")
        if top is not None and level > top:
            sys.exit(f"--min-sdks: {level} is above compileSdk {top}; raise "
                     "compileSdk in app/build.gradle.kts first")
    return levels


def variant_apk_path(apk_out, min_sdk, multiple):
    """Where one min SDK's optimized APK goes.

    A single level keeps --apk-out verbatim (so `--min-sdks 37` still writes
    rouge_final.apk, the path every existing script and the README use); with
    several, the level is inserted before the extension so the files say which
    API floor they were compiled for.
    """
    if not multiple:
        return apk_out
    stem, ext = os.path.splitext(apk_out)
    return f"{stem}-min{min_sdk}{ext}"


def apk_min_sdk(apk_path):
    """The minSdkVersion the APK's own manifest declares, or None.

    Reads the compiled AndroidManifest.xml straight out of the archive with
    tools/manifest_golf.py's parser.  This is the *input* APK -- the golfed
    output drops that attribute on purpose (see the module docstring there) --
    so the value is present and is exactly what Gradle compiled against.
    """
    with zipfile.ZipFile(apk_path) as zf:
        data = zf.read("AndroidManifest.xml")
    strings, map_rids, nodes = manifest_golf.parse(data)
    for node in nodes:
        if node[0] != "elem":
            continue
        name = node[1]
        if name >= len(strings) or strings[name] != "uses-sdk":
            continue
        for _ns, nm, is_map, _raw, _typ, data_value in node[2]:
            if is_map and nm < len(map_rids) and map_rids[nm] == manifest_golf.MINSDK_RID:
                return data_value
    return None


def check_variant(apk, wanted, strict):
    """Fail if `apk` was not built for min SDK `wanted`.

    Every build writes the same path (app/build/outputs/apk/release/
    app-release.apk), so a Gradle that ignored -PminSdk -- an edit that
    dropped the property from app/build.gradle.kts, say -- would leave this
    loop reading the previous iteration's APK and signing it under the new
    name.  That is the one mistake the loop can make silently, so it is
    checked rather than assumed.

    An unreadable manifest only warns: the check is a heuristic on a file the
    rest of the pipeline never parses, and refusing to release because it
    could not be read would be worse than the risk it guards.  With --no-build
    a mismatch is the user's assertion about a prebuilt APK, so it warns too.
    """
    declared = apk_min_sdk(apk)
    if declared is None:
        print("  warning: no minSdkVersion found in "
              f"{os.path.basename(apk)}; assuming -PminSdk took effect")
        return
    if declared != wanted:
        message = (f"{apk} declares minSdkVersion {declared}, not {wanted}: "
                   "Gradle did not honor -PminSdk")
        if strict:
            sys.exit(message + "\n       (app/build.gradle.kts must read the "
                               "'minSdk' project property)")
        print(f"  warning: {message}; reusing it anyway (--no-build)")


def build_release(min_sdk):
    """`:app:assembleRelease` for one API floor."""
    gradlew = os.path.join(ROOT, "gradlew" + (".bat" if os.name == "nt" else ""))
    args = [":app:assembleRelease", "--console=plain", f"-PminSdk={min_sdk}"]
    if os.name == "nt":
        # A .bat needs cmd; going through shell keeps the quoting honest.
        subprocess.run(f'"{gradlew}" ' + " ".join(args), cwd=ROOT, shell=True,
                       check=True)
    else:
        sh([gradlew] + args, cwd=ROOT)


def device_api(adb):
    """The connected device's API level, or None if it cannot be read."""
    res = sh_out([adb, "shell", "getprop", "ro.build.version.sdk"])
    text = (res.stdout or "").strip()
    return int(text) if res.returncode == 0 and text.isdigit() else None


def pick_variant(variants, api):
    """The variant to install: the highest built min SDK <= the device's API.

    Not the newest variant outright -- that one may be compiled against an API
    the device does not have -- and not the oldest either, which would leave
    the tightest build the device could actually run on the table.
    """
    eligible = [v for v in variants if v[0] <= api]
    if eligible:
        return max(eligible, key=lambda v: v[0])
    lowest = min(variants, key=lambda v: v[0])
    print(f"  warning: device API {api} is below every built variant "
          f"(oldest is {lowest[0]}); installing that one anyway")
    return lowest


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
    # Android ships some tools as batch files on Windows -- apksigner.bat is
    # the one this script needs -- while adb and zipalign are .exe, so try
    # every extension the SDK uses rather than only .exe.
    suffixes = ("", ".exe", ".bat", ".cmd") if os.name == "nt" else ("",)
    for d in dirs:
        if not d:
            continue
        for suffix in suffixes:
            cand = os.path.join(d, name + suffix)
            if os.path.exists(cand):
                return cand
    return None


def release_apk():
    """The APK `:app:assembleRelease` wrote, whatever AGP decided to call it.

    AGP names the file after the release variant's signing config:
    `app-release.apk` while the release build type carries a `signingConfig`
    (this project points it at the debug key so a plain `assembleRelease`
    produces an installable APK, see app/build.gradle.kts) and
    `app-release-unsigned.apk` when it does not.  Hardcoding either name
    breaks the moment that config changes, so AGP's own
    output-metadata.json is authoritative here, with the two known names and
    finally any APK in the directory as fallbacks.
    """
    meta = os.path.join(RELEASE_DIR, "output-metadata.json")
    names = []
    if os.path.exists(meta):
        try:
            with open(meta, encoding="utf-8") as fh:
                names = [e.get("outputFile") for e in json.load(fh)["elements"]]
        except (ValueError, KeyError, TypeError, AttributeError):
            names = []  # unreadable/unknown shape: fall through to the names
    for name in names:
        cand = os.path.join(RELEASE_DIR, name) if name else None
        if cand and os.path.exists(cand):
            return cand

    found = [p for p in (os.path.join(RELEASE_DIR, n) for n in (
        "app-release.apk", "app-release-unsigned.apk")) if os.path.exists(p)]
    if not found and os.path.isdir(RELEASE_DIR):
        found = [os.path.join(RELEASE_DIR, n)
                 for n in os.listdir(RELEASE_DIR) if n.endswith(".apk")]
    if not found:
        sys.exit(f"release APK not found in {RELEASE_DIR}\n"
                 "       run without --no-build (or ./gradlew "
                 ":app:assembleRelease) first")
    return max(found, key=os.path.getmtime)


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


def adopt_legacy_keystore(ks):
    """Move a keystore still sitting at the old build/keys path into place.

    The default used to be <repo>/build/keys/release.p12, and build/ is
    deleted by `gradlew clean` (and by Android Studio's Clean Project) -- so
    the app's signing identity could be wiped by a routine build command.
    Generating a fresh key there would silently change that identity, which
    is the one thing in this repo that cannot be regenerated: treat a
    keystore found at the old path as the real key and move it (with its
    .pass) rather than making a new one.
    """
    if ks != DEFAULT_KS or os.path.exists(ks) or not os.path.exists(LEGACY_KS):
        return
    os.makedirs(os.path.dirname(ks) or ".", exist_ok=True)
    shutil.move(LEGACY_KS, ks)
    if os.path.exists(LEGACY_KS + ".pass"):
        shutil.move(LEGACY_KS + ".pass", ks + ".pass")
    print(f"[key] moved the existing keystore {LEGACY_KS} -> {ks}")
    print("      (build/ is deleted by `gradlew clean`; the signing identity "
          "is not regenerable)")


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


def keystore_certificate(ks, ks_pass):
    """The certificate that identifies this app to Android and to Play."""
    with open(ks, "rb") as fh:
        _key, cert, _extra = pkcs12.load_key_and_certificates(
            fh.read(), ks_pass.encode())
    if cert is None:
        sys.exit(f"keystore contains no certificate: {ks}")
    return cert


def write_fingerprint(ks, ks_pass):
    """Write <keystore>.sha256: the certificate's SHA-256 fingerprint.

    The file holds exactly what the Play Console's certificate fingerprint
    field accepts -- uppercase hex, colon-separated, no "SHA256:" prefix and
    nothing else on the line -- so it can be copied straight out of the file.

    It is rewritten on every run because the fingerprint *is* the signing
    identity: a re-issued certificate (--recert) or a replacement keystore
    changes it, and a stale fingerprint file is worse than none.  The file is
    public information (unlike the keystore and its password, which
    .gitignore keeps out of the repository).
    """
    fingerprint = keystore_certificate(ks, ks_pass).fingerprint(hashes.SHA256())
    text = ":".join(f"{byte:02X}" for byte in fingerprint)
    path = ks + ".sha256"
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text + "\n")
    print(f"[cert] SHA-256 fingerprint: {text}")
    print(f"[cert] written to {path} (paste into the Play Console)")
    return text


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ks", default=DEFAULT_KS)
    ap.add_argument("--ks-pass", default=None)
    ap.add_argument("--apk-out", default=DEFAULT_OUT,
                    help="where the optimized APK goes; with more than one "
                         "min SDK the level is inserted before the extension "
                         "(rouge_final.apk -> rouge_final-min37.apk). "
                         f"Default {DEFAULT_OUT}")
    ap.add_argument("--min-sdks", nargs="+", default=[DEFAULT_MIN_SDKS],
                    metavar="N[,N...]",
                    help="comma- or space-separated Android API levels to "
                         "build, one optimized APK each (default "
                         f"{DEFAULT_MIN_SDKS}); each is compiled by "
                         "`:app:assembleRelease -PminSdk=N`")
    ap.add_argument("--package", default=None, help="override applicationId")
    ap.add_argument("--no-build", action="store_true",
                    help="reuse the APK already in "
                         "app/build/outputs/apk/release instead of rebuilding "
                         "(one min SDK only: the directory holds one APK)")
    ap.add_argument("--no-install", action="store_true")
    ap.add_argument("--recert", action="store_true",
                    help="re-issue the keystore certificate as a minimal one "
                         "(smaller APK, but a NEW signing identity: an "
                         "existing install must be uninstalled first)")
    args = ap.parse_args()

    min_sdks = parse_min_sdks(args.min_sdks)
    if args.no_build and len(min_sdks) > 1:
        sys.exit("--no-build reuses the single APK Gradle already wrote, so it "
                 "cannot produce one variant per min SDK:\n"
                 "       drop --no-build, or pass a single --min-sdks value")

    pkg = args.package or application_id()
    adopt_legacy_keystore(args.ks)
    ks, ks_pass = ensure_keystore(args.ks, args.ks_pass)
    ks_pass = load_keystore_password(ks, ks_pass)
    if args.recert:
        recert(ks, ks_pass)
    # After any certificate change (a new keystore or --recert), and before the
    # --recert-only exit below: the fingerprint file has to match the
    # certificate that will sign the APK.
    write_fingerprint(ks, ks_pass)
    if args.recert and args.no_build and args.no_install:
        return

    multiple = len(min_sdks) > 1
    variants = []  # [(min sdk, optimized apk path)], in build order

    print(f"[1/3] {'optimizing' if args.no_build else 'building + optimizing'} "
          f"{len(min_sdks)} variant(s): min SDK "
          + ", ".join(str(s) for s in min_sdks), flush=True)
    for min_sdk in min_sdks:
        tag = f"[minSdk {min_sdk}]"
        if not args.no_build:
            print(f"  {tag} :app:assembleRelease -PminSdk={min_sdk}", flush=True)
            build_release(min_sdk)
        gradle_apk = release_apk()
        print(f"  {tag} gradle output: {os.path.relpath(gradle_apk, ROOT)}")
        check_variant(gradle_apk, min_sdk, strict=not args.no_build)

        out = variant_apk_path(args.apk_out, min_sdk, multiple)
        print(f"  {tag} optimizing + v2-signing -> {os.path.relpath(out, ROOT)}")
        # The Gradle APK may already be signed (the release build type uses the
        # debug key); optimize_sign.py rebuilds the archive from its entries,
        # so that throwaway signature never reaches the output.  Each variant
        # is finished here, before the next build overwrites the same Gradle
        # output file.
        sh([sys.executable, OPTIMIZE_SIGN, gradle_apk, out,
            "--sign", "--ks", ks, "--ks-pass", ks_pass])
        variants.append((min_sdk, out))

    print("[2/3] verifying signatures", flush=True)
    sdk = sdk_dir()
    apksigner = None
    if sdk:
        try:
            apksigner = tool("apksigner", newest_build_tools(sdk))
        except OSError:  # SDK without a build-tools/ directory
            apksigner = None
    if not apksigner:
        # Say so rather than passing silently: a skip that looks like a pass
        # is how a broken signature ships.
        print("  (apksigner not found; signature left unverified)")
    else:
        for min_sdk, out in variants:
            # The shipped APK declares no minSdkVersion (the manifest golf step
            # drops it -- see tools/manifest_golf.py), so apksigner falls back
            # to minSdk 1 and then demands a v1 JAR signature this APK
            # deliberately does not have ("Missing META-INF/MANIFEST.MF").
            # Pin the min SDK to the one this variant was compiled for, so it
            # verifies the v2 scheme that is present.  parse_min_sdks() has
            # already refused anything under 24, which is where v2 starts.
            print(f"  [minSdk {min_sdk}] apksigner verify", flush=True)
            subprocess.run([apksigner, "verify", "--min-sdk-version", str(min_sdk),
                            "--verbose", "--print-certs", out],
                           check=True)

    for min_sdk, out in variants:
        print(f"[ok] minSdk {min_sdk}: {out} "
              f"({os.path.getsize(out)} bytes)")

    if args.no_install:
        return
    print("[3/3] installing via adb", flush=True)
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
    # One package, one install: with several variants this picks the one the
    # device can actually run (and that is still built for its API level),
    # rather than whichever happened to be built last.
    if multiple:
        api = device_api(adb)
        if api is None:
            print("  warning: could not read ro.build.version.sdk; installing "
                  "the lowest min SDK variant")
            install_sdk, apk = min(variants, key=lambda v: v[0])
        else:
            install_sdk, apk = pick_variant(variants, api)
            print(f"  device API {api} -> minSdk {install_sdk} variant")
    else:
        install_sdk, apk = variants[0]
    res = sh_out([adb, "install", "-r", apk])
    if res.returncode != 0:
        print("  install -r failed (likely signature change); uninstalling "
              f"{pkg} and retrying")
        sh_out([adb, "uninstall", pkg])
        res = subprocess.run([adb, "install", apk])
        if res.returncode != 0:
            sys.exit("install failed")
    print(f"[ok] installed {pkg} (minSdk {install_sdk}) on {online[0]}")

    print("  launching app")
    launched = False
    # resolve the launcher activity so we don't hardcode the component
    resolve = sh_out([adb, "shell", "cmd", "package", "resolve-activity",
                      "--brief", "-c", "android.intent.category.LAUNCHER", pkg])
    comp = ""
    for line in resolve.stdout.splitlines():
        line = line.strip()
        if line and " " not in line and "/" in line:
            comp = line  # e.g. ca.justinmo.r/a.a
    if comp:
        launched = sh_out([adb, "shell", "am", "start", "-n", comp]).returncode == 0
    if not launched:
        # Fallback for a shell where resolve-activity said nothing: the
        # manifest declares <activity android:name="a.a">, a root-package
        # class, so the component is pkg/a.a (not pkg/.A -- the leading dot
        # would mean "A in the app's package", which does not exist).
        launched = sh_out(
            [adb, "shell", "am", "start", "-n", f"{pkg}/a.a"]).returncode == 0
    if launched:
        print(f"[ok] launched {pkg}")
    else:
        print("  warning: installed, but could not auto-launch the app")


if __name__ == "__main__":
    main()
