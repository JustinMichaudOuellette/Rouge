# Rouge

**A full-screen red Android app that turns horizontal touch/drag into a
brightness control — shipped as a ~2.1 KB signed APK.**

`ca.justinmo.r` · minSdk 37 · targetSdk 37 · zero dependencies

Rouge is both a tiny utility and an exercise in aggressive APK size golf:
the release APK you install is a hand-tuned ~2.1 KB, built with standard
Android tooling plus a byte-tight, pure-Python APK Signature Scheme v2
signer — inspired by [ApkGolf](https://github.com/fractalwrench/ApkGolf),
but without sacrificing the launcher icon, the UI, or any functionality.

## What it does

Open Rouge and you get an edge-to-edge red screen (system bars hidden,
screen kept on). Touch anywhere and drag left/right:

- the **brightness of the app window** follows your finger's horizontal
  position (`0%` at the left edge → `100%` at the right edge)

It is intentionally a single self-contained screen — there is no settings
UI, no network, no dependencies.

## How small is it really?

Measured on this repository (`gradlew :app:assembleRelease` + `tools/release.py`):

| Artifact | Size |
|---|---|
| Typical Gradle+AppCompat hello world | ~1.5 MB |
| This app, plain `assembleRelease` (unsigned) | 2,967 B |
| After `tools/optimize_sign.py` (optimized, unsigned) | 1,578 B |
| **Signed release APK (this repo's default)** | **2,145 B** |

A stock `apksigner` run would pad the signing block and the central
directory to 4 KB boundaries, adding several KB of dead weight to an APK
this size. The in-repo signer (`tools/v2sign.py`) does not.

What's inside the 2,145 B — and note what's *not* there:

| Component | Bytes (approx.) |
|---|---|
| `classes.dex` (R8-minified, deflated, metadata slimmed) | ~821 |
| `AndroidManifest.xml` (compiled, deflated, golfed) | ~523 |
| ~~`resources.arsc`~~ | **none** |
| v2 signing block (tight, EC P-256 + minimal cert) | ~585 |
| ZIP headers / central directory (incl. 4-byte zipalign padding) | ~215 |

The manifest golfing step (technique 8) is what takes the compiled
`AndroidManifest.xml` from 1,908 B raw (715 B deflated) down to 1,184 B raw
(523 B deflated) before signing.  The dex-golf step (technique 9) then slims
R8/D8's own metadata strings in `classes.dex`, cutting the deflated entry
from 985 B to 821 B.

There is **no `resources.arsc` at all**: the icon references a framework
color (`@android:color/holo_red_light`), the theme is the framework
`Theme.Material.NoActionBar`, and the red background is set in code — so
Android never needs an app resource table (verified on-device).

## Repository layout

```
app/                          Android app module (single Activity in one file)
  src/main/java/a/a.java
  build.gradle.kts            R8 full-mode, resource shrinking, zero deps
tools/
  release.py                  one-shot: key → build → optimize+sign → adb install + launch
  optimize_sign.py            post-build repack + zipalign + sign
  manifest_golf.py            re-encodes the compiled AndroidManifest.xml smaller
  dex_golf.py                 zeroes R8/D8 metadata strings in classes.dex
  v2sign.py                   pure-Python APK Signature Scheme v2 signer
```

## Requirements

- **JDK 17+** (JDK 21 recommended) — for Gradle
- **Android SDK** with `platforms;android-37` and recent `build-tools`
  (path goes in `local.properties` → `sdk.dir`, or `ANDROID_HOME`)
- **Python 3.9+** with the [`cryptography`](https://pypi.org/project/cryptography/)
  package (key generation and signing; the repack step alone needs no extras)

## Build & install

The one-command flow generates a signing key if you don't have one, builds,
optimizes, signs, installs on a connected device, and launches the app:

```bash
python tools/release.py
```

Useful flags:

```bash
python tools/release.py --no-install        # just produce the signed APK
python tools/release.py --no-build          # reuse the existing unsigned APK
python tools/release.py --ks your.p12 --ks-pass secret   # your own key
```

Manual equivalent:

```bash
./gradlew :app:assembleRelease
python tools/optimize_sign.py \
    app/build/outputs/apk/release/app-release-unsigned.apk \
    app-release-final.apk \
    --sign --ks your.p12 --ks-pass secret
adb install -r app-release-final.apk
```

Outputs land in `app/build/outputs/apk/release/`:

- `app-release-unsigned.apk` — plain Gradle output
- `app-release-final.apk` — optimized + v2-signed APK (2,145 B)

Launch it with `adb shell am start -n ca.justinmo.r/a.a` (or just run
`tools/release.py`, which installs and launches it for you).

## Signing key

`tools/release.py` auto-generates an **EC P-256** keystore at
`build/keys/release.p12` (gitignored) with a random password stored next to
it in `build/keys/release.p12.pass`. Treat those two files as the app's
signing identity:

- **Back them up.** If you lose them, you can never ship an update over an
  installed copy (Android requires the same key).
- The auto-generated certificate is minimal (no X.509 extensions) to keep
  the signing block small — but identity = the *whole keystore*: Android
  treats a re-issued certificate as a different signer, so change it only
  for fresh installs (uninstall required), never for published updates.
- For Play Store / long-lived apps, generate one key once and keep it; pass
  it explicitly with `--ks` / `--ks-pass`.

The signer itself (`tools/v2sign.py`) implements APK Signature Scheme v2
exactly as AOSP apksig does (CHUNKED_SHA256 content digests, length-prefixed
signer blocks), but writes a **byte-tight signing block** — modern
`apksigner` pads the block and the central directory to 4 KB boundaries,
adding several KB of dead weight to small APKs.

## Why is it so small?

A checklist of the techniques used (full details live in each file):

1. **No dependencies, no AndroidX.** The Activity extends `android.app.Activity`
   directly; AppCompat/ConstraintLayout would pull in tens of thousands of methods.
2. **One tiny source file.** The whole app is a single Java class.
3. **R8 full-mode minification + resource shrinking** (`isMinifyEnabled`,
   `isShrinkResources`, `android.enableR8.fullMode=true`).
4. **No bundled drawables and no resource table.** The launcher icon
   references a framework color (`@android:color/holo_red_light`) instead of
   an own resource, so `resources.arsc` is dropped entirely (aapt2 only
   emits a 40-byte stub for a resource-less app; the optimizer removes it).
5. **The red window background is set in code**, not via a custom style:
   the Activity source (`app/src/main/java/a/a.java`) calls
   `getWindow().getDecorView().setBackgroundColor(0xFFFF0000)`
   and the manifest theme is the framework `Theme.Material.NoActionBar`.
6. **Deterministic, trimmed packaging**:
   - `localeFilters += "en"` and `META-INF/**` excluded,
   - app-metadata.properties entry stripped,
   - `classes.dex` re-deflated at max compression (Gradle stores it raw),
   - an empty `resources.arsc` stub is dropped (real tables are kept),
   - stable ZIP timestamps (reproducible output).
7. **EC P-256 key with a minimal certificate + v2-only signing** (no v1 JAR
   signature, whose `META-INF/CERT.*` files would add ~2 KB) via the tight
   in-repo signer.
8. **The compiled manifest is re-encoded smaller** (`tools/manifest_golf.py`,
   wired into `optimize_sign.py`; disable with `--no-manifest-golf`). aapt2
   stores the manifest's string pool as UTF-16 and injects informational
   attributes (`versionName`, `compileSdkVersion`, `compileSdkVersionCodename`,
   `platformBuildVersionCode/Name`, `extractNativeLibs`) that nothing reads at
   runtime. The optimizer drops those and re-encodes the identical element
   tree with a deduplicated UTF-8 string pool (raw 1,908 B → 1,184 B, so the
   deflated entry in the signed APK drops from 715 B to 523 B).
   aapt2 writes manifest pools as UTF-16 to dodge an old OEM device bug; the
   UTF-8 flag is standard and fine on modern Android, but if a device ever
   fails to parse the golfed manifest, set `UTF8_POOL = False` in
   `tools/manifest_golf.py` — the attribute drops still save most of the
   bytes. The tool falls back to the untouched manifest unless its own
   parse-and-compare self-check passes, and the result is verified by a real
   install on each release run.
9. **R8/D8 metadata is slimmed in `classes.dex`** (`tools/dex_golf.py`,
   wired into `optimize_sign.py`; disable with `--no-dex-golf`). R8 embeds an
   unreferenced ~200 B provenance marker (`~~R8{...}`, no flag disables it)
   and AGP 8.12+ writes a 74-char `r8-map-id-*` as the class SourceFile. The
   optimizer rewrites both strings to compressible runs (e.g.
   `r8-map-id-aaa...`) -- same length, same pool position, so the dex
   structure and ART's verifier are untouched (verified with build-tools
   dexdump) -- and refreshes the dex header checksums.  The deflated
   `classes.dex` entry drops 985 B → 821 B.  Runtime behaviour is unchanged;
   the SourceFile a crash trace shows is a junk run instead of the map-id
   hash.

Nothing here changes behaviour or the package name — the app on your screen
is byte-for-byte the same logic as the plain Gradle build. (The launcher
icon color is the only visual choice left to you: `holo_red_light` is used
so it costs zero bytes, but any `@android:color/…` or your own drawable
works the same way.)

## Compatibility

| | |
|---|---|
| Package | `ca.justinmo.r` |
| minSdk / target / compile | 37 / 37 / 37 |
| Signature scheme | APK Signature Scheme v2 only (fine for minSdk ≥ 24) |
| Permissions | none (window brightness + keep-screen-on need none) |
