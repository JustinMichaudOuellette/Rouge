# Rouge

**A full-screen red Android app that turns horizontal touch/drag into a
brightness control — shipped as a ~2.0 KB signed APK.**

`ca.justinmo.r` · minSdk 37 · targetSdk 37 · zero dependencies

Rouge is both a tiny utility and an exercise in aggressive APK size golf:
the release APK you install is a hand-tuned ~2.0 KB, built with standard
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
| After `tools/optimize_sign.py` (optimized, unsigned) | 1,461 B |
| **Signed release APK (with Zopfli, technique 10)** | **2,028 B** |
| Signed release APK (Zopfli not installed: zlib -9 only) | 2,078 B |
| Signed with a minimal certificate (`--recert`, technique 11) | 2,019 B |

The last two rows are the same pipeline with one ingredient missing, so a
machine without Zopfli builds the 2,078 B APK. Signing is the other jitter
source: the ECDSA signature is DER-encoded and its length varies by a byte or
two, so a signed build measures 2,028 B ±1 B.

A stock `apksigner` run would pad the signing block and the central
directory to 4 KB boundaries, adding several KB of dead weight to an APK
this size. The in-repo signer (`tools/v2sign.py`) does not.

What's inside the 2,028 B — and note what's *not* there:

| Component | Bytes |
|---|---|
| `classes.dex` (R8-minified, metadata stripped, deflated) | 735 |
| `AndroidManifest.xml` (compiled, deflated, golfed) | 492 |
| ~~`resources.arsc`~~ | **none** |
| v2 signing block (tight, EC P-256 + 233–266 B cert) | 567 |
| ZIP local headers + central directory + EOCD (2 entries) | 234 |

The manifest golfing step (technique 8) is what takes the compiled
`AndroidManifest.xml` from 1,908 B raw down to 1,184 B raw before signing.
The dex-golf step (technique 9) removes R8/D8's own metadata strings from
`classes.dex`, taking it from 1,632 B raw to 1,360 B. Technique 10 then
deflates both entries as far as they will go, landing the two entries at
735 B and 492 B.

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
  dex_golf.py                 strips R8/D8 metadata strings out of classes.dex
  mincert.py                  builds the 233-257 B self-signed signing certificate
  v2sign.py                   pure-Python APK Signature Scheme v2 signer
```

## Requirements

- **JDK 17+** (JDK 21 recommended) — for Gradle
- **Android SDK** with `platforms;android-37` and recent `build-tools`
  (path goes in `local.properties` → `sdk.dir`, or `ANDROID_HOME`)
- **Python 3.9+** with the [`cryptography`](https://pypi.org/project/cryptography/)
  package (key generation and signing; the repack step alone needs no extras)
  and, optionally, [`zopfli`](https://pypi.org/project/zopfli/) for the
  smallest possible DEFLATE (see technique 10; without it the build still
  works, just 50 B larger — 2,078 B instead of 2,028 B)

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
python tools/release.py --recert            # re-issue the certificate smaller
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

`optimize_sign.py` also takes `--work-dir DIR` to keep the intermediate
repacked/aligned APKs for inspection instead of deleting them, and switches
for turning each golfing step off (`--no-dex-golf`, `--no-manifest-golf`,
`--no-zopfli`) so a suspect build can be bisected.

Outputs land in `app/build/outputs/apk/release/`:

- `app-release-unsigned.apk` — plain Gradle output
- `app-release-final.apk` — optimized + v2-signed APK (2,028 B; 2,078 B
  without the optional Zopfli)

Launch it with `adb shell am start -n ca.justinmo.r/a.a` (or just run
`tools/release.py`, which installs and launches it for you).

## Signing key

`tools/release.py` auto-generates an **EC P-256** keystore at
`build/keys/release.p12` (gitignored) with a random password stored next to
it in `build/keys/release.p12.pass`. Treat those two files as the app's
signing identity:

- **Back them up.** If you lose them, you can never ship an update over an
  installed copy (Android requires the same key).
- The certificate is generated by `tools/mincert.py` — a 257 B version 1,
  no-extensions certificate (technique 11) — but identity = the *certificate*:
  Android treats a re-issued certificate as a different signer, so change it
  only for fresh installs (uninstall required), never for published updates.
  `--recert` re-issues an existing keystore's certificate as the minimal one
  (worth 9 B on this APK, and 24 B against the ~281 B certificate
  `cryptography` would otherwise produce); it prints the old and new
  certificate hashes and reminds you about the uninstall.
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
   deflated entry in the signed APK drops from 715 B to 492 B).
   aapt2 writes manifest pools as UTF-16 to dodge an old OEM device bug; the
   UTF-8 flag is standard and fine on modern Android, but if a device ever
   fails to parse the golfed manifest, set `UTF8_POOL = False` in
   `tools/manifest_golf.py` — the attribute drops still save most of the
   bytes. The tool falls back to the untouched manifest unless its own
   parse-and-compare self-check passes, and the result is verified by a real
   install on each release run.
9. **R8/D8 metadata is removed from `classes.dex`** (`tools/dex_golf.py`,
   wired into `optimize_sign.py`; disable with `--no-dex-golf`). R8 embeds an
   unreferenced ~200 B provenance marker (`~~R8{...}`, no flag disables it)
   and AGP 8.12+ writes a 74-char `r8-map-id-*` as the class SourceFile. The
   optimizer replaces both with the shortest string that keeps the string
   pool sorted (one character, chosen to sort between the neighbours) and
   then fixes up everything the shorter string data invalidates: every
   `string_ids` offset after the first shortened string, the items that live
   after the string data (re-laid out with the alignment their type
   requires), every offset field that pointed at one of them, and the
   header's `file_size`/`data_size`/`map_off` plus both checksums. Nothing is
   renumbered — the string, type, proto, field, method and class counts are
   untouched — and the rewrite is abandoned unless every re-parse check
   passes. Raw `classes.dex` drops 1,632 B → 1,360 B and the deflated entry
   762 B → 735 B. (The earlier version of this step rewrote the characters in
   place, `r8-map-id-aaa...`: same layout, but it leaves a 200-byte run of
   `a` for DEFLATE to encode, and removing the characters outright is worth
   another ~21 B.) Verified with build-tools `dexdump` and an on-device
   install; the only observable difference is that the SourceFile a crash
   trace shows is a one-letter junk run instead of the map-id hash.
10. **Every deflated entry is compressed with Zopfli**
   (`tools/optimize_sign.py`; needs the optional `pip install zopfli`,
   disable with `--no-zopfli`). Zopfli emits plain DEFLATE, so Android
   decompresses it unchanged — it simply searches longer for a smaller
   stream than zlib. It takes the signed APK from 2,078 B (zlib -9 only) to
   2,028 B: `classes.dex` 770 → 735 B and `AndroidManifest.xml` 507 → 492 B
   deflated. The search parameters are tuned on these exact payloads
   (`ZOPFLI_ITERATIONS = 1000`, `ZOPFLI_BLOCKSPLITTING_MAX = 2`); the earlier
   `blocksplittingmax = 1` was optimal for the pre-dex-golf 1632 B dex and
   silently costs 6 B now, so re-measure them if the payloads change shape.
   Most of the remaining bytes are the v2 signing block and ZIP headers,
   which compression cannot touch.
11. **The signing certificate is built by hand** (`tools/mincert.py`; used
   when `release.py` creates a keystore, and by `release.py --recert` for an
   existing one). The certificate is half of the v2 signing block, so its
   size is paid for once per APK: a keytool/Android Studio certificate is
   700–900 B, `cryptography.CertificateBuilder` gives ~281 B, and this
   builder gives **257 B** — version 1 (no `[0]` version field), no X.509
   extensions, minimal serial, `UTCTime` validity (13-byte times instead of
   17-byte `GeneralizedTime`) and a *one-character* CommonName.
   `build_best()` also re-rolls the ECDSA nonce until the signature's DER
   encoding is as short as P-256 allows (70 B rather than 71–72 B), and
   `tools/v2sign.py` does the same for the APK signature itself. The
   certificate *is* the signing identity, so it is generated once and stored
   in the keystore — never per build; `optimize_sign.py` therefore trusts the
   file and re-issues nothing.

   A certificate with an **empty** subject and issuer DN (`30 00`) would be
   another 24 B smaller (233 B) and `cryptography` parses it without
   complaint, but `apksigner` — the same apksig code the platform verifier is
   built from — rejects it as a malformed certificate, so it is not offered.

Nothing here changes behaviour or the package name — the app on your screen
is byte-for-byte the same logic as the plain Gradle build. (The launcher
icon color is the only visual choice left to you: `holo_red_light` is used
so it costs zero bytes, but any `@android:color/…` or your own drawable
works the same way.)

## Dead ends (measured, so you don't have to try them)

Every idea below looks like free bytes on paper. Each was built, signed and —
where it got that far — offered to a Pixel 7a on Android 17:

| Idea | Would have saved | What actually happens |
|---|---|---|
| ZIP entries whose *local* headers omit the file name (the central directory keeps it) | 30 B | Android's `StrictJarFile` cannot find the entry: `Failed to parse AndroidManifest.xml`. It takes the data offset from the local header, not the central directory alone. |
| Dropping the manifest's XML namespace nodes, and with them the `android` prefix and the schema URI from the string pool | ~48 B | The AXML parser rejects the file outright: `Corrupt XML binary file`. `aapt2` emits those nodes for a reason. |
| An empty subject/issuer DN in the certificate (`30 00`) | 24 B | `apksigner`, and the platform verifier it mirrors: `Malformed certificate #1`. |
| More Zopfli iterations | 0 B | 15 → 3000 iterations moves the total by ±2 B in both directions; 1000 is the plateau. |
| Dropping the `setBrightness` helper to remove a method from the dex | 0 B | R8 already inlines it into both callers — the dex holds exactly three code items (the constructor, `onCreate`, `onTouchEvent`). |
| A class name shorter than `a.a` | ~4 B | Already minimal: `-repackageclasses 'a'` yields the descriptor `La/a;`. A root-package class (`-repackageclasses ''`) could only be reached as `ca.justinmo.r.a`, which is longer. |

The remaining semantic switches are real bytes, but they change what the app
*is*, so they are off by default. Their exact measured cost in the signed
APK:

| Manifest attribute | Bytes saved if dropped | Price |
|---|---|---|
| `android:label="R"` | 29 B | the launcher lists the app as `ca.justinmo.r` |
| `android:theme` | 21 B | needs a `requestWindowFeature(NO_TITLE)` call to keep the title bar away, and most of the saving goes back into the dex |
| `android:icon` | 19 B | the default system icon instead of the red one |
| `android:targetSdkVersion` | 17 B | **changes behaviour**: the app would run in legacy compatibility mode |
| `android:versionCode` | 15 B | `versionCode` becomes 0, and `adb install -r` then refuses the next build as a downgrade |
| `android:minSdkVersion` | 14 B | the APK claims API 1+, so it installs on devices whose runtime cannot load a format-039 dex |
| all six | 119 B | — |

After that there is no slack left to find: the other 801 B of the 2,028 B APK
are the v2 signing block (567 B — 266 B certificate, 70 B ECDSA signature,
91 B public key, the rest framing) and the ZIP container itself (234 B of
local headers, central directory and EOCD for exactly two entries).

## Compatibility

| | |
|---|---|
| Package | `ca.justinmo.r` |
| minSdk / target / compile | 37 / 37 / 37 |
| Signature scheme | APK Signature Scheme v2 only (fine for minSdk ≥ 24) |
| Permissions | none (window brightness + keep-screen-on need none) |
