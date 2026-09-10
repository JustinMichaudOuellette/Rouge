#!/usr/bin/env python3
"""Report where an APK's bytes went, and re-tune the DEFLATE search.

Two things this project needs whenever it changes shape:

  * the byte budget -- how much of the APK is each entry, the v2 signing
    block, and the ZIP container itself (the three places bytes can hide);
  * a DEFLATE sweep over the two entries, because Zopfli's optimum depends on
    the payload: `optimize_sign.py`'s ZOPFLI_ITERATIONS /
    ZOPFLI_BLOCKSPLITTING_MAX were tuned for a 1632 B dex and had to be
    re-tuned once tools/dex_golf.py cut it to 1360 B.

Usage:
  python tools/size_report.py [<apk>]        # default: app-release-final.apk
  python tools/size_report.py <apk> --sweep  # add the Zopfli parameter sweep
"""
import argparse
import os
import struct
import sys
import zipfile
import zlib

MAGIC = b"APK Sig Block 42"
DEFAULT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "app", "build", "outputs", "apk", "release", "app-release-final.apk")


def _u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def _u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def budget(path):
    d = open(path, "rb").read()
    size = len(d)
    print(f"{path}: {size} B")
    eocd = d.rfind(b"PK\x05\x06")
    cd_off, cd_size = _u32(d, eocd + 16), _u32(d, eocd + 12)

    rows = []
    with zipfile.ZipFile(path) as z:
        total_local = total_data = 0
        for info in z.infolist():
            lho = info.header_offset
            nl, el = _u16(d, lho + 26), _u16(d, lho + 28)
            total_local += 30 + nl + el
            total_data += info.compress_size
            rows.append((info.filename, info.compress_size, info.file_size))
        entries = len(z.infolist())
        for name, csize, usize in rows:
            pct = 100 * csize / size
            print(f"  entry  {name:22s} {csize:6d} B deflated "
                  f"({usize} B raw, {pct:4.1f}%)")

    block = 0
    m = d.find(MAGIC)
    if m > 0:
        bsize = struct.unpack_from("<Q", d, m - 8)[0]
        start = m + 16 - (bsize + 8)
        block = m + 16 - start
        cert = _v2_cert_size(d[start:m])
        print(f"  v2 signing block       {block:6d} B "
              f"({100 * block / size:4.1f}%)"
              + (f", certificate {cert} B" if cert else ""))

    zip_over = size - total_data - block
    print(f"  ZIP container          {zip_over:6d} B "
          f"({100 * zip_over / size:4.1f}%) -- {total_local} B local headers, "
          f"{cd_size} B central directory, 22 B EOCD, {entries} entries")
    check = total_data + block + zip_over
    assert check == size, (check, size)


def _v2_cert_size(block):
    """Pull the signer certificate's DER length out of the v2 block."""
    try:
        body = block
        plen = struct.unpack_from("<Q", body, 8)[0]
        value = body[20:8 + plen]
        outer = _lp(value)[0]
        inner = _lp(outer)[0]
        _sd, _sigs, _pk = _lp(inner)
        parts = _lp(_sd)
        return len(_lp(parts[1])[0])
    except (struct.error, IndexError):
        return None


def _lp(d):
    """Parse a sequence of u32-length-prefixed elements."""
    out, o = [], 0
    while o + 4 <= len(d):
        n = _u32(d, o)
        out.append(d[o + 4:o + 4 + n])
        o += 4 + n
    return out


def sweep(path, iterations=(15, 100, 500, 1000, 3000),
          splits=(0, 1, 2, 4, 8, 15)):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import dex_golf
    import manifest_golf
    with zipfile.ZipFile(path) as z:
        names = {i.filename: z.read(i.filename) for i in z.infolist()}
    dex = dex_golf.golf_dex(names.get("classes.dex", b""))
    man = manifest_golf.golf_manifest(names.get("AndroidManifest.xml", b""))
    try:
        import zopfli.zlib as zp
    except ImportError:
        print("\nzopfli not installed; skipping the sweep")
        return
    print(f"\nDEFLATE sweep (dex {len(dex)} B, manifest {len(man)} B):")
    best = None
    for n in iterations:
        for bs in splits:
            d = len(zp.compress(dex, numiterations=n, blocksplittingmax=bs)) - 6
            m = len(zp.compress(man, numiterations=n, blocksplittingmax=bs)) - 6
            zl = _zlib9(dex), _zlib9(man)
            if best is None or d + m < best[0] + best[1]:
                best = (d, m, n, bs)
            print(f"  iter={n:5d} splitting={bs:3d}: dex={d:4d} man={m:4d} "
                  f"total={d + m:4d}")
    print(f"  zlib -9 baseline: dex={zl[0]} man={zl[1]} "
          f"total={zl[0] + zl[1]}")
    print(f"  best: iter={best[2]} splitting={best[3]} -> "
          f"{best[0]} + {best[1]} = {best[0] + best[1]} B")


def _zlib9(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return len(c.compress(data) + c.flush())


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("apk", nargs="?", default=DEFAULT)
    ap.add_argument("--sweep", action="store_true",
                    help="also sweep Zopfli's iterations/blocksplittingmax")
    args = ap.parse_args()
    if not os.path.exists(args.apk):
        sys.exit(f"not found: {args.apk}")
    budget(args.apk)
    if args.sweep:
        sweep(args.apk)


if __name__ == "__main__":
    main()
