#!/usr/bin/env python3
"""Slim down build-tool metadata strings inside classes.dex.

R8/D8 embeds two pieces of metadata into the dex string pool that no runtime
code ever reads:

  * a provenance marker string, e.g.
      ~~R8{"backend":"dex","compilation-mode":"release", ... "version":"9.4.14"}
    (~200 B, zero references in the whole file; there is deliberately no R8
    flag to disable it), and
  * AGP (8.12+) writes "r8-map-id-<hash>" as the class SourceFile
    (class_def.source_file_idx) so crash-retrace tooling can find the mapping
    file.

golf_dex() rewrites those strings' characters to compressible runs, e.g.
"r8-map-id-" + "aaaa...".  The dex structure is left byte-identical: each
string keeps its exact length, offset and NUL terminator, and its leading
bytes (which determine its position in the sorted string pool), so ART's dex
verifier sees the same well-formed, sorted, contiguous string data.  Only the
character bytes change, so the blobs deflate to almost nothing and the header
SHA-1 / Adler-32 integrity fields are refreshed (signature first, then the
checksum over the file from offset 12, which includes the signature).

Why not just zero the strings out?  Emptying them shrinks the string-data
items ART walks by their length prefixes, desynchronising the section layout,
which ART rejects ("Non-zero padding before section of type ...") -- verified
with build-tools dexdump.  This replacement keeps every string valid.

Effect on the APK: byte-identical runtime behaviour; the SourceFile shown in
stack traces is a short junk run instead of the map-id hash.  Disable with
--no-dex-golf on tools/optimize_sign.py.
"""
import hashlib
import struct
import zlib

MARKER_PREFIXES = (b"~~R8{", b"~~D8{", b"~~L8{", b"r8-map-id-")


def _u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def _uleb(d, o):
    r = 0
    s = 0
    while True:
        b = d[o]
        o += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            return r, o
        s += 7


def _strings(d, sids_off, sids_size):
    """Return list of (body_bytes, body_start_after_length_prefix, nul_pos)."""
    out = []
    for i in range(sids_size):
        so = _u32(d, sids_off + 4 * i)
        _utf16_len, nxt = _uleb(d, so)
        j = d.index(b"\0", nxt)
        out.append((d[nxt:j], nxt, j))
    return out


def _utf16_key(text):
    """Byte-compare key matching ART's UTF-16 string ordering."""
    return text.decode("utf-8").encode("utf-16-le")


def golf_dex(data):
    """Return a dex with R8/D8 metadata strings slimmed (or the input).

    Never raises: on any anomaly the original bytes are returned unchanged.
    """
    try:
        if len(data) < 0x70 or data[:4] != b"dex\n":
            return data
        sids_size = _u32(data, 0x38)
        sids_off = _u32(data, 0x3C)
        entries = _strings(data, sids_off, sids_size)

        out = bytearray(data)
        changed = False
        for body, nxt, j in entries:
            prefix = None
            for p in MARKER_PREFIXES:
                if body.startswith(p):
                    prefix = p
                    break
            if prefix is None:
                continue
            new_body = prefix + b"a" * (len(body) - len(prefix))
            if new_body == body:
                continue
            out[nxt:j] = new_body
            changed = True

        if not changed:
            return data

        # Guard: the replacement must keep the string pool sorted (ART's
        # verifier checks it).  Re-decode and compare adjacent entries.
        keys = [_utf16_key(bytes(out[n:j])) for _b, n, j in
                _strings(out, sids_off, sids_size)]
        if any(a > b for a, b in zip(keys, keys[1:])):
            return data

        # Refresh the header integrity fields.  Order matters: write the
        # SHA-1 signature (offset 12, over everything from offset 32) first,
        # then the Adler-32 checksum (offset 8) over everything from offset
        # 12 -- which includes the signature field.  ART rejects a dex whose
        # header checksums don't match its content.
        out[12:32] = hashlib.sha1(bytes(out[32:])).digest()
        struct.pack_into("<I", out, 8, zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF)
        return bytes(out)
    except (ValueError, IndexError, struct.error):
        return data
