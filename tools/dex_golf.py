#!/usr/bin/env python3
"""Strip build-tool metadata strings out of classes.dex.

R8/D8 embeds two pieces of metadata into the dex string pool that no runtime
code ever reads:

  * a provenance marker string, e.g.
      ~~R8{"backend":"dex","compilation-mode":"release", ... "version":"9.4.14"}
    (~200 B, zero references in the whole file; there is deliberately no R8
    flag to disable it), and
  * AGP (8.12+) writes "r8-map-id-<hash>" as the class SourceFile
    (class_def.source_file_idx) so crash-retrace tooling can find the mapping
    file.

golf_dex() rewrites those strings to the *shortest* replacement that keeps the
string pool sorted -- one character, chosen to sort strictly between the
string's neighbours -- and then fixes up everything the move invalidates:

  * the string data items, written back-to-back in string_ids order (dex
    string data items are byte-aligned and must appear in that order),
  * every string_ids offset after the first shortened string,
  * the items that live after the string data (class_data_item, map_list, ...)
    which are re-laid out with the alignment each item type requires,
  * every u32 field in the file that holds an offset into a moved item
    (map_list entries, class_def.interfaces_off/annotations_off/
    class_data_off/static_values_off, proto_id.parameters_off,
    code_item.debug_info_off, header.map_off),
  * header file_size / data_size / map_off, and the SHA-1 signature +
    Adler-32 checksum.

Nothing is renumbered: the string, type, proto, field, method and class counts
are untouched, so no index anywhere in the file changes.  The two junk strings
are the only content that differs (the SourceFile a crash trace shows becomes a
one-letter junk run instead of the map-id hash), and the deflated entry shrinks
-- on this app 1632 B raw / 762 B deflated down to 1358 B raw / ~728 B
deflated, i.e. ~34 B off the signed APK.

Two rejected alternatives, for the record:

  * Rewriting the characters in place ("r8-map-id-aaaa...") keeps the layout
    byte-identical, but a 200-character run of 'a' still costs DEFLATE ~10-20
    bytes; removing the characters costs the same once and then the bytes are
    gone from the raw file as well.
  * Deleting the pool entries outright is worse than it looks: emptying a
    string breaks the sorted-pool invariant ART checks (an empty string has to
    sort first), and dropping entries renumbers every string index in the file
    (descriptors, names, shorties, source_file_idx).  A one-character
    replacement keeps the invariant with an index-identical rewrite.

Correctness guard: the result is re-parsed and checked before it is returned --
string pool ordering and contiguity, map_list ordering and alignment,
cross-section offsets, header sizes and checksums -- and the rewrite is
abandoned (returning the input bytes) unless every check passes.  Sections that
carry offsets we do not model (annotation sets/directories, call sites) make
the rewrite bail out rather than guess.  Validate with build-tools `dexdump`
and an on-device install (tools/release.py does both).
"""
import hashlib
import struct
import zlib

MARKER_PREFIXES = (b"~~R8{", b"~~D8{", b"~~L8{", b"r8-map-id-")

HEADER_ITEM = 0x0000
STRING_ID_ITEM = 0x0001
CALL_SITE_ID_ITEM = 0x0007
METHOD_HANDLE_ITEM = 0x0008
MAP_LIST = 0x1000
TYPE_LIST = 0x1001
ANNOTATION_SET_REF_LIST = 0x1002
ANNOTATION_SET_ITEM = 0x1003
CLASS_DATA_ITEM = 0x2000
CODE_ITEM = 0x2001
STRING_DATA_ITEM = 0x2002
DEBUG_INFO_ITEM = 0x2003
ANNOTATION_ITEM = 0x2004
ENCODED_ARRAY_ITEM = 0x2005
ANNOTATIONS_DIRECTORY_ITEM = 0x2006

# Items whose start must be 4-byte aligned (dex-format alignment rules).
ALIGN4 = {MAP_LIST, TYPE_LIST, ANNOTATION_SET_REF_LIST, ANNOTATION_SET_ITEM,
          CODE_ITEM, ANNOTATIONS_DIRECTORY_ITEM, CALL_SITE_ID_ITEM,
          METHOD_HANDLE_ITEM}

# Section types we refuse to rewrite a file containing, because they hold
# offsets to other items that this tool does not patch.
BAIL_TYPES = {ANNOTATION_SET_REF_LIST, ANNOTATION_SET_ITEM, ANNOTATION_ITEM,
              ANNOTATIONS_DIRECTORY_ITEM, CALL_SITE_ID_ITEM, METHOD_HANDLE_ITEM}


class _Bad(Exception):
    """Internal: the dex is not shaped the way we can safely rewrite it."""


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


def _uleb_len(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _align4(n):
    return n + (-n % 4)


def _parse_header(d):
    if len(d) < 0x70 or d[:4] != b"dex\n" or d[7] != 0:
        raise _Bad("not a dex")
    h = {
        "file_size": _u32(d, 0x20), "header_size": _u32(d, 0x24),
        "map_off": _u32(d, 0x34),
        "n_string": _u32(d, 0x38), "off_string": _u32(d, 0x3C),
        "n_type": _u32(d, 0x40), "off_type": _u32(d, 0x44),
        "n_proto": _u32(d, 0x48), "off_proto": _u32(d, 0x4C),
        "n_field": _u32(d, 0x50), "off_field": _u32(d, 0x54),
        "n_method": _u32(d, 0x58), "off_method": _u32(d, 0x5C),
        "n_class": _u32(d, 0x60), "off_class": _u32(d, 0x64),
        "data_size": _u32(d, 0x68), "data_off": _u32(d, 0x6C),
    }
    if h["header_size"] != 0x70 or h["file_size"] != len(d):
        raise _Bad("unexpected header/file size")
    if h["map_off"] == 0 or h["map_off"] >= len(d):
        raise _Bad("no map_list")
    return h


def _parse_map(d, map_off):
    """Return [(type, count, offset, entry_field_offset)] in map order."""
    size = _u32(d, map_off)
    entries = []
    o = map_off + 4
    for _ in range(size):
        if o + 12 > len(d):
            raise _Bad("map_list runs past EOF")
        entries.append((struct.unpack_from("<H", d, o)[0], _u32(d, o + 4),
                        _u32(d, o + 8), o))
        o += 12
    if o != len(d):
        raise _Bad("map_list is not the last item")
    offs = [e[2] for e in entries]
    if any(a > b for a, b in zip(offs, offs[1:])):
        raise _Bad("map_list not sorted")
    for t, count, _off, _e in entries:
        if t in BAIL_TYPES and count:
            raise _Bad("section we do not model: 0x%04x" % t)
    return entries


def _parse_strings(d, h):
    """Return [(item_off, uleb_len, body_off, nul_off, body_bytes)]."""
    out = []
    for i in range(h["n_string"]):
        so = _u32(d, h["off_string"] + 4 * i)
        if so >= len(d):
            raise _Bad("string_id out of range")
        ulen, body = _uleb(d, so)
        try:
            nul = d.index(b"\0", body)
        except ValueError:
            raise _Bad("unterminated string")
        out.append((so, ulen, body, nul, d[body:nul]))
    return out


def _shorten(body, prev, nxt):
    """Shortest replacement for `body` that still sorts between neighbours."""
    for cand in (body[:1], body[:2]):
        if cand and prev < cand and (nxt is None or cand < nxt):
            return cand
    for c in range(0x21, 0x7F):
        cand = bytes([c])
        if prev < cand and (nxt is None or cand < nxt):
            return cand
    return None


def _offset_fields(d, h, entries):
    """Locations of every u32 field in the file that holds a *file offset*."""
    locs = [0x34]                                   # header.map_off
    for i in range(h["n_proto"]):
        locs.append(h["off_proto"] + 12 * i + 8)    # parameters_off
    for i in range(h["n_class"]):
        o = h["off_class"] + 32 * i
        if o + 32 > len(d):
            raise _Bad("class_def out of range")
        locs += [o + 12, o + 20, o + 24, o + 28]    # interfaces/annotations/
        #                                             class_data/static_values
    for t, count, off, _e in entries:
        if t == CODE_ITEM:
            o = off
            for _ in range(count):
                if o + 16 > len(d):
                    raise _Bad("code_item out of range")
                if struct.unpack_from("<H", d, o + 6)[0]:
                    raise _Bad("code_item has try/catch (not modelled)")
                locs.append(o + 8)                  # debug_info_off
                o = _align4(o + 16 + 2 * _u32(d, o + 12))
    return locs


def golf_dex(data):
    """Return a dex with the R8/D8 metadata strings removed (or the input).

    Never raises: on any anomaly the original bytes are returned unchanged.
    """
    try:
        return _golf(data)
    except (_Bad, ValueError, IndexError, struct.error, UnicodeDecodeError):
        return data


def _golf(data):
    h = _parse_header(data)
    entries = _parse_map(data, h["map_off"])
    strings = _parse_strings(data, h)
    if not strings:
        return data

    # ---- which strings are junk, and what they shrink to ----
    repl = {}
    for i, (_so, _ul, _bo, _no, body) in enumerate(strings):
        for p in MARKER_PREFIXES:
            if body.startswith(p):
                prev = strings[i - 1][4] if i else b""
                nxt = strings[i + 1][4] if i + 1 < len(strings) else None
                short = _shorten(body, prev, nxt)
                if short is not None and len(short) < len(body):
                    repl[i] = short
                break
    if not repl:
        return data

    # ---- rebuild the string data region (same index order, same base) ----
    base = strings[0][0]
    pos = base
    for (so, _ul, _bo, no, _body) in strings:
        if so != pos:
            raise _Bad("string data is not packed in string_ids order")
        pos = no + 1
    old_end = pos
    if any(_u32(data, h["off_string"] + 4 * i) != strings[i][0]
           for i in range(h["n_string"])):
        raise _Bad("string_ids disagree")
    if entries[-1][0] != MAP_LIST or entries[-1][2] != h["map_off"]:
        raise _Bad("unexpected last item")
    sd = [e for e in entries if e[0] == STRING_DATA_ITEM]
    if len(sd) != 1 or sd[0][2] != base or sd[0][1] != h["n_string"]:
        raise _Bad("string_data section does not match string_ids")

    blob = bytearray()
    new_off = []
    for i, (_so, _ul, _bo, _no, body) in enumerate(strings):
        new_off.append(base + len(blob))
        b = repl.get(i, body)
        blob += _uleb_len(len(b)) + b + b"\0"
    new_end = base + len(blob)

    # ---- re-lay out everything that lived after the string data ----
    tail = [(t, c, o) for (t, c, o, _e) in entries if o >= old_end]
    if tail and tail[0][2] < old_end:
        raise _Bad("tail before string data")
    if tail and any(data[old_end:tail[0][2]]):
        raise _Bad("non-zero gap after string data")

    moved = {}
    out_tail = bytearray()
    pos = new_end
    for i, (t, _count, off) in enumerate(tail):
        end = tail[i + 1][2] if i + 1 < len(tail) else len(data)
        if end < off or end > len(data):
            raise _Bad("bad item span")
        pad = -pos % 4 if t in ALIGN4 else 0
        out_tail += b"\0" * pad
        pos += pad
        moved[off] = pos
        out_tail += data[off:end]
        pos += end - off

    out = bytearray(data[:base]) + blob + out_tail

    # ---- repoint every offset field that referred to a moved item ----
    for loc in _offset_fields(data, h, entries):
        old = _u32(data, loc)
        if old == 0:
            continue
        if old in moved:
            struct.pack_into("<I", out, loc, moved[old])
        elif old >= old_end:
            raise _Bad("offset field dangles into the moved region")
        # offsets below `base` point at items before the string data
        # (type_lists, annotation sets, code items ...): they do not move.
    # the map_list itself moved, so its entries are patched at their new home
    if h["map_off"] not in moved:
        raise _Bad("map_list did not move where expected")
    map_delta = moved[h["map_off"]] - h["map_off"]
    for _t, _c, off, entry_off in entries:
        loc = entry_off + 8
        if loc >= old_end:
            loc += map_delta
        if off in moved:
            struct.pack_into("<I", out, loc, moved[off])

    # ---- string_ids, header sizes, checksums ----
    for i in range(h["n_string"]):
        struct.pack_into("<I", out, h["off_string"] + 4 * i, new_off[i])
    struct.pack_into("<I", out, 0x20, len(out))
    struct.pack_into("<I", out, 0x34, moved.get(h["map_off"], h["map_off"]))
    struct.pack_into("<I", out, 0x68, len(out) - h["data_off"])
    out[12:32] = hashlib.sha1(bytes(out[32:])).digest()
    struct.pack_into("<I", out, 8, zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF)

    out = bytes(out)
    if len(out) >= len(data) or not _verify(data, out, strings, repl, base):
        return data
    return out


def _verify(old, new, strings, repl, base):
    """Re-parse the result and check every invariant this tool relies on."""
    try:
        h = _parse_header(new)
        entries = _parse_map(new, h["map_off"])
        s2 = _parse_strings(new, h)
    except _Bad:
        return False
    if len(s2) != len(strings):
        return False

    # strings: same bodies except the shortened ones, in order, packed,
    # offsets rewritten, pool still sorted
    keys = []
    pos = base
    for i, (so, ulen, _bo, no, body) in enumerate(s2):
        want = repl.get(i, strings[i][4])
        if body != want or so != pos or ulen != len(want):
            return False
        keys.append(body)
        pos = no + 1
    if any(a > b for a, b in zip(keys, keys[1:])):
        return False

    # everything before the string data must be untouched except the fields we
    # are allowed to rewrite: checksum/signature/sizes/map_off, string_ids,
    # and the offset fields that point into the moved region
    holes = {8, 0x20, 0x34, 0x68} | set(range(12, 32))
    holes |= {h["off_string"] + 4 * i for i in range(h["n_string"])}
    holes |= {loc for loc in _offset_fields(old, h, entries) if loc < base}

    def masked(buf):
        b = bytearray(buf[:base])
        for o in holes:
            if o + 4 <= len(b):
                b[o:o + 4] = b"\0\0\0\0"
        return bytes(b)

    if masked(old) != masked(new):
        return False

    # header sizes and checksums
    if (h["file_size"] != len(new) or h["data_off"] > len(new)
            or h["data_size"] != len(new) - h["data_off"]):
        return False
    if new[12:32] != hashlib.sha1(new[32:]).digest():
        return False
    if _u32(new, 8) != (zlib.adler32(new[12:]) & 0xFFFFFFFF):
        return False

    # map entries point at real, correctly aligned items
    for t, count, off, _e in entries:
        if count == 0:
            continue
        if off >= len(new) or (t in ALIGN4 and off % 4):
            return False
    # class_data reachable from class_def, and every offset field in range
    for i in range(h["n_class"]):
        cd = _u32(new, h["off_class"] + 32 * i + 24)
        if cd and not (base <= cd < len(new)):
            return False
    for loc in _offset_fields(new, h, entries):
        v = _u32(new, loc)
        if v and not (0 < v < len(new)):
            return False
    return True
