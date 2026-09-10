#!/usr/bin/env python3
"""Shrink the compiled AndroidManifest.xml (aapt2 binary XML) inside the APK.

aapt2 compiles the manifest into binary XML ("AXML").  For a manifest this
small most of the bytes are encoding overhead, not information:

  * the string pool is stored UTF-16 even though every string is ASCII
    (aapt2 deliberately does this for manifests - see note below), and
  * aapt2/AGP inject "informational" attributes nothing reads at runtime:
      <manifest>     versionName, compileSdkVersion, compileSdkVersionCodename,
                     platformBuildVersionCode, platformBuildVersionName
      <application>  extractNativeLibs="false"   (no native libs exist)

golf_manifest() re-encodes the manifest with the *identical* element tree and
runtime attributes (versionCode, uses-sdk, icon/label/theme, exported, and the
MAIN/LAUNCHER intent filters are all kept), but:

  * drops the informational attributes listed above,
  * rebuilds the string pool as UTF-8, deduplicated, containing only strings
    the tree references.  The first n slots keep the framework attribute names
    in resource-map order (pool index == resource-map index, exactly the
    invariant aapt2's XmlFlattener produces and ResXMLParser relies on), and
  * re-serializes every chunk tightly; typed values are copied byte-identically
    (only TYPE_STRING data indices are remapped to the new pool).

Correctness guard: the output is re-parsed and its semantic dump (tree +
attribute namespaces/names/values) must equal the input's dump with the same
informational attributes removed.  On any mismatch, unexpected structure, or
parse failure golf_manifest() returns the input unchanged rather than risking
an uninstallable APK.

Note on UTF-8: aapt2 writes manifest string pools as UTF-16 on purpose
(tools/aapt2/format/binary/XmlFlattener.cpp cites an OEM-device memory bug
triggered by UTF-8 manifest pools).  UTF8_FLAG pools are standard and every
modern Android reads them fine, but if a device ever fails to install the
result, set UTF8_POOL = False below - the attribute drops alone still save
most of the bytes.
"""
import struct

NO_ENTRY = 0xFFFFFFFF
TYPE_STRING = 0x03
UTF8_FLAG = 0x0100

# Framework-attribute resource IDs that aapt2/AGP inject but PackageManager
# never reads for behavior.  Safe to drop.  (versionCode 0x0101021b is kept.)
DROP_RIDS = {
    0x0101021c,  # versionName
    0x01010572,  # compileSdkVersion
    0x01010573,  # compileSdkVersionCodename
    0x010104ea,  # extractNativeLibs
}
# Same, but these have no framework resource ID (plain string attr names).
DROP_NAMES = {"platformBuildVersionCode", "platformBuildVersionName"}

UTF8_POOL = True  # see module note


def _u16(data, o):
    return struct.unpack_from("<H", data, o)[0]


def _u32(data, o):
    return struct.unpack_from("<I", data, o)[0]


def _decode_length(data, o, wide):
    """Return (value, next_offset) for a ResStringPool length prefix.

    wide=False -> UTF-8 style: 1 byte, 2 bytes if the high bit is set.
    wide=True  -> UTF-16 style: 1 u16, 2 u16s if the high bit is set.
    """
    if not wide:
        v = data[o]
        if v & 0x80:
            return ((v & 0x7F) << 8) | data[o + 1], o + 2
        return v, o + 1
    v = _u16(data, o)
    if v & 0x8000:
        return ((v & 0x7FFF) << 16) | _u16(data, o + 2), o + 4
    return v, o + 2


def parse(data):
    """Return (strings, map_rids, nodes).

    nodes is a flat list of tuples:
      ("ns", chunk_type, prefix_idx, uri_idx)      types 0x0100/0x0101
      ("elem", name_idx, [attr tuples])            type 0x0102
      ("end", ns_idx, name_idx)                    type 0x0103
    attr tuple: (ns_idx, name_idx, is_map, raw_idx, data_type, data)
    is_map=True  -> name_idx indexes the resource map (framework attribute).
    is_map=False -> name_idx indexes the string pool.
    """
    if len(data) < 8 or _u16(data, 0) != 0x0003:
        raise ValueError("not a binary XML file")
    strcount = _u32(data, 8 + 8)
    flags = _u32(data, 8 + 16)
    sstart = _u32(data, 8 + 20)
    utf8 = bool(flags & UTF8_FLAG)
    strings = []
    for i in range(strcount):
        so = 8 + sstart + _u32(data, 8 + 28 + 4 * i)
        if utf8:
            _charlen, so = _decode_length(data, so, False)
            blen, so = _decode_length(data, so, False)
            strings.append(data[so:so + blen].decode("utf-8"))
        else:
            _clen, so = _decode_length(data, so, True)
            n = _clen  # u16 length is in UTF-16 code units
            strings.append(data[so:so + 2 * n].decode("utf-16-le"))
    map_rids = []
    nodes = []
    off = 8
    seen_map = False
    while off < len(data):
        t = _u16(data, off)
        size = _u32(data, off + 4)
        if t == 0x0180:
            if seen_map:
                raise ValueError("duplicate resource map")
            seen_map = True
            n = (size - 8) // 4
            map_rids = [_u32(data, off + 8 + 4 * k) for k in range(n)]
        elif t in (0x0100, 0x0101):
            nodes.append(("ns", t, _u32(data, off + 16), _u32(data, off + 20)))
        elif t == 0x0102:
            name = _u32(data, off + 20)
            acount = _u16(data, off + 28)
            attrs = []
            a = off + 36
            for _ in range(acount):
                ns = _u32(data, a)
                nm = _u32(data, a + 4)
                raw = _u32(data, a + 8)
                typ = data[a + 15]
                dat = _u32(data, a + 16)
                attrs.append((ns, nm, nm < len(map_rids), raw, typ, dat))
                a += 20
            nodes.append(("elem", name, attrs))
        elif t == 0x0103:
            nodes.append(("end", _u32(data, off + 16), _u32(data, off + 20)))
        elif t == 0x0003 or t == 0x0001:
            pass  # outer XML header / string pool chunk (pool parsed above loop)
        else:
            raise ValueError("unexpected chunk type 0x%04x" % t)
        off += size
    return strings, map_rids, nodes


def _attr_key(strings, map_rids, ns, nm, is_map):
    """Human-readable attribute identity for semantic comparison."""
    rid = map_rids[nm] if is_map else None
    nm_s = None if rid is not None else (strings[nm] if nm != NO_ENTRY else None)
    return rid, nm_s


def _drop_attr(strings, map_rids, attr):
    ns, nm, is_map, _raw, _typ, _dat = attr
    rid, nm_s = _attr_key(strings, map_rids, ns, nm, is_map)
    return (rid in DROP_RIDS) or (nm_s in DROP_NAMES)


def _semantic_dump(data):
    """Canonical dump of the tree with informational attributes removed."""
    strings, map_rids, nodes = parse(data)
    out = []

    def S(v):
        return None if v == NO_ENTRY or v >= len(strings) else strings[v]

    for nd in nodes:
        if nd[0] == "ns":
            out.append(("ns", S(nd[2]), S(nd[3])))
        elif nd[0] == "elem":
            ats = []
            for attr in nd[2]:
                if _drop_attr(strings, map_rids, attr):
                    continue
                ns, nm, is_map, raw, typ, dat = attr
                rid, nm_s = _attr_key(strings, map_rids, ns, nm, is_map)
                key = ("map", rid) if rid is not None else ("name", nm_s)
                val = dat if typ != TYPE_STRING else S(dat)
                ats.append((S(ns), key, S(raw), typ, val))
            out.append(("elem", S(nd[1]), tuple(sorted(ats, key=repr))))
        else:
            out.append(("end", S(nd[2])))
    return tuple(out)


def rewrite(strings, map_rids, nodes):
    """Rebuild pool/map/nodes, dropping informational attributes.

    The XML namespace nodes and the attributes' namespace references are kept:
    dropping them looks like ~48 free bytes (the 'android' prefix and the
    schema URI leave the pool too) but Android's AXML parser then rejects the
    APK with "Corrupt XML binary file" -- measured on Android 17.
    """
    keep = []          # (rid, name) for the resource map, in original order
    old_to_new = {}
    pos = 0
    for i, rid in enumerate(map_rids):
        if rid in DROP_RIDS:
            continue
        old_to_new[i] = pos
        keep.append((rid, strings[i]))
        pos += 1

    refs = []

    def addref(v):
        if v != NO_ENTRY and v < len(strings):
            refs.append(v)

    new_nodes = []
    for nd in nodes:
        if nd[0] == "ns":
            _k, t, p, u = nd
            addref(p)
            addref(u)
            new_nodes.append(nd)
        elif nd[0] == "elem":
            _k, name, attrs = nd
            addref(name)
            kept = []
            for attr in attrs:
                if _drop_attr(strings, map_rids, attr):
                    continue
                ns, nm, is_map, raw, typ, dat = attr
                if is_map:
                    nm2 = old_to_new[nm]
                else:
                    addref(nm)
                    nm2 = nm
                addref(ns)
                addref(raw)
                if typ == TYPE_STRING:
                    addref(dat)
                kept.append((ns, nm2, is_map, raw, typ, dat))
            new_nodes.append(("elem", name, kept))
        else:
            _k, nns, name = nd
            addref(nns)
            addref(name)
            new_nodes.append(nd)

    # pool: map-name strings first (index == map index), then referenced
    # strings in first-reference order; identical strings share one entry.
    pool = []
    seen = {}
    for _rid, nm in keep:
        seen[nm] = len(pool)
        pool.append(nm)
    for r in refs:
        s = strings[r]
        if s not in seen:
            seen[s] = len(pool)
            pool.append(s)

    def remap(v):
        return NO_ENTRY if v == NO_ENTRY else seen[strings[v]]

    out_nodes = []
    for nd in new_nodes:
        if nd[0] == "ns":
            _k, t, p, u = nd
            out_nodes.append(("ns", t, remap(p), remap(u)))
        elif nd[0] == "elem":
            _k, name, attrs = nd
            a2 = [(remap(ns), nm if is_map else remap(nm), is_map, remap(raw),
                   typ, remap(dat) if typ == TYPE_STRING else dat)
                  for (ns, nm, is_map, raw, typ, dat) in attrs]
            out_nodes.append(("elem", remap(name), a2))
        else:
            _k, nns, name = nd
            out_nodes.append(("end", remap(nns), remap(name)))
    return pool, [r for r, _ in keep], out_nodes


def _encode_len(n):
    if n < 0x80:
        return bytes([n])
    return bytes([0x80 | (n >> 8), n & 0xFF])


def serialize(pool, map_rids, nodes):
    """Serialize pool (UTF-8 by default), resource map and node chunks."""
    out = bytearray()
    out += struct.pack("<HHI", 0x0003, 8, 0)  # XML header; size patched below

    # ---- string pool chunk ----
    count = len(pool)
    flags = UTF8_FLAG if UTF8_POOL else 0
    sp = len(out)
    out += struct.pack("<HHIIIIII", 0x0001, 28, 0, count, 0, flags,
                       28 + 4 * count, 0)
    out += b"\0" * (4 * count)
    blob = bytearray()
    offs = []
    for s in pool:
        offs.append(len(blob))
        if UTF8_POOL:
            u8 = s.encode("utf-8")
            u16len = len(s.encode("utf-16-le")) // 2
            blob += _encode_len(u16len)
            blob += _encode_len(len(u8))
            blob += u8
            blob += b"\0"
        else:
            blob += struct.pack("<H", len(s))
            blob += s.encode("utf-16-le")
            blob += b"\0\0"
    for i, o in enumerate(offs):
        struct.pack_into("<I", out, sp + 28 + 4 * i, o)
    out += blob
    struct.pack_into("<I", out, sp + 4, len(out) - sp)

    # ---- resource map ----
    if map_rids:
        out += struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(map_rids))
        for r in map_rids:
            out += struct.pack("<I", r)

    # ---- XML node chunks ----
    for nd in nodes:
        if nd[0] == "ns":
            _k, t, p, u = nd
            out += struct.pack("<HHIII", t, 16, 24, NO_ENTRY, 0xFFFFFFFF)
            out += struct.pack("<II", p, u)
        elif nd[0] == "elem":
            _k, name, attrs = nd
            n = len(attrs)
            out += struct.pack("<HHIII", 0x0102, 16, 36 + 20 * n,
                               NO_ENTRY, 0xFFFFFFFF)
            out += struct.pack("<II", NO_ENTRY, name)
            out += struct.pack("<HHHHHH", 0x14, 0x14, n, 0, 0, 0)
            for (ns, nm, _is_map, raw, typ, dat) in attrs:
                out += struct.pack("<III", ns, nm, raw)
                out += struct.pack("<HBB", 8, 0, typ)
                out += struct.pack("<I", dat)
        else:
            _k, nns, name = nd
            out += struct.pack("<HHIII", 0x0103, 16, 24, NO_ENTRY, 0xFFFFFFFF)
            out += struct.pack("<II", nns, name)
    struct.pack_into("<I", out, 4, len(out))
    return bytes(out)


def golf_manifest(data):
    """Return a smaller, semantically identical manifest (or the input).

    Never raises and never returns malformed output: anything unexpected
    (parse failure, chunk types we don't model, rewrite/verify mismatch)
    falls back to the original bytes.
    """
    try:
        strings, map_rids, nodes = parse(data)
        pool, rids, out_nodes = rewrite(strings, map_rids, nodes)
        out = serialize(pool, rids, out_nodes)
        if _semantic_dump(data) != _semantic_dump(out):
            raise ValueError("semantic dump mismatch after rewrite")
        return out
    except (ValueError, IndexError, struct.error, UnicodeDecodeError):
        return data
