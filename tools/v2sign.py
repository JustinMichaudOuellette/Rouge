#!/usr/bin/env python3
"""Minimal APK Signature Scheme v2 signer (pure Python, no padding).

Implements the exact v2 block serialization and CHUNKED_SHA256 content
digest from AOSP apksig (ApkSigningBlockUtils / V2SchemeSigner), so the
resulting signing block is byte-tight instead of apksigner's padded one:

  * v2 signer block:  signedData + signatures + publicKey (SubjectPublicKeyInfo)
  * block framing:    [u64 size][pairs][u64 size]["APK Sig Block 42"]
  * content digest:   CHUNKED_SHA256 over (bytes before signing block,
                      central directory, EOCD with cd-offset replaced by the
                      pre-block length)  -- exactly what apksig verifies.

Supported keys: EC P-256 (alg 0x0201, ECDSA w/ SHA-256), RSA <= 3072 bit
(alg 0x0101, PKCS#1 v1.5 w/ SHA-256). SHA-512 variants are not implemented.
"""
import hashlib
import struct

V2_BLOCK_ID = 0x7109871a
MAGIC = b"APK Sig Block 42"
CHUNK = 1024 * 1024


def _u32(n):
    return struct.pack("<I", n)


def _u64(n):
    return struct.pack("<Q", n)


def _lp_seq(byte_arrays):
    """encodeAsSequenceOfLengthPrefixedElements: u32-len-prefixed, no count."""
    out = b""
    for b in byte_arrays:
        out += _u32(len(b)) + b
    return out


def _lp_pairs(pairs):
    """(id, bytes) -> u32(8+len) u32(id) u32(len) bytes..., no count."""
    out = b""
    for pid, val in pairs:
        out += _u32(8 + len(val)) + _u32(pid) + _u32(len(val)) + val
    return out


def _chunked_sha256(*sections):
    """CHUNKED_SHA256 over ordered sections (bytes), split into 1 MiB chunks."""
    chunk_digests = []
    for section in sections:
        for i in range(0, len(section), CHUNK):
            chunk = section[i:i + CHUNK]
            chunk_digests.append(
                hashlib.sha256(b"\xa5" + _u32(len(chunk)) + chunk).digest())
    payload = b"\x5a" + _u32(len(chunk_digests)) + b"".join(chunk_digests)
    return hashlib.sha256(payload).digest()


def _parse_eocd(data):
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise ValueError("no End of Central Directory found")
    # eocd fields: sig(4) disk(2) cddisk(2) n(2) n(2) cd_size(4) cd_off(4) comment_len(2)
    cd_off = struct.unpack("<I", data[eocd + 16:eocd + 20])[0]
    comment_len = struct.unpack("<H", data[eocd + 20:eocd + 22])[0]
    if eocd + 22 + comment_len != len(data):
        raise ValueError("trailing data after EOCD")
    return eocd, cd_off


def _find_data_end(data, cd_off):
    """Walk ZIP local headers to find where entry data ends (= block start)."""
    pos = 0
    while data[pos:pos + 4] == b"PK\x03\x04":
        nl, el = struct.unpack("<HH", data[pos + 26:pos + 30])
        cs = struct.unpack("<I", data[pos + 18:pos + 22])[0]
        pos += 30 + nl + el + cs
    if pos != cd_off:
        # a signing block is already present (pos < cd_off)
        raise ValueError(f"expected central dir at {pos}, found {cd_off}; "
                         "input must be an unsigned APK")
    return pos


def pick_algorithm(key):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if key.curve.name != "secp256r1":
            raise ValueError("only EC P-256 supported (got %s)" % key.curve.name)
        return 0x0201  # ECDSA with SHA-256
    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size > 3072:
            raise ValueError("RSA > 3072 bit needs SHA-512 (not implemented)")
        return 0x0101  # RSASSA-PKCS1-v1_5 with SHA-256
    raise ValueError("unsupported key type %s" % type(key).__name__)


def v2_sign(apk_bytes, private_key, cert_der):
    """Return a v2-signed APK (byte-tight signing block, no padding)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)

    eocd_pos, cd_off = _parse_eocd(apk_bytes)
    if eocd_pos != len(apk_bytes) - 22:
        raise ValueError("EOCD must be the last 22 bytes (no comment)")
    # Unsigned APK: the central directory begins right after the entry data.
    # `cd_off` (from the EOCD) is the authoritative boundary.
    before_block = apk_bytes[:cd_off]
    central_dir = apk_bytes[cd_off:eocd_pos]
    eocd = apk_bytes[eocd_pos:eocd_pos + 22]

    # EOCD for digesting: central-directory offset replaced by the length of
    # the pre-block section (mirrors ApkSigningBlockUtils.verifyIntegrity).
    digest_eocd = bytearray(eocd)
    struct.pack_into("<I", digest_eocd, 16, len(before_block))

    alg_id = pick_algorithm(private_key)
    content_digest = _chunked_sha256(before_block, central_dir, bytes(digest_eocd))
    assert len(content_digest) == 32

    # ---- serialize v2 signer block (AOSP V2SchemeSigner) ----
    digests_field = _lp_pairs([(alg_id, content_digest)])
    certs_field = _lp_seq([cert_der])
    signed_data = _lp_seq([digests_field, certs_field, b"", b""])  # attrs empty

    if alg_id == 0x0201:
        signature = private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))
    else:
        signature = private_key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    sigs_field = _lp_pairs([(alg_id, signature)])
    pub_spki = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    signer_block = _lp_seq([signed_data, sigs_field, pub_spki])

    # value = lp_seq([ lp_seq([signer_block]) ])
    inner = _lp_seq([signer_block])
    value = _lp_seq([inner])

    # ---- wrap into APK Signing Block ----
    # Entry format: u64(length of id+value) + u32(id) + value
    pair = _u64(len(value) + 4) + _u32(V2_BLOCK_ID) + value
    size = len(pair) + 8 + 16          # excludes leading u64 only
    block = _u64(size) + pair + _u64(size) + MAGIC

    # ---- reassemble APK ----
    cd_start = len(before_block) + len(block)
    out = bytearray(before_block + block + central_dir)
    final_eocd = bytearray(eocd)
    struct.pack_into("<I", final_eocd, 16, cd_start)  # cd offset in final file
    out += final_eocd
    return bytes(out)


def sign_apk_file(input_path, output_path, private_key, cert_der):
    with open(input_path, "rb") as fh:
        apk = fh.read()
    signed = v2_sign(apk, private_key, cert_der)
    with open(output_path, "wb") as fh:
        fh.write(signed)
    return len(signed)
