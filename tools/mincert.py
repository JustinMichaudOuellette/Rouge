#!/usr/bin/env python3
"""Build the smallest valid self-signed certificate for an APK signing key.

The certificate is the single largest fixed cost inside an APK v2 signing
block (266 B of the 568 B block with a stock BUILD cert), so it is worth
hand-rolling.  A stock certificate produced by `keytool`/Android Studio is
~700-900 B; `cryptography.CertificateBuilder` gets to ~270 B; this builder
gets to 233 B by emitting only what a parser actually needs:

  * **version 1** -- no [0] EXPLICIT version field (-5 B).  Legal: an X.509
    certificate with no extensions is allowed to be v1, and the cryptography
    library parses the result as `Version.v1`.
  * **no X.509 extensions** (a stock cert carries basicConstraints /
    keyUsage / subjectKeyIdentifier: several hundred bytes).
  * **empty issuer and subject** Distinguished Names (-24 B).  `30 00` is a
    syntactically valid RDNSequence; Android's v2 verifier only needs the
    certificate to parse and to carry the signing public key.  Pass
    `cn=b"R"` (or `--cert-dn`) to keep a one-character CommonName instead if
    a device ever objects.
  * **UTCTime validity** (13-byte times, -2 B): valid because the default
    notAfter stays inside the 1950-2049 UTCTime range.
  * **minimal serial** and **no optional fields**.
  * the ECDSA signature is re-rolled until it DER-encodes to the shortest
    possible SEQUENCE (70 B for P-256, sometimes 69), saving another ~1-2 B.

Note that APK certificate validity dates are never checked for APK Signature
Scheme v2 (no chain is built -- the certificate *is* the signing identity),
and that this module is the only place the certificate's shape is decided.

The certificate bytes are the app's signing identity: Android treats a
re-issued certificate as a different signer, so an existing install must be
uninstalled before an APK signed with a re-issued certificate can replace it.
release.py stores what build() returns in the PKCS12 keystore, so the identity
stays stable across builds once generated.
"""
import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding, PublicFormat, pkcs12)

# AlgorithmIdentifier for ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
ECDSA_WITH_SHA256 = bytes.fromhex("06082a8648ce3d040302")

# Fixed validity: deterministic, inside the UTCTime range (<= 2049), long
# enough for any realistic app lifetime.  Android does not check it for v2.
NOT_BEFORE = datetime.datetime(2020, 1, 1, 0, 0, 0,
                               tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2049, 12, 31, 23, 59, 59,
                              tzinfo=datetime.timezone.utc)

# A P-256 ECDSA signature needs 70 B as a DER SEQUENCE when neither r nor s
# gets a leading zero byte; more attempts only improve the odds of hitting it.
SIGN_TRIES = 200


def _tlv(tag, content):
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(b)]) + b + content


def _name(cn):
    """RDNSequence with a single CommonName, or an empty sequence."""
    if cn is None:
        return _tlv(0x30, b"")
    atv = _tlv(0x30, _tlv(0x06, bytes.fromhex("550403")) + _tlv(0x0C, cn))
    return _tlv(0x30, _tlv(0x31, atv))


def _utctime(dt):
    return _tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def _tbs(private_key, cn=None, not_before=NOT_BEFORE, not_after=NOT_AFTER):
    """The DER of the TBSCertificate this module would emit for the key."""
    if cn is not None and len(cn) > 1:
        raise ValueError("cn must be empty or a single byte (it costs bytes)")
    name = _name(cn)
    spki = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return _tlv(0x30, b"".join((
        _tlv(0x02, b"\x01"),                       # serialNumber = 1
        _tlv(0x30, ECDSA_WITH_SHA256),             # signature
        name,                                      # issuer
        _tlv(0x30, _utctime(not_before) + _utctime(not_after)),
        name,                                      # subject
        spki,
    )))


def build(private_key, cn=None, empty_dn=None,
          not_before=NOT_BEFORE, not_after=NOT_AFTER):
    """Return a minimal self-signed DER certificate for `private_key`.

    `cn` is a one-character (or shorter) CommonName; `None` means an empty
    Distinguished Name (which Android rejects -- see the module note).
    `empty_dn` is a deprecated alias for `cn=None`.
    """
    if empty_dn is not None:
        cn = None if empty_dn else (cn or b"R")
    tbs = _tbs(private_key, cn=cn, not_before=not_before, not_after=not_after)
    sig = private_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
    return _tlv(0x30, tbs + _tlv(0x30, ECDSA_WITH_SHA256) +
                _tlv(0x03, b"\x00" + sig))


def is_minimal(cert_der, private_key, cn=None, **kw):
    """True if `cert_der` already has the shape this module builds.

    The ECDSA signature differs on every issue (the nonce is random), so the
    comparison is on the TBSCertificate, which holds everything else: version,
    serial, algorithm, DN, validity and public key.  This is what makes
    re-issuing idempotent -- without it, `--recert` would mint a new signing
    identity on every run.
    """
    from cryptography import x509
    try:
        have = x509.load_der_x509_certificate(cert_der).tbs_certificate_bytes
    except Exception:
        return False
    return have == _tbs(private_key, cn=cn, **kw)


def build_best(private_key, cn=None, tries=SIGN_TRIES, **kw):
    """Like build(), re-rolling the ECDSA nonce for the shortest DER.

    A P-256 certificate bottoms out at 233 B with an empty DN and 257 B with a
    one-character CommonName (the two DNs are 2 B instead of 14 B each), so it
    stops as soon as it hits that rather than always running the full loop.
    """
    floor = 233 + (0 if cn is None else 24)
    best = None
    for _ in range(max(1, tries)):
        der = build(private_key, cn=cn, **kw)
        if best is None or len(der) < len(best):
            best = der
        if len(der) <= floor:
            break
    return best


def load(path, password):
    """Load (key, cert_der) from a PKCS12 keystore."""
    with open(path, "rb") as fh:
        key, cert, _extra = pkcs12.load_key_and_certificates(fh.read(),
                                                             password.encode())
    if key is None or cert is None:
        raise ValueError("keystore contains no private key + certificate")
    return key, cert.public_bytes(Encoding.DER)


def recert_keystore(path, password, cn=None, tries=SIGN_TRIES):
    """Re-issue the keystore's certificate as a minimal one.

    Returns (old_der, new_der), which are equal when the stored certificate
    already has the minimal shape -- re-issuing is idempotent, because
    otherwise every run would mint a new signing identity.  When it does
    change, the identity changes with it: Android treats a re-issued
    certificate as a different signer, so an installed copy has to be
    uninstalled before it can be replaced.
    """
    from cryptography import x509
    key, old_der = load(path, password)
    if is_minimal(old_der, key, cn=cn):
        return old_der, old_der
    new_der = build_best(key, cn=cn, tries=tries)
    cert = x509.load_der_x509_certificate(new_der)
    blob = pkcs12.serialize_key_and_certificates(
        b"release", key, cert, None,
        BestAvailableEncryption(password.encode()))
    with open(path, "wb") as fh:
        fh.write(blob)
    return old_der, new_der


if __name__ == "__main__":
    # Show what the three certificate profiles cost for a fresh P-256 key.
    k = ec.generate_private_key(ec.SECP256R1())
    for label, cn in (("empty DN", None), ("CN=R", b"R")):
        d = build_best(k, cn=cn)
        print(f"  minimal cert, {label:9s}: {len(d)} B DER")
    from cryptography.hazmat.primitives.asymmetric import rsa
    r = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    print(f"  (a stock RSA-2048 self-signed cert is ~900 B, "
          f"RSA-2048 SPKI alone is {len(r.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))} B)")
