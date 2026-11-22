#!/usr/bin/env python3
"""ed25519.py — pure-Python Ed25519 (RFC 8032), standard library only.

Implements the EdDSA signing and verification algorithms specified in
RFC 8032 sections 5.1.6 (signing) and 5.1.7 (verification), with the
curve arithmetic of section 5.1.5. Verified against the RFC 8032
section 7.1 test vectors (TEST 1, TEST 2, TEST 3) — see
scripts/ed25519_selftest.py, which prints the vector comparison.

LAB ONLY. No live key material: keys used by callers are freshly
generated test keys.
"""
import hashlib

B_BITS = 256
Q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
# d = -121665 / 121666 (mod q)
D = -121665 * pow(121666, Q - 2, Q) % Q
# sqrt(-1) mod q
I = pow(2, (Q - 1) // 4, Q)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _hint(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little")


def _inv(x: int) -> int:
    return pow(x, Q - 2, Q)


def _xrecover(y: int) -> int:
    """Recover the x-coordinate for a given y on the Edwards curve."""
    xx = (y * y - 1) * _inv(D * y * y + 1) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = (x * I) % Q
    if x % 2 != 0:
        x = Q - x
    return x


# Base point B = (Bx, By), By = 4/5.
_BY = 4 * _inv(5) % Q
_BX = _xrecover(_BY)
BASE_POINT = (_BX % Q, _BY % Q)


def _edwards(p, q):
    """Edwards-curve point addition (twisted curve a = -1).

    x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
    y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
    Verified against the extended-coordinate formulas in RFC 8032
    Appendix A (EFD, a = -1 propagated): expanding E, F, G, H there
    gives exactly these affine formulas.
    """
    x1, y1 = p
    x2, y2 = q
    t = D * x1 * x2 * y1 * y2 % Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + t) % Q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - t) % Q
    return (x3, y3)


def _scalarmult(point, e: int):
    """Scalar multiplication by double-and-add (recursive, RFC style)."""
    if e == 0:
        return (0, 1)
    q = _scalarmult(point, e // 2)
    q = _edwards(q, q)
    if e & 1:
        q = _edwards(q, point)
    return q


def _encode_int(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encode_point(point) -> bytes:
    x, y = point
    bits = (y & ((1 << 255) - 1)) | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _decode_int(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _decode_point(data: bytes):
    y = _decode_int(data) & ((1 << 255) - 1)
    sign = (_decode_int(data) >> 255) & 1
    x = _xrecover(y)
    if x & 1 != sign:
        x = Q - x
    point = (x, y)
    if not _on_curve(point):
        raise ValueError("decoded point is not on the curve")
    return point


def _on_curve(point) -> bool:
    x, y = point
    return (-x * x + y * y - 1 - D * x * x * y * y) % Q == 0


def _clamp(h: bytes) -> int:
    """RFC 8032 section 5.1.5 clamping of the hashed secret key."""
    bits = bytearray(h[:32])
    bits[0] &= 248
    bits[31] &= 127
    bits[31] |= 64
    return int.from_bytes(bytes(bits), "little")


def public_key(secret_key: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte secret key."""
    if len(secret_key) != 32:
        raise ValueError("secret key must be 32 bytes")
    a = _clamp(_sha512(secret_key))
    return _encode_point(_scalarmult(BASE_POINT, a))


def sign(message: bytes, secret_key: bytes, public_key_bytes: bytes) -> bytes:
    """RFC 8032 section 5.1.6 signing. Returns a 64-byte signature."""
    if len(secret_key) != 32:
        raise ValueError("secret key must be 32 bytes")
    h = _sha512(secret_key)
    a = _clamp(h)
    r = _hint(h[32:] + message)
    big_r = _scalarmult(BASE_POINT, r)
    encoded_r = _encode_point(big_r)
    s = (r + _hint(encoded_r + public_key_bytes + message) * a) % L
    return encoded_r + _encode_int(s)


def verify(signature: bytes, message: bytes, public_key_bytes: bytes) -> bool:
    """RFC 8032 section 5.1.7 verification. Returns True iff valid."""
    if len(signature) != 64 or len(public_key_bytes) != 32:
        return False
    try:
        big_r = _decode_point(signature[:32])
        big_a = _decode_point(public_key_bytes)
    except ValueError:
        return False
    s = _decode_int(signature[32:])
    if s >= L:
        return False
    h = _hint(signature[:32] + public_key_bytes + message)
    return _scalarmult(BASE_POINT, s) == _edwards(
        big_r, _scalarmult(big_a, h)
    )
