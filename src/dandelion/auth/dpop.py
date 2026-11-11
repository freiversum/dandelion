# SPDX-License-Identifier: GPL-3.0-or-later
"""DPoP (RFC 9449) mit ES256 ohne zusätzliche Abhängigkeit.

Das GNOME-Runtime bringt keine Kryptobibliothek für Python mit. Für den
Schlüssel, der nur ein Sitzungstoken bindet, genügt eine kleine ECDSA-Umsetzung
über P-256 (Python-Ganzzahlen, Zufallswert aus `secrets`). Die Tests prüfen sie
gegen eine unabhängige Implementierung, sofern `cryptography` installiert ist.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from typing import Any

# NIST P-256
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

_Point = tuple[int, int] | None


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _add(p: _Point, q: _Point) -> _Point:
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P


def _mul(k: int, p: _Point) -> _Point:
    result: _Point = None
    while k:
        if k & 1:
            result = _add(result, p)
        p = _add(p, p)
        k >>= 1
    return result


def _on_curve(p: tuple[int, int]) -> bool:
    x, y = p
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def _int_bytes(n: int) -> bytes:
    return n.to_bytes(32, "big")


class DpopKey:
    """Privater ES256-Schlüssel samt DPoP-Beweisen."""

    def __init__(self, d: int, public: tuple[int, int]) -> None:
        self.d = d
        self.x, self.y = public

    @classmethod
    def generate(cls) -> DpopKey:
        d = secrets.randbelow(_N - 1) + 1
        pub = _mul(d, _G)
        assert pub is not None
        return cls(d, pub)

    @classmethod
    def from_jwk(cls, jwk: dict[str, str]) -> DpopKey:
        d = int.from_bytes(b64url_decode(jwk["d"]), "big")
        pub = (int.from_bytes(b64url_decode(jwk["x"]), "big"),
               int.from_bytes(b64url_decode(jwk["y"]), "big"))
        if not 0 < d < _N or not _on_curve(pub):
            raise ValueError("invalid key")
        return cls(d, pub)

    def to_jwk(self, private: bool = False) -> dict[str, str]:
        jwk = {"kty": "EC", "crv": "P-256", "x": b64url(_int_bytes(self.x)),
               "y": b64url(_int_bytes(self.y))}
        if private:
            jwk["d"] = b64url(_int_bytes(self.d))
        return jwk

    def sign(self, message: bytes) -> bytes:
        """ES256-Signatur (r || s, je 32 Bytes)."""
        z = int.from_bytes(hashlib.sha256(message).digest(), "big")
        while True:
            k = secrets.randbelow(_N - 1) + 1
            point = _mul(k, _G)
            assert point is not None
            r = point[0] % _N
            if r == 0:
                continue
            s = pow(k, -1, _N) * (z + r * self.d) % _N
            if s:
                return _int_bytes(r) + _int_bytes(s)

    def proof(self, method: str, url: str, *, nonce: str | None = None,
              access_token: str | None = None, now: float | None = None) -> str:
        """DPoP-Beweis für genau eine Anfrage (`htu` ohne Query und Fragment)."""
        parts = urllib.parse.urlsplit(url)
        htu = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        claims: dict[str, Any] = {"jti": secrets.token_urlsafe(16), "htm": method.upper(),
                                  "htu": htu, "iat": int(now if now is not None else time.time())}
        if nonce:
            claims["nonce"] = nonce
        if access_token:
            claims["ath"] = b64url(hashlib.sha256(access_token.encode("ascii")).digest())
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self.to_jwk()}
        signing = (b64url(json.dumps(header, separators=(",", ":")).encode())
                   + "." + b64url(json.dumps(claims, separators=(",", ":")).encode()))
        return signing + "." + b64url(self.sign(signing.encode("ascii")))


def verify(jwk: dict[str, str], message: bytes, signature: bytes) -> bool:
    """ES256-Prüfung (für Tests und Selbsttest)."""
    if len(signature) != 64:
        return False
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (0 < r < _N and 0 < s < _N):
        return False
    pub = (int.from_bytes(b64url_decode(jwk["x"]), "big"),
           int.from_bytes(b64url_decode(jwk["y"]), "big"))
    if not _on_curve(pub):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, _N)
    point = _add(_mul(z * w % _N, _G), _mul(r * w % _N, pub))
    return point is not None and point[0] % _N == r
