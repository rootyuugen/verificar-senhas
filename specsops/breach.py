"""Cruzamento da senha com hashes vazados/conhecidos.

- Have I Been Pwned (Pwned Passwords) via k-anonimato: só os 5 primeiros
  caracteres do SHA-1 saem da máquina; a senha e o hash completo nunca.
- Arquivos locais de hashes (um por linha, opcionalmente ``HASH:contagem``)
  em MD5, SHA-1, SHA-256, SHA-512 ou NTLM.
"""

from __future__ import annotations

import hashlib
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "specsops-password-checker"


def _md4(data: bytes) -> bytes:
    """MD4 puro (RFC 1320) — o OpenSSL 3 frequentemente não expõe MD4."""
    def f(x, y, z): return (x & y) | (~x & z)
    def g(x, y, z): return (x & y) | (x & z) | (y & z)
    def h(x, y, z): return x ^ y ^ z
    def rotl(v, s): return ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF

    msg = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + (len(data) * 8).to_bytes(8, "little")
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + i:off + i + 4], "little") for i in range(0, 64, 4)]
        aa, bb, cc, dd = a, b, c, d
        for i in range(16):
            k, s = i, (3, 7, 11, 19)[i % 4]
            a, b, c, d = d, rotl((a + f(b, c, d) + x[k]) & 0xFFFFFFFF, s), b, c
        for i in range(16):
            k, s = (i % 4) * 4 + i // 4, (3, 5, 9, 13)[i % 4]
            a, b, c, d = d, rotl((a + g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s), b, c
        for i in range(16):
            k, s = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[i], (3, 9, 11, 15)[i % 4]
            a, b, c, d = d, rotl((a + h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s), b, c
        a, b, c, d = [(v + w) & 0xFFFFFFFF for v, w in zip((a, b, c, d), (aa, bb, cc, dd))]
    return b"".join(v.to_bytes(4, "little") for v in (a, b, c, d))


def ntlm(password: str) -> str:
    return _md4(password.encode("utf-16-le")).hex()


def hashes_for(password: str) -> dict[str, str]:
    raw = password.encode("utf-8")
    return {
        "md5": hashlib.md5(raw).hexdigest(),
        "sha1": hashlib.sha1(raw).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sha512": hashlib.sha512(raw).hexdigest(),
        "ntlm": ntlm(password),
    }


@dataclass
class BreachHit:
    source: str
    algorithm: str
    count: int | None = None


def _http_get(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Add-Padding": "true"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def check_hibp(password: str, timeout: float = 10.0,
               fetch: Callable[[str, float], str] = _http_get) -> BreachHit | None:
    """Consulta o Pwned Passwords. Retorna o hit (com contagem) ou None."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    body = fetch(HIBP_RANGE_URL.format(prefix=prefix), timeout)
    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix:
            n = int(count or 0)
            if n > 0:  # linhas de padding vêm com contagem 0
                return BreachHit("haveibeenpwned", "sha1", n)
    return None


def check_hash_lines(password: str, lines: Iterable[str], source: str) -> BreachHit | None:
    """Procura a senha em linhas ``HASH`` ou ``HASH:contagem`` (qualquer algoritmo suportado)."""
    by_hash = {v: k for k, v in hashes_for(password).items()}
    for line in lines:
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        value, _, count = entry.partition(":")
        algo = by_hash.get(value.lower())
        if algo:
            return BreachHit(source, algo, int(count) if count.strip().isdigit() else None)
    return None


def check_hash_file(password: str, path: str | Path) -> BreachHit | None:
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        return check_hash_lines(password, fh, str(path))
