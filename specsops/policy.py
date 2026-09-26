"""Critérios de complexidade e análise estrutural da senha."""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field
from importlib import resources

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
LEET_MAP = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
                          "0": "o", "$": "s", "5": "s", "7": "t"})


@dataclass(frozen=True)
class Policy:
    """Política de senha configurável."""

    min_length: int = 12
    require_lower: bool = True
    require_upper: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    max_repeat: int = 3          # máximo de caracteres idênticos consecutivos
    max_sequence: int = 3        # máximo de caracteres em sequência (abc, 123, qwe)
    min_entropy_bits: float = 60.0
    forbidden_words: tuple[str, ...] = ()


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


@dataclass
class PolicyResult:
    checks: list[Check] = field(default_factory=list)
    entropy_bits: float = 0.0

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)


def load_common_passwords() -> frozenset[str]:
    text = resources.files("specsops.data").joinpath("common_passwords.txt").read_text("utf-8")
    return frozenset(line.strip().lower() for line in text.splitlines() if line.strip())


def charset_size(password: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation or c == " " for c in password):
        size += 33
    if any(ord(c) > 127 for c in password):
        size += 100
    return size


def estimate_entropy(password: str) -> float:
    """Entropia estimada (bits), penalizando repetições e sequências."""
    if not password:
        return 0.0
    # Conta apenas caracteres "efetivos": repetições e sequências valem pouco.
    effective = 1.0
    for prev, cur in zip(password, password[1:]):
        if cur == prev or abs(ord(cur) - ord(prev)) == 1:
            effective += 0.25
        else:
            effective += 1.0
    return effective * math.log2(max(charset_size(password), 1))


def longest_repeat(password: str) -> int:
    best = run = 1 if password else 0
    for prev, cur in zip(password, password[1:]):
        run = run + 1 if cur == prev else 1
        best = max(best, run)
    return best


def longest_sequence(password: str) -> int:
    """Maior sequência alfabética/numérica ou de teclado (ascendente ou descendente)."""
    lowered = password.lower()
    best = 1 if password else 0
    sources = [string.ascii_lowercase, string.digits, *KEYBOARD_ROWS]
    sources += [s[::-1] for s in sources]
    for src in sources:
        run = 1
        for prev, cur in zip(lowered, lowered[1:]):
            i = src.find(prev)
            run = run + 1 if i != -1 and i + 1 < len(src) and src[i + 1] == cur else 1
            best = max(best, run)
    return best


def _normalize(password: str) -> str:
    return re.sub(r"[^a-z]", "", password.lower().translate(LEET_MAP))


def evaluate(password: str, policy: Policy | None = None,
             common: frozenset[str] | None = None) -> PolicyResult:
    policy = policy or Policy()
    common = load_common_passwords() if common is None else common
    result = PolicyResult(entropy_bits=estimate_entropy(password))
    add = result.checks.append

    add(Check("comprimento", len(password) >= policy.min_length,
              f"{len(password)} caracteres (mínimo {policy.min_length})"))
    if policy.require_lower:
        add(Check("minúscula", bool(re.search(r"[a-z]", password)), "ao menos uma letra minúscula"))
    if policy.require_upper:
        add(Check("maiúscula", bool(re.search(r"[A-Z]", password)), "ao menos uma letra maiúscula"))
    if policy.require_digit:
        add(Check("dígito", bool(re.search(r"\d", password)), "ao menos um dígito"))
    if policy.require_symbol:
        add(Check("símbolo", bool(re.search(r"[^A-Za-z0-9]", password)), "ao menos um símbolo"))

    rep = longest_repeat(password)
    add(Check("repetição", rep <= policy.max_repeat,
              f"maior repetição: {rep} (máximo {policy.max_repeat})"))
    seq = longest_sequence(password)
    add(Check("sequência", seq <= policy.max_sequence,
              f"maior sequência: {seq} (máximo {policy.max_sequence})"))

    normalized = _normalize(password)
    lowered = password.lower()
    is_common = lowered in common or (normalized and normalized in common) or any(
        len(w) >= 5 and w in lowered for w in common if w.isalpha())
    add(Check("dicionário", not is_common, "não baseada em senha comum (inclui variações leet)"))

    bad = [w for w in policy.forbidden_words if w and w.lower() in (lowered + " " + normalized)]
    add(Check("palavras proibidas", not bad,
              f"contém: {', '.join(bad)}" if bad else "sem dados pessoais/proibidos"))

    add(Check("entropia", result.entropy_bits >= policy.min_entropy_bits,
              f"{result.entropy_bits:.1f} bits (mínimo {policy.min_entropy_bits:.0f})"))
    return result
