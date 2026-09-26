"""Interface de linha de comando do SpecSops."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from dataclasses import asdict

from specsops import __version__
from specsops.breach import check_hash_file, check_hibp
from specsops.policy import Policy, evaluate

EXIT_OK, EXIT_WEAK, EXIT_BREACHED, EXIT_ERROR = 0, 1, 2, 3


def strength_label(bits: float) -> str:
    if bits < 28:
        return "muito fraca"
    if bits < 45:
        return "fraca"
    if bits < 60:
        return "razoável"
    if bits < 80:
        return "forte"
    return "muito forte"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="specsops",
        description="Valida a força de uma senha e cruza com hashes conhecidos/vazados.")
    p.add_argument("--stdin", action="store_true",
                   help="lê a senha da entrada padrão (evita histórico do shell)")
    p.add_argument("--min-length", type=int, default=12)
    p.add_argument("--min-entropy", type=float, default=60.0)
    p.add_argument("--no-upper", action="store_true", help="não exige maiúscula")
    p.add_argument("--no-lower", action="store_true", help="não exige minúscula")
    p.add_argument("--no-digit", action="store_true", help="não exige dígito")
    p.add_argument("--no-symbol", action="store_true", help="não exige símbolo")
    p.add_argument("--forbid", action="append", default=[], metavar="PALAVRA",
                   help="palavra proibida (nome, e-mail, empresa…); pode repetir")
    p.add_argument("--hash-file", action="append", default=[], metavar="ARQUIVO",
                   help="arquivo de hashes vazados (MD5/SHA-1/SHA-256/SHA-512/NTLM); pode repetir")
    p.add_argument("--offline", action="store_true", help="não consulta o Have I Been Pwned")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", action="store_true", help="saída em JSON")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def read_password(args: argparse.Namespace) -> str:
    if args.stdin:
        return sys.stdin.readline().rstrip("\r\n")
    return getpass.getpass("Senha: ")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    password = read_password(args)
    if not password:
        print("erro: senha vazia", file=sys.stderr)
        return EXIT_ERROR

    policy = Policy(
        min_length=args.min_length, min_entropy_bits=args.min_entropy,
        require_upper=not args.no_upper, require_lower=not args.no_lower,
        require_digit=not args.no_digit, require_symbol=not args.no_symbol,
        forbidden_words=tuple(args.forbid))
    result = evaluate(password, policy)

    hits, warnings, sources_checked = [], [], 0
    for path in args.hash_file:
        try:
            hit = check_hash_file(password, path)
        except OSError as exc:
            warnings.append(f"não foi possível ler {path}: {exc}")
            continue
        sources_checked += 1
        if hit:
            hits.append(hit)
    if not args.offline:
        try:
            hit = check_hibp(password, timeout=args.timeout)
        except Exception as exc:  # rede indisponível não deve derrubar a validação local
            warnings.append(f"consulta ao Have I Been Pwned falhou: {exc}")
        else:
            sources_checked += 1
            if hit:
                hits.append(hit)

    code = EXIT_BREACHED if hits else (EXIT_OK if result.passed else EXIT_WEAK)

    if args.json:
        print(json.dumps({
            "aprovada": code == EXIT_OK,
            "forca": strength_label(result.entropy_bits),
            "entropia_bits": round(result.entropy_bits, 1),
            "criterios": [asdict(c) for c in result.checks],
            "fontes_consultadas": sources_checked,
            "vazamentos": [asdict(h) for h in hits],
            "avisos": warnings,
        }, ensure_ascii=False, indent=2))
        return code

    print(f"\nForça estimada: {strength_label(result.entropy_bits)} "
          f"({result.entropy_bits:.1f} bits)\n")
    for c in result.checks:
        print(f"  [{'OK' if c.passed else 'FALHA'}] {c.name}: {c.detail}")
    print()
    if hits:
        for h in hits:
            extra = f" — vista {h.count:,} vezes".replace(",", ".") if h.count else ""
            print(f"  [VAZADA] encontrada em {h.source} ({h.algorithm}){extra}")
    elif sources_checked:
        print("  [OK] não encontrada nas bases de vazamento consultadas")
    for w in warnings:
        print(f"  [AVISO] {w}")
    print("\nResultado:", {EXIT_OK: "APROVADA", EXIT_WEAK: "REPROVADA (critérios)",
                           EXIT_BREACHED: "REPROVADA (vazada)"}[code])
    return code
