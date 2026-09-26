# SpecSops — Verificador de Força de Senhas

Ferramenta de linha de comando (Python puro, sem dependências) que valida se uma
senha atende a critérios de complexidade e cruza a informação com hashes
conhecidos ou vazados.

## O que é verificado

**Critérios de complexidade** (configuráveis):

| Critério | Padrão |
|---|---|
| Comprimento mínimo | 12 |
| Minúscula, maiúscula, dígito, símbolo | obrigatórios |
| Caracteres idênticos consecutivos | no máximo 3 (`aaaa` reprova) |
| Sequências alfabéticas, numéricas e de teclado | no máximo 3 (`abcd`, `4321`, `qwer` reprovam) |
| Senhas comuns, incluindo variações leet (`P@ssw0rd`) | reprova |
| Palavras proibidas (nome, e-mail, empresa…) | via `--forbid` |
| Entropia estimada | no mínimo 60 bits |

**Vazamentos:**

- **Have I Been Pwned (Pwned Passwords)** usando *k-anonimato*: só os 5
  primeiros caracteres do SHA-1 da senha são enviados; a senha e o hash completo
  nunca saem da máquina. A requisição usa `Add-Padding` para dificultar análise
  do tamanho da resposta.
- **Arquivos locais de hashes** (`--hash-file`), um hash por linha, com
  contagem opcional (`HASH:contagem`). Algoritmos detectados automaticamente:
  MD5, SHA-1, SHA-256, SHA-512 e NTLM. Útil para dumps internos ou o arquivo
  offline do HIBP.

## Uso

```bash
python3 -m specsops                      # pede a senha sem ecoar no terminal
echo 'minha senha' | python3 -m specsops --stdin --json
python3 -m specsops --forbid tales --forbid empresa --hash-file vazados.txt
python3 -m specsops --offline --min-length 16 --no-symbol
```

Ou instale: `pip install .` e use o comando `specsops`.

### Códigos de saída

| Código | Significado |
|---|---|
| 0 | aprovada |
| 1 | reprovada nos critérios |
| 2 | encontrada em vazamento |
| 3 | erro (ex.: senha vazia) |

Falhas de rede na consulta ao HIBP não interrompem a validação: viram um aviso,
e a saída informa que nenhuma base foi consultada.

## Testes

```bash
python3 -m unittest -v
```
