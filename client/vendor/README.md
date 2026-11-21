# Bibliotecas copiadas tal cual

## Monocypher 4.0.2

- Origen: https://monocypher.org/download/monocypher-4.0.2.tar.gz (bajado el 2026-11-21).
- SHA-256 del tarball: `38d07179738c0c90677dba3ceb7a7b8496bcfea758ba1a53e803fed30ae0879c`.
- Licencia: BSD-2-Clause **o** CC0-1.0, a elección (`LICENCE.md`). Auditada por Cure53 (corregido en 3.1.2).
- Se copiaron sin cambios solo los archivos que usa el verificador (BLAKE2b-512 y Ed25519 con SHA-512):

| Archivo | SHA-256 |
|---|---|
| `monocypher.c` | `afe2b098c8569577a84488e0b98d276d1fba6506adea68bb9241a52111734c59` |
| `monocypher.h` | `f78bb31255cfb7beba66afd2137f5194c8a025cf40488b6cc1e295234d43f374` |
| `optional/monocypher-ed25519.c` | `7c9b16056cbd27521919e8a6f56a228808b9e718afc42e3d33f28c08e5abdee2` |
| `optional/monocypher-ed25519.h` | `bd546edcd468d64e28caa3dbf4b1d6bfad7435c0ce994723fd81aae26405121b` |
| `LICENCE.md` | `5f8360e4c06ddcc584bdb4b210c6af824c4bb301e6a9a521869b6d90795ca4b3` |

Tamaño medido en una DLL x86 `/O2 /MT /OPT:REF` con VS 2019: +48 KiB (design §13).
El aviso C4244 de `monocypher.c(881)` es del original; no se toca el código copiado.
