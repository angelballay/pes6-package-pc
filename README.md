# pes6-package-pc

El índice firmado de los mods de PES 6 PC de PityCharly (PES6 HD Text, PES6 Translations y, más adelante,
pes6xlife_mods), y la herramienta con la que se publican. Así los mods se actualizan solos **sin que nadie pueda hacer
pasar otro archivo por uno de estos**: los programas traen las claves públicas adentro y no instalan ni avisan nada que
no esté firmado.

## Cómo funciona

- **El índice** (`index/index.json` + `index.json.minisig`) dice la última versión de cada paquete y dónde está, con un
  número que solo sube y un vencimiento (90 días).
- **Cada paquete** (un zip) está en el release de su propio repo (`pes6-hd-text`, `pes6xlife-translations`), con su
  **manifiesto firmado**: qué archivos trae, con su tamaño y su SHA-256. El manifiesto va también dentro del zip.
- Las firmas son de [minisign](https://jedisct1.github.io/minisign/) (Ed25519). Las claves públicas están en `keys/`.
- Este repo es **solo texto**: nunca guarda los zips, las DLL ni los ejecutables.

## Comprobar un paquete a mano

Con minisign y la clave pública de uso de `keys/` (ejemplo con HD Text 1.0.3):

```
minisign -Vm hdtext-1.0.3.manifest.json -p keys\k1.pub
certutil -hashfile PES6_HD_Text_v1.0.3.zip SHA256
```

El SHA-256 del zip tiene que ser el que dice `index/index.json` para ese paquete (`archive.sha256`), y el de cada
archivo, el que dice el manifiesto.

## Qué hay

| Carpeta | Qué es |
|---|---|
| `index/` | el índice firmado que leen los jugadores |
| `manifests/` | copia de cada manifiesto publicado (registro) |
| `keys/` | claves públicas y su rol (`keys.json`) |
| `packages/` | recetas de los paquetes (`packages/README.md`) |
| `tool/` | `pes6pkg`, la herramienta (Python 3.11+, solo biblioteca estándar) |
| `client/` | el verificador C++ común que usan los mods (`client/README.md`) |
| `docs/` | [receta para publicar](docs/RECETA.md) |

## Pruebas

```
python -I tool\tests\test_pes6pkg.py         (la herramienta)
client\build_tests.cmd                        (el verificador C++, con VS 2019)
```

La CI (`.github/workflows/check.yml`) corre las dos, comprueba la firma del índice y que no entre ningún binario. Todos
los días, `vencimiento.yml` avisa si el índice está por vencer.

## Seguridad

Ver [SECURITY.md](SECURITY.md).
