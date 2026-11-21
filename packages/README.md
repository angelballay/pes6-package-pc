# Recetas de paquetes (`pes6pkg-recipe/1`)

`pes6pkg build <paquete> <versión> --from <carpeta>` lee `<paquete>.json`: primero en `--recipes <carpeta>`, después
en `./packages/` (la carpeta donde lo corrés, por ejemplo `pes6xlife-translations`) y por último en `packages/` de este
repo. Acá está la de HD Text; las de traducciones viven en `pes6xlife-translations/packages/`.

```json
{
  "recipe": "pes6pkg-recipe/1",
  "package": "translation-ru",
  "name": "Русский",
  "release": { "repo": "angelballay/pes6xlife-translations", "tag": "ru-v{version}",
               "archive": "PES6_Translation_ru_v{version}.zip" },
  "requires": [ { "package": "hdtext", "min": "1.0.2" }, { "package": "translations", "min": "1.0" } ],
  "bundles": [ "translations" ],
  "files": [
    { "path": "dat/ru_text.afs", "install": true },
    { "path": "Docs/translation-ru/README.txt", "install": false },
    { "path": "Docs/translation-ru/LEEME.txt", "install": false }
  ]
}
```

| Campo | Qué es |
|---|---|
| `recipe` | `pes6pkg-recipe/1` (se acepta `pes6pkg-recipe-draft/1` con un aviso) |
| `package`, `name` | id del paquete (FMT-7) y nombre para mostrar; van al manifiesto |
| `release.repo`, `release.tag`, `release.archive` | dónde se publica y cómo se llaman el tag y el zip; `{version}` es la versión de `build` |
| `requires` | `{package, min}`; va al manifiesto (`build --requires paquete=versión` lo reemplaza) |
| `bundles` | opcional: paquetes ya armados que van **adentro** de este zip, tal cual (ver abajo) |
| `files[].path` | un archivo: ruta dentro del zip y, con `install: true`, donde se instala (relativa a la carpeta del juego) |
| `files[].glob` (+ `min`) | en lugar de `path`: varios archivos de una carpeta (`*` dentro del nombre), al menos `min` |
| `files[].install` | `false` para lo que es solo para quien instala a mano (README, LEEME): en la raíz del zip o en `Docs/<paquete>/` (ver abajo) |
| `files[].mode` | opcional: `replace` (por defecto) o `if-absent` (configuraciones por defecto que edita el usuario) |
| `files[].pe_version` | `true` en cada `.dll`/`.exe`: su `FileVersion` y `ProductVersion` tienen que ser la versión del paquete (PUB-4) |
| `files[].embeds_keys` | `true` en lo que verifica firmas (la DLL y `hdtext.exe` de HD Text): tiene que traer las claves de `keys/` y ninguna de prueba (KEY-8) |
| `files[].from` | una nota para quien arma la carpeta de `--from`; no va al manifiesto |

Cada paquete solo puede instalar en sus rutas permitidas (design §5.5): `build` se niega si una receta pide otra cosa.
`pes6pkg` agrega solo el manifiesto firmado en `Kitserver/pes6pkg/installed/<paquete>.json` (+ `.json.minisig`).

## Documentos: en la raíz o en `Docs/<paquete>/`

Un documento (`install: false`) va en la raíz del zip (`README.txt`) o en **`Docs/<id del paquete>/<nombre>`**
(`Docs/translations/README.txt`, `Docs/translation-pt-br/LEEME.txt`). En `Docs/` va un solo nivel, y cada paquete
escribe solo en su carpeta: los verificadores (Python y C++) rechazan `Docs/translations/…` en el manifiesto de
`translation-ru`. El nombre lleva letras, números, `.`, `-`, `_` y espacio, y termina en `.txt` o `.md`. Los paquetes
que van juntos en un zip (abajo) usan `Docs/<paquete>/`, así sus README no chocan.

## Un paquete adentro de otro (`bundles`, `--bundle`)

Un zip de idioma lleva adentro `translations` (la DLL): el jugador baja un solo archivo, y el instalador pone cada
paquete en su propia transacción. `pes6pkg build translation-ru 1.0 --from … --bundle out\translations\1.0` (o
`"bundles": ["translations"]` en la receta, que toma la versión más nueva armada en `out\translations\`):

- copia **tal cual** todas las entradas del zip de `translations`: su manifiesto, su firma (la de su release) y sus
  archivos. No lo vuelve a firmar;
- se niega si un nombre está en los dos paquetes, si el idioma no pide ese paquete en `requires` o si la versión
  incluida es más vieja que la que pide;
- el índice apunta al zip combinado (su tamaño y su SHA-256). `release` e `index add` se niegan si la `translations` que
  va adentro no está publicada, o es distinta de la publicada.
