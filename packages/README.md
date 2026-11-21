# Recetas de paquetes (`pes6pkg-recipe/1`)

`pes6pkg build <paquete> <versión> --from <carpeta>` lee `<paquete>.json`: primero en `--recipes <carpeta>`, después
en `./packages/` (la carpeta donde lo corrés, por ejemplo `pes6xlife-translations`) y por último en `packages/` de este
repo. Acá está la de HD Text; las de traducciones viven en `pes6xlife-translations/packages/`.

```json
{
  "recipe": "pes6pkg-recipe/1",
  "package": "translations",
  "name": "PES6 Translations",
  "release": { "repo": "angelballay/pes6xlife-translations", "tag": "dll-v{version}",
               "archive": "PES6_Translations_DLL_v{version}.zip" },
  "requires": [ { "package": "hdtext", "min": "1.0.2" } ],
  "files": [
    { "path": "Kitserver/translations.dll", "install": true, "pe_version": true, "from": "build.ps1 de pes6xlife_mods" },
    { "path": "README.txt", "install": false }
  ]
}
```

| Campo | Qué es |
|---|---|
| `recipe` | `pes6pkg-recipe/1` (se acepta `pes6pkg-recipe-draft/1` con un aviso) |
| `package`, `name` | id del paquete (FMT-7) y nombre para mostrar; van al manifiesto |
| `release.repo`, `release.tag`, `release.archive` | dónde se publica y cómo se llaman el tag y el zip; `{version}` es la versión de `build` |
| `requires` | `{package, min}`; va al manifiesto (`build --requires paquete=versión` lo reemplaza) |
| `files[].path` | un archivo: ruta dentro del zip y, con `install: true`, donde se instala (relativa a la carpeta del juego) |
| `files[].glob` (+ `min`) | en lugar de `path`: varios archivos de una carpeta (`*` dentro del nombre), al menos `min` |
| `files[].install` | `false` para lo que es solo para quien instala a mano (README, LEEME), en la raíz del zip |
| `files[].mode` | opcional: `replace` (por defecto) o `if-absent` (configuraciones por defecto que edita el usuario) |
| `files[].pe_version` | `true` en cada `.dll`/`.exe`: su `FileVersion` y `ProductVersion` tienen que ser la versión del paquete (PUB-4) |
| `files[].embeds_keys` | `true` en lo que verifica firmas (la DLL y `hdtext.exe` de HD Text): tiene que traer las claves de `keys/` y ninguna de prueba (KEY-8) |
| `files[].from` | una nota para quien arma la carpeta de `--from`; no va al manifiesto |

Cada paquete solo puede instalar en sus rutas permitidas (design §5.5): `build` se niega si una receta pide otra cosa.
`pes6pkg` agrega solo el manifiesto firmado en `Kitserver/pes6pkg/installed/<paquete>.json` (+ `.json.minisig`).
