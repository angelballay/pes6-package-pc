# Verificador común (`client/`)

C++14 + Monocypher 4.0.2, para Windows (Win32 o x64). Lo copian los clientes: la DLL y `hdtext.exe` de PES6 HD Text, y
después pes6xlife_mods. Hace todo lo de design §5 y §6: firmas minisign, JSON restringido, índice (serial que sube,
vencimiento, revocación de la clave de uso), manifiestos, rutas permitidas, zip estricto, descarga y estado local.

## Archivos

| Archivo | Qué es |
|---|---|
| `pes6pkg_client.h` | la API completa |
| `pes6pkg_core.cpp` | JSON, versiones, fechas, rutas, minisign, estado, índice, manifiesto (sin Windows) |
| `pes6pkg_zip.cpp` | zip estricto, deflate (estilo `puff.c`) y CRC-32 |
| `pes6pkg_win.cpp` | SHA-256 (CNG), descarga (WinHTTP), reloj, archivos atómicos, `%LOCALAPPDATA%\pes6pkg\state.json` |
| `pes6pkg_keys.h` | claves de producción; lo genera `pes6pkg keys export` (hasta la ceremonia, `#error`) |
| `vendor/monocypher-4.0.2/` | Monocypher sin cambios (`vendor/README.md`) |
| `tests/test_client.cpp` | pruebas: unidades y los vectores de `pes6pkg vectors` |

## Cómo se suma a un mod

1. Copiar `client/` a `vendor/pes6pkg/` del mod, con un `VERSION` que diga el commit de `pes6-package-pc` de donde sale.
2. Compilar `pes6pkg_core.cpp`, `pes6pkg_zip.cpp`, `pes6pkg_win.cpp`, `vendor/monocypher-4.0.2/monocypher.c` y
   `vendor/monocypher-4.0.2/optional/monocypher-ed25519.c`, con `/I<vendor/pes6pkg> /I<vendor/pes6pkg>/vendor/monocypher-4.0.2`.
   Con `cl` (HD Text): sumarlos a la línea de `build_release.cmd` y `build_cfgtool.cmd`.
3. Enlazar `winhttp.lib bcrypt.lib` (van por `#pragma comment`). En la DLL del juego, cargarlas diferidas:
   `/link /DELAYLOAD:winhttp.dll /DELAYLOAD:bcrypt.dll delayimp.lib` (HDU-4).
4. Incluir `pes6pkg_keys.h` (claves de producción) en el build público. Para desarrollar, `pes6pkg_test_keys.h`
   (`pes6pkg --test-keys keys export`), que nunca va en un build público (`pes6pkg build` lo rechaza, KEY-8).

## Uso típico

La DLL, en su hilo de consulta (HDU-1):

```cpp
#include "pes6pkg_keys.h"
pes6pkg::CheckConfig cfg;
cfg.keys = pes6pkg::PRODUCTION_KEYS;
cfg.key_count = pes6pkg::PRODUCTION_KEY_COUNT;
cfg.min_serial = pes6pkg::PRODUCTION_MIN_SERIAL;
cfg.http.user_agent = L"PES6-HD-Text/1.0.2";
pes6pkg::Index idx;
if (pes6pkg::fetch_index(cfg, idx) == pes6pkg::OK) {
    const pes6pkg::IndexEntry* e = idx.find("hdtext");
    pes6pkg::Version have, got;
    if (e && pes6pkg::parse_version(PES6_HD_TEXT_VERSION, have) && pes6pkg::parse_version(e->version, got) &&
        pes6pkg::compare_versions(got, have) > 0) { /* aviso de HDU-3 con e->version */ }
}
```

`hdtext.exe`, para instalar (design §5.2): `fetch_index`, después `http_get` del manifiesto (`check_bytes` contra
`e->manifest`, `check_manifest` con el paquete y la versión del índice y la instalada), `http_get` del zip
(`check_bytes` contra `e->archive`) y `check_zip` con `{"hdtext"}`: devuelve el contenido de cada archivo ya comprobado
para la transacción de design §9.3. Un zip de traducción bajado de la web: `check_zip` con
`{"translations", "translation-*"}` y las versiones instaladas, sin red.

## Pruebas

```
client\build_tests.cmd                      (VS 2019, x86: compila, genera los vectores y corre)
build\client-vs2019\test_client.exe build\vectors --red   (además, descarga real con WinHTTP)
```

Con CMake (VS 2026, como pes6xlife_mods):

```
cmake -S client -B build\client-vs2026 -G "Visual Studio 18 2026" -A Win32
cmake --build build\client-vs2026 --config Release
python -I tool\run.py --test-keys vectors --out build\vectors
build\client-vs2026\Release\test_client.exe build\vectors
```

Los vectores son los mismos que pasa el verificador de Python (`tool/tests`): las dos implementaciones tienen que dar el
mismo código de error en cada caso.
