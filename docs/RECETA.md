# Receta: publicar una versión firmada

Para quien publica. Todo se corre desde la raíz de
`pes6-package-pc` con `pes6pkg <comando>` (el `pes6pkg.cmd` de la raíz; necesita Python 3.11 o más nuevo).

`pes6pkg` nunca ve tus contraseñas: las pide minisign en la consola. Con cada comando, si el índice vence en 30 días o
menos, arriba de todo aparece un cartel con la fecha.

## Una sola vez

1. **minisign 0.12:** `winget install jedisct1.minisign`.
2. **Claves:** `pes6pkg keys new` y el PR de `keys/`. Las claves secretas nunca van a un repo.
3. **Repo en GitHub:** creá `angelballay/pes6-package-pc` **público**, subí `main` y protegé `main` (Settings → Branches
   → regla para `main`: "Require a pull request before merging"). Activá 2FA en tu cuenta si no lo tenés.
4. **Releases inmutables:** en `pes6-hd-text` y en `pes6xlife-translations`: Settings → General → Releases →
   "Enable release immutability".
5. **Avisos por correo:** en GitHub, Settings → Notifications → "Participating, @mentions and custom": tildá **Email**
   (viene así de fábrica). Ahí te llegan los avisos de vencimiento.
6. **Primer índice:** `pes6pkg renew --first` → te pide la contraseña de K1 → abre el PR → lo mergeás.

## Cada versión (ejemplo: HD Text 1.0.3)

1. **Compilar** como siempre (`build_release.cmd` y `build_cfgtool.cmd` con su ruta completa), con
   `client/pes6pkg_keys.h` de producción adentro.
2. **Armar la carpeta** con la estructura del zip: `Kitserver\pes6_hd_text.dll`, `Kitserver\hdtext.exe`,
   `Kitserver\GDB\fonts\HD_*.bin`, `Kitserver\GDB\fonts\FONT_LICENSES.txt`, `Kitserver\GDB\fonts\licenses\*.txt`,
   `README.txt`, `LEEME.txt`, `CHANGELOG.md`, `LICENSE.txt` (la receta es `packages/hdtext.json`).
3. **Armar y firmar:**

   ```
   pes6pkg build hdtext 1.0.3 --from D:\ruta\a\la\carpeta
   ```

   Comprueba que la DLL y el `.exe` digan 1.0.3.0 en su versión y que traigan las claves de `keys/`, arma el manifiesto,
   te pide la contraseña de K1, arma el zip y lo comprueba como un jugador. Queda todo en `out\hdtext\1.0.3\`.
4. **Comprobar:** `pes6pkg check out\hdtext\1.0.3` (también con `minisign -V`). Probá el zip en el lab.
5. **Publicar:**

   ```
   pes6pkg release hdtext 1.0.3 --notes-file notas-1.0.3.md
   ```

   Crea el release `v1.0.3` en `pes6-hd-text` como borrador con el zip, el manifiesto y su firma; baja lo subido y lo
   compara; te pregunta **"¿Publicar?"** (contestá `sí`); lo publica (queda inmutable); comprueba las direcciones
   públicas y `gh release verify-asset`; arma el índice nuevo (serial + 1, vence en 90 días), te pide la contraseña,
   y abre el PR en `pes6-package-pc`. Para ver qué haría sin tocar nada: `--dry-run`.
6. **Mergeá el PR.** Desde ahí los jugadores lo ven (el CDN de GitHub puede tardar unos 5 minutos).
7. **Comprobar lo publicado:** `pes6pkg verify-live --archives`.
8. **Calendario:** importá `out\recordatorios-indice-<serial>.ics` (ver abajo).

Traducciones: lo mismo con `pes6pkg build translations 1.0 --from …` (la DLL, tag `dll-v1.0`) y
`pes6pkg build translation-ru 1.0 --from …` (cada idioma, tag `ru-v1.0`), con las recetas de
`pes6xlife-translations\packages\` (`--recipes <esa carpeta>`). Después, `pes6pkg web <paquete> <versión>
--translations-repo <ruta>` escribe la descarga en los datos de la web.

## Renovar el índice (cada dos meses)

El índice vence a los **90 días** de firmarlo. Vencido, nada se rompe, pero los jugadores dejan de ver avisos.

```
pes6pkg renew          → contraseña de K1 → abre el PR
(mergeás el PR)
pes6pkg verify-live
```

y después importás el `.ics` nuevo. Cada `release` también renueva el índice.

## Dónde te llegan los avisos de vencimiento

| Cuándo | Por dónde |
|---|---|
| a los 30 días | **correo de GitHub** (`notifications@github.com`, al correo de tu cuenta) y la campanita de GitHub (y GitHub Mobile, si lo tenés): un issue **"El índice vence el <fecha>"** en `pes6-package-pc`, asignado a vos y con tu mención |
| a los 21, 14, 7, 3 y 1 días | otro correo: un comentario nuevo en ese issue, con tu mención |
| cada día después de vencido | un correo por día, hasta que mergees el índice renovado (el issue se cierra solo) |
| cada vez que usás `pes6pkg` (desde 30 días antes) | el cartel `ATENCIÓN: el índice vence el <fecha> (faltan N días). Corré: pes6pkg renew` |
| a los 30, 14, 7 y 1 días, a las 9 | **tu calendario**, si importaste `out\recordatorios-indice-<serial>.ics` (Google Calendar: Configuración → Importar y exportar → Importar) |

Ojo: GitHub apaga los workflows programados de un repo público tras 60 días sin actividad. El de avisos se vuelve a
habilitar solo en cada corrida, pero por las dudas `pes6pkg status` te dice si está apagado (en ese caso: Actions →
vencimiento → "Enable workflow"). El calendario no depende de GitHub.

## Si algo falla

| Mensaje | Qué hacer |
|---|---|
| `No encuentro minisign` / `no es el minisign 0.12 fijado` | `winget install jedisct1.minisign` (o reinstalalo) |
| `La clave … está dentro del repo` | movela a `%USERPROFILE%\.pes6pkg\` |
| `FileVersion 1.0.2.0, el paquete es 1.0.3 (PUB-4)` | subí la versión en los `.rc` y recompilá |
| `no trae la clave … de keys/` | recompilá con el `client/pes6pkg_keys.h` de producción |
| `trae una clave de PRUEBA` | se compiló con `pes6pkg_test_keys.h`: recompilá con el de producción |
| `El índice del repo tiene CR` | git lo convirtió: `.gitattributes` tiene que tener `index/** -text`; volvé a hacer checkout |
| `Ya existe el release` | la versión ya se publicó; las etiquetas inmutables no se reusan: subí la versión |
