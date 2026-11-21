# Receta: publicar una versión firmada

Para quien publica. Todo se corre desde la raíz de `pes6-package-pc` con `pes6pkg <comando>` (el `pes6pkg.cmd` de la
raíz; necesita Python 3.11 o más nuevo, `gh` con la sesión iniciada y minisign 0.12).

`pes6pkg` nunca ve tus contraseñas: las pide minisign en la consola. Con cada comando, si el índice vence en 30 días o
menos, arriba de todo aparece un cartel con la fecha. Para ensayar sin tocar nada, ver [ENSAYO.md](ENSAYO.md).

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

## Cómo publica `pes6pkg`

**De punta a punta, `pes6pkg publish`**, para una tanda (uno o varios paquetes):

```
pes6pkg publish --lote dia.json --dry-run     (qué haría: no arma, no sube, no firma)
pes6pkg publish --lote dia.json
```

`dia.json` dice qué paquetes van y de qué carpeta se arma cada uno (las rutas relativas, relativas al archivo):

```json
{
  "recipes": "<pes6xlife-translations>/packages",
  "packages": [
    { "package": "translations", "version": "1.0", "from": "<carpeta de la DLL>" },
    { "package": "translation-ru", "version": "1.0", "from": "<carpeta de ru>" },
    { "package": "hdtext", "version": "1.0.2", "from": "<carpeta de HD Text>", "notes": "notas-1.0.2.md" }
  ]
}
```

(Con paquetes ya armados alcanza con `pes6pkg publish translations@1.0 translation-ru@1.0 …`.) `publish`:

1. ordena la tanda: `translations` primero (va adentro de cada idioma), los idiomas, y el resto (HD Text) al final;
2. arma lo que falta en `out\` (lo ya armado lo usa tal cual), cada idioma con la `translations` de la tanda adentro;
3. lee `main`, comprueba todo lo que se puede antes de tocar GitHub, y sube cada release como **borrador** comparado
   con lo armado;
4. muestra la lista entera y pregunta **una vez**: `¿Publicar los N? Escribí "sí"`;
5. firma el índice (antes de publicar nada), publica en orden, comprueba cada uno por sus direcciones públicas y abre
   **un** PR del índice.

Si se corta, **el mismo `publish` retoma**: lo armado, lo publicado y los borradores que coinciden se usan tal cual, y
lo que ya está en el índice de `main` se saltea.

Lo mismo, de a un paso, con dos comandos que también se pueden correr de nuevo sin riesgo:

- **`pes6pkg release <paquete> <versión> --no-index`** publica el release en el repo del mod y **no** toca el índice
  (no pide contraseña). Un release publicado que no está en el índice no lo ve ningún jugador.
- **`pes6pkg index add <paquete>@<versión> …`** comprueba que cada release esté publicado y que sus direcciones públicas
  bajen exactamente lo armado. Después firma **un** índice con todos (una contraseña) y abre **un** PR. El índice
  anterior lo lee siempre de `main` en GitHub (hace `git fetch`), no de tu carpeta. El PR lo arma en una carpeta
  temporal: tu checkout no cambia de rama ni se toca.

`pes6pkg release <paquete> <versión>` sin `--no-index` hace las dos cosas para un solo paquete. Pide la contraseña del
índice **antes** de publicar: si sale mal, queda solo un borrador.

Con `--dry-run`, cualquiera de los dos hace todas las lecturas: el estado de cada release, `main` y lo publicado. No sube,
no publica, no firma y no pide la contraseña. Muestra lo que haría y avisa si falta algo para el día real (la clave,
minisign).

Si algo se corta a mitad de camino, **corré el mismo comando otra vez**: retoma un borrador que coincide con lo armado,
rehace uno distinto o a medias (un borrador no es público), y completa el índice de un release ya publicado. Para
borrar un borrador: `pes6pkg release <paquete> <versión> --discard` (nunca borra uno publicado).

## Cada versión (ejemplo: HD Text 1.0.3)

1. **Compilar** como siempre (`build_release.cmd` y `build_cfgtool.cmd` con su ruta completa), con
   `client/pes6pkg_keys.h` de producción adentro.
2. **Armar la carpeta** con la estructura del zip: `Kitserver\pes6_hd_text.dll`, `Kitserver\hdtext.exe`,
   `Kitserver\GDB\fonts\HD_*.bin`, `Kitserver\GDB\fonts\FONT_LICENSES.txt`, `Kitserver\GDB\fonts\licenses\*.txt`,
   `README.txt`, `LEEME.txt`, `CHANGELOG.md`, `LICENSE.txt` (la receta es `packages/hdtext.json`).
3. **Armar y firmar:** `pes6pkg build hdtext 1.0.3 --from D:\ruta\a\la\carpeta`. Comprueba que la DLL y el `.exe`
   digan 1.0.3.0 en su versión y que traigan las claves de `keys/`, arma el manifiesto, te pide la contraseña de K1,
   arma el zip y lo comprueba como un jugador. Queda todo en `out\hdtext\1.0.3\`.
4. **Comprobar:** `pes6pkg check out\hdtext\1.0.3`. Probá el zip en el lab.
5. **Ver qué va a pasar:** `pes6pkg release hdtext 1.0.3 --dry-run`.
6. **Publicar:** `pes6pkg release hdtext 1.0.3 --notes-file notas-1.0.3.md`. Contestá `sí` a "¿Publicar?" y poné la
   contraseña cuando la pida minisign (después del "sí"). Abre el PR del índice.
7. **Mergeá el PR** cuando la CI esté en verde. Desde ahí los jugadores lo ven (el CDN de GitHub puede tardar unos 5
   minutos).
8. **Comprobar lo publicado:** `pes6pkg verify-live --archives`.
9. **Calendario:** importá `out\recordatorios-indice-<serial>.ics` (ver abajo).

Traducciones: lo mismo con las recetas de `pes6xlife-translations\packages\` (`--recipes <esa carpeta>`). La DLL es
el paquete `translations` (tag `dll-v1.0`). Cada idioma es `translation-<código>` (tag `ru-v1.0`) y lleva **adentro**
la `translations` ya armada y publicada: su receta dice `"bundles": ["translations"]`, y `build` toma la más nueva de
`out\translations\` (o la que le pases con `--bundle out\translations\<versión>`). Los README y LEEME de cada paquete van
en `Docs/<paquete>/` (packages/README.md). Después, `pes6pkg web <paquete> <versión> --translations-repo <ruta>`
escribe la descarga en los datos de la web.

## El día de la publicación: HD Text 1.0.2, `translations` 1.0 y siete idiomas

Hoy el índice está vacío (`packages: []`): hasta que se mergea un PR del índice, ningún jugador ve nada nuevo. Los
tags de los releases los crea GitHub **al publicar**, desde la rama principal de cada repo de releases. Por eso cada
`release/…` va a `main` **antes**. La web, en cambio, se publica **después**: lee las versiones de GitHub cuando se
arma.

### En orden

| # | Dónde | Qué | Por qué en este lugar |
|---|---|---|---|
| 1 | `pes6-package-pc` | `pes6pkg status`; HD Text 1.0.2 compilado con el `client/` actual (acepta `Docs/<paquete>/`) | un cliente viejo rechaza los zips de idioma |
| 2 | `pes6xlife-translations` | mergear a `main` las recetas (`Docs/<paquete>/`, `"bundles": ["translations"]`) y los README/LEEME | los tags `dll-v1.0` y `<código>-v1.0` salen de ese `main` |
| 3 | `pes6-hd-text` | mergear `release/1.0.2` → `main` (README y CHANGELOG del repo público) | el tag `v1.0.2` sale de ese `main` |
| 4 | `pes6_hd_text_code` | **no** mergear todavía `release/1.0.2` → `main`: ese merge publica la web | la web se arma con la última versión publicada en GitHub |
| 5 | `pes6-package-pc` | **primer tiempo**: `translations` sola (abajo) | prueba el camino entero con las claves reales, con el paquete más chico |
| 6 | `pes6-package-pc` | **segundo tiempo**: los siete idiomas y HD Text (abajo) | los idiomas llevan adentro la `translations` ya publicada |
| 7 | `pes6xlife-translations` | `pes6pkg web <paquete> <versión> --translations-repo <ruta>` de cada uno, y su PR | la descarga de cada página apunta al release publicado |
| 8 | `pes6_hd_text_code` | mergear `release/1.0.2` → `main` (publica la web). Si la web ya se había publicado, Actions → Sitio → **Run workflow** | ya están los releases y el índice: la web muestra 1.0.2 y los idiomas |

### Primer tiempo: `translations` 1.0

| Paso | Comando | Qué mirar |
|---|---|---|
| 1 | `pes6pkg publish --lote tiempo1.json --dry-run` (el lote con solo `translations`) | `(simulado) armaría translations@1.0 …`, o `ya armado` |
| 2 | `pes6pkg publish --lote tiempo1.json` | `Tanda, en este orden: translations@1.0.`, `main de angelballay/pes6-package-pc (…): índice 1`, `En GitHub: no existe todavía.`, `Borrador: lo subido coincide con lo armado.`, la lista `Se van a publicar …` → `sí` → `Publicado …`, `las direcciones públicas bajan lo mismo que se armó`, `gh release verify-asset: bien.` y `Índice 2 firmado … PR: …` |
| 3 | (en GitHub) la CI del PR en verde → **Merge** | los dos trabajos de `check` en verde |
| 4 | `pes6pkg verify-live --archives` | `Índice público 2 …` y `translations 1.0: manifiesto bien, zip bien` |

Aparece `AVISO: translations 1.0 pide hdtext 1.0.2 o más nueva…`: es lo esperado, HD Text entra en el segundo tiempo.
Si algo falla, **pará acá**. Un release publicado sin índice no lo ve nadie. Se corrige la herramienta y se sigue con el
mismo comando. En el peor caso la DLL pasa a 1.0.1, y los idiomas la llevan adentro.

### Segundo tiempo: los siete idiomas y HD Text

El lote `dia.json` con `translations`, los siete idiomas (`el`, `hr`, `id`, `pt-br`, `ru`, `sr` y `tr`) y `hdtext`.
`translations` ya está en el índice y se saltea; los idiomas la llevan adentro.

| Paso | Comando | Qué mirar |
|---|---|---|
| 1 | `pes6pkg publish --lote dia.json --dry-run` | `índice 2`, `translations 1.0 ya está en el índice 2: lo salteo.`, un `(simulado) armaría …` por cada paquete que falta armar |
| 2 | `pes6pkg publish --lote dia.json` | un `Armo …` por cada uno que faltaba, y la lista: cada idioma `(borrador listo, trae translations 1.0 adentro)` y `hdtext 1.0.2 … (borrador listo)` → `sí` → `Publicado …` uno por uno, HD Text último → `Índice 3 firmado … PR: …` |
| 3 | (en GitHub) la CI en verde → **Merge**, enseguida | entre el paso 2 y este, HD Text 1.0.2 se ve en GitHub, pero el actualizador y la pestaña Languages todavía no |
| 4 | `pes6pkg verify-live --archives` | `Índice público 3`, y los nueve paquetes con `manifiesto bien, zip bien`; cada idioma `(trae adentro translations 1.0)` |
| 5 | importar el `.ics` del índice 3, y seguir con los pasos 7 y 8 de la tabla de arriba | |

Con los comandos de a un paso es lo mismo: `pes6pkg build …` de cada paquete, `pes6pkg release <paquete> <versión>
--no-index` de cada uno (con un "sí" cada uno), y un `pes6pkg index add <paquete>@<versión> …` con todos.

## Qué hace cada paso en GitHub

`pes6pkg` muestra cada escritura antes de correrla (las líneas con `$`), y con `--dry-run` la muestra como
`(simulado) …` sin correrla. Las lecturas (consultar el estado, `git fetch` y bajar lo publicado) corren siempre.
Comprobado contra `gh` 2.101:

| Paso | Lo que corre | Qué esperar |
|---|---|---|
| Estado del release | `gh release list --repo <repo> --json tagName,isDraft,isImmutable --limit 1000` y `gh release view <tag> --json …,assets` | `En GitHub: no existe todavía.` / `borrador con <archivos>` / `publicado e inmutable`. `gh` encuentra un borrador por su tag |
| Borrador | `gh release create <tag> --repo <repo> --draft --title "<nombre> <versión>" --notes-file <notas> <zip>` | solo el zip: `gh` sube en paralelo los archivos de un mismo `create`, así el zip queda primero. El tag todavía no existe |
| El resto | `gh release upload <tag> --repo <repo> <manifiesto> <manifiesto>.minisig` | |
| Comparar | `gh release download <tag> --repo <repo> --dir <temporal> --clobber` | `Borrador: lo subido coincide con lo armado.` |
| Publicar | `gh release edit <tag> --repo <repo> --draft=false` | `Publicado <repo> <tag>.` GitHub crea el tag desde la rama principal del repo del mod; desde acá el release es inmutable |
| Lo público | bajar sin sesión `…/releases/download/<tag>/<zip>`, el manifiesto y su `.minisig` | `las direcciones públicas bajan lo mismo que se armó (zip, manifiesto y firma).` |
| Atestación | `gh release verify-asset <tag> <zip> --repo <repo>` | `gh release verify-asset: bien.` (gh dice `Verification succeeded!`). Si no, la inmutabilidad está apagada en ese repo |
| Borrar un borrador | `gh release delete <tag> --repo <repo> --yes` | solo con `--discard`, o para rehacer un borrador distinto; nunca toca uno publicado |
| PR del índice | `git worktree add …`, `git commit`, `git push -u origin publicar/indice-N`, `gh pr create --repo angelballay/pes6-package-pc --head publicar/indice-N --base main` | antes del push: la misma comprobación que la CI, y otro `git fetch`. Después: `Índice N firmado, vence el …. PR: …` |

## Si algo se corta a mitad de camino

| Qué dice | Cómo quedó | Qué hacer |
|---|---|---|
| En `publish`: `No se publicó nada. Los borradores quedan` (contestaste que no) | borradores, privados | el mismo `publish` los retoma |
| En `publish`: `Publicados y comprobados: … Sin terminar: … Ninguno entró al índice` | algunos publicados, el resto en borrador, sin índice: nadie ve nada | el mismo `publish` en unos minutos: retoma donde quedó |
| `Quedó en borrador: no se publicó nada` (contestaste que no) | un borrador, privado | el mismo comando lo retoma; `--discard` lo borra |
| `Falló: gh release upload …` (se cortó la red) | un borrador a medias | el mismo comando lo rehace |
| `minisign no pudo firmar (¿contraseña equivocada?)` en `release` | nada publicado, el borrador sigue | el mismo comando |
| `minisign no pudo firmar` en `index add`, o se cortó antes del PR | los releases publicados, fuera del índice: nadie los ve | el mismo `index add` |
| `Ya hay una rama publicar/indice-N` | hay un PR del índice sin mergear | mergealo, o cerralo y borrá la rama; después, el mismo comando |
| `Mientras tanto otro PR cambió el índice de main` | no se subió nada | el mismo comando (parte del `main` nuevo) |
| `N de M paquetes no están listos` | no se firmó nada | lo que dice cada línea `NO ESTÁ LISTO` (publicar uno que falta, retomar un borrador) |
| `quedó publicado, pero las direcciones públicas no bajan lo armado` | publicado, fuera del índice | esperá unos minutos y `pes6pkg index add <paquete>@<versión>`; si sigue igual, versión nueva |
| `trae translations 1.0 adentro, y dll-v1.0 no está publicado` | nada | publicá antes `translations` |
| `se armó de nuevo después` | nada | armá el idioma otra vez, con la `translations` publicada |
| `La rama … quedó subida pero no se abrió el PR` | la rama está en GitHub | el `gh pr create …` que muestra |

## Renovar el índice (cada dos meses)

El índice vence a los **90 días** de firmarlo. Vencido, nada se rompe, pero los jugadores dejan de ver avisos.

```
pes6pkg renew --dry-run   → qué haría, sin firmar
pes6pkg renew             → contraseña de K1 → abre el PR
(mergeás el PR)
pes6pkg verify-live
```

y después importás el `.ics` nuevo. Cada `index add` (y cada `release` sin `--no-index`) también renueva el índice.

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
| `El índice … tiene CR` | git lo convirtió: `.gitattributes` tiene que tener `index/** -text`; volvé a hacer checkout |
| `ya está publicado y no coincide con lo armado` | la versión ya se publicó con otros archivos; las etiquetas inmutables no se reusan: subí la versión |
| `… está en <paquete> y en translations: un nombre por zip` | los documentos de cada paquete van en `Docs/<paquete>/` (packages/README.md) |
| `… se armó con claves de prueba` | ese `out\…` es de un simulacro: armalo de nuevo sin `--test-keys` |
| `El origin de … no es …` | tu checkout apunta a otro repo: revisá `git remote -v` |
