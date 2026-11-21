# Ensayo: la publicación sin tocar nada

Tres ensayos, de menos a más real. Ninguno publica ni firma con la clave de uso. El primer tiempo del día de la
publicación ([RECETA.md](RECETA.md), solo `translations`) es el ensayo de red con las claves reales.

## 1. Las pruebas automáticas (sin red, sin claves)

```
python -I tool\tests\test_pes6pkg.py
```

Además de las reglas del formato, recorren la publicación entera contra un repo central en un git local (un repo
`--bare` en una carpeta temporal, con `main` y el índice 1) y un `gh` falso con borradores, releases publicados e
inmutables y lo que baja un jugador. Cubren:

- el lote: cuatro `release --no-index`, sin contraseña ni PR, y un `index add` con una firma y un PR cuya rama pasa
  lo mismo que la CI;
- que el índice anterior sale de `origin/main` y no de la carpeta, y que el checkout no se toca;
- la contraseña equivocada, contestar "no", el borrador a medias, `--discard`, completar un release publicado sin
  índice, la rama de un PR sin mergear, y otro PR que cambia `main` mientras se firma;
- el idioma con `translations` adentro (no se sube si la DLL no está publicada, o si es distinta de la publicada) y
  `verify-live --archives` de ese zip;
- `--dry-run` con un llavero real, que no firma ni escribe; y el simulacro local, que no corre ningún comando.

## 2. El simulacro local (claves de prueba, sin red)

Con `--test-keys`, `release`, `index add` y `renew` no corren git, gh ni nada por la red: muestran cada comando como
`(simulado) …` y dejan lo firmado (con las claves de prueba) en `out\prueba\simulado\`. Por defecto todo va a
`out\prueba\`, así un simulacro nunca pisa un paquete real de `out\`.

1. **Armar con las claves de prueba**, con las mismas carpetas y recetas del día:

   ```
   pes6pkg --test-keys build translations 1.0 --from <carpeta de la DLL> --recipes <pes6xlife-translations>\packages
   pes6pkg --test-keys build translation-ru 1.0 --from <carpeta de ru> --recipes <pes6xlife-translations>\packages
   …
   ```

   `translations` y los idiomas sirven tal cual. HD Text necesita un build compilado con `pes6pkg_test_keys.h` (el de
   desarrollo, `pes6pkg --test-keys keys export`); si no lo tenés a mano, ensayá sin HD Text. Mirá que cada idioma
   diga `incluyo translations 1.0` y `adentro: translations 1.0, …`.

2. **Publicar en simulacro**, en el orden del día:

   ```
   pes6pkg --test-keys release translations 1.0 --no-index
   pes6pkg --test-keys index add translations@1.0
   pes6pkg --test-keys release translation-ru 1.0 --no-index
   …
   pes6pkg --test-keys index add translation-ru@1.0 … hdtext@1.0.2
   ```

   Qué mirar:
   - `(simulacro local) sin red ni git: parte de un índice vacío.`;
   - en cada `release`, las líneas `(simulado) gh release create <tag> … <zip>` (solo el zip) y
     `(simulado) gh release upload <tag> … <manifiesto> <manifiesto>.minisig`;
   - en cada `index add`, `(simulado) índice 1 firmado en …\out\prueba\simulado\index`.

   Cada `index add` del simulacro parte de un índice vacío: no es la cuenta de seriales del día real (eso lo ensaya el
   paso 3).
3. **Mirar lo firmado:** `out\prueba\simulado\index\index.json` (los paquetes, sus tamaños y SHA-256) y
   `out\prueba\simulado\manifests\`.

Si un comando del simulacro se queja de que un paquete "se armó con las claves reales", es que le pasaste un `--out`
de un paquete real: el simulacro solo usa paquetes armados con `--test-keys`.

## 3. Con las claves reales, sin publicar (`--dry-run`)

Con los paquetes reales ya armados (`out\…`, con la contraseña de K1), `--dry-run` hace las lecturas de verdad: el
estado de cada release en GitHub, `git fetch` y el índice de `main`, y lo que ya está publicado. No sube, no publica, no
firma y **no pide la contraseña**.

```
pes6pkg release translations 1.0 --no-index --dry-run
pes6pkg index add translations@1.0 --dry-run
pes6pkg renew --dry-run
```

Qué mirar:
- `main de angelballay/pes6-package-pc (<commit>): índice <N>, vence <fecha>.` (el índice que hay hoy en GitHub);
- `En GitHub: no existe todavía.` (o el borrador o el release que haya);
- `(simulado) acá minisign pediría la contraseña de la clave <id> para firmar el índice <N+1>. No se firma nada.`;
- `(simulado) el índice <N+1> vencería el <fecha>, con <paquetes>, y se abriría un PR desde la rama publicar/indice-<N+1> …`;
- `(simulado) AVISO para el día real: …`, si falta la clave o minisign.

`index add --dry-run` de un paquete todavía sin publicar termina con `NO ESTÁ LISTO: … no hay release …`: es lo
esperado antes de publicarlo.
