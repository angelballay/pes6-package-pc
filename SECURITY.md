# Seguridad

## Si sospechás de un paquete

- Instalá y actualizá **solo** con `hdtext.exe` (o el instalador del zip oficial), o bajando de
  `github.com/angelballay/…` y de la web oficial. `hdtext.exe` rechaza cualquier zip que no esté firmado por el autor.
- Antes de la primera instalación a mano, compará el SHA-256 del zip (`certutil -hashfile <zip> SHA256`) con el que
  muestra el release de GitHub y con `index/index.json` de este repo.
- Si algo no coincide, no lo instales y avisá en un issue de este repo (sin adjuntar el archivo).

## Qué cubre y qué no

Lo cubre: un zip cambiado en un release, una descarga alterada en la red, un sitio falso, un índice viejo servido para
volver a una versión con fallas o para esconder una nueva, archivos enormes, rutas tramposas dentro de un zip, y la
pérdida o filtración de **una** de las dos claves.

No lo cubre: un virus que ya está en la PC del jugador, la primera instalación a mano de un zip falso (por eso
comparar el SHA-256), y el robo a la vez de la clave, su contraseña y la cuenta de GitHub del autor.

## Claves

Las claves públicas están en `keys/` (`keys.json` dice cuál es la de uso, cuál la de reserva y cuáles están
revocadas). Si una clave se pierde o se filtra, el autor rota a la de reserva y lo avisa acá, en el
README de cada mod y en la web.
