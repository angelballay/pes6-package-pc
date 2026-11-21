"""Quién firma. Producción: minisign.exe con la clave cifrada (pide la contraseña él; PUB-8). Pruebas: las claves de
prueba en Python. La herramienta nunca lee ni guarda una contraseña."""
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import minisig

# minisign 0.12 de https://github.com/jedisct1/minisign/releases/tag/0.12, zip comprobado con la clave del autor
# (RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3) el 2026-11-21. SHA-256 del zip:
# 37b600344e20c19314b2e82813db2bfdcc408b77b876f7727889dbd46d539479
PINNED_MINISIGN = {
    '5535be9e4e123831ebe6ef324aafe9dde507015c176191f9e20c3ad60567f9e1': 'minisign 0.12 win64 x86_64',
    'f39e065e649d5ed7075675accfe0ada234175d63479df650654ec4365d7c4513': 'minisign 0.12 win64 aarch64',
}
MINISIGN_AUTHOR_KEY = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'


def default_key_path(name='k1.key'):
    return Path(os.environ.get('USERPROFILE', str(Path.home()))) / '.pes6pkg' / name


def find_minisign(required=True, pinned=True):
    """minisign (PES6PKG_MINISIGN o el PATH). Para firmar tiene que ser el 0.12 fijado por SHA-256; para la segunda
    comprobación (`-V`, solo puede rechazar) sirve cualquiera, como el de apt en la CI. None si no está y no es
    obligatorio."""
    exe = os.environ.get('PES6PKG_MINISIGN') or shutil.which('minisign')
    if not exe:
        if required:
            raise SystemExit('No encuentro minisign. Instalalo con `winget install jedisct1.minisign` (docs/RECETA.md).')
        return None
    if not pinned:
        return exe
    digest = hashlib.sha256(Path(exe).read_bytes()).hexdigest()
    if digest not in PINNED_MINISIGN:
        raise SystemExit(f'{exe} no es el minisign 0.12 fijado (SHA-256 {digest}). Reinstalalo desde winget o desde '
                         'el release oficial y comprobalo (docs/RECETA.md).')
    return exe


def inside_git_repo(path: Path):
    p = path.resolve().parent
    for q in (p, *p.parents):
        if (q / '.git').exists():
            return q
    return None


class MinisignSigner:
    def __init__(self, key_path: Path, public: minisig.PublicKey, minisign_exe=None):
        key_path = Path(key_path)
        if not key_path.exists():
            raise SystemExit(f'No está la clave {key_path}.')
        repo = inside_git_repo(key_path)
        if repo:
            raise SystemExit(f'La clave {key_path} está dentro del repo {repo}: movela fuera (KEY-2).')
        if not minisig.secret_key_is_encrypted(key_path.read_text(encoding='utf-8')):
            raise SystemExit(f'La clave {key_path} no está cifrada con contraseña: no se usa para publicar (KEY-1).')
        self.key_path = key_path
        self.public = public
        self.exe = minisign_exe or find_minisign()
        self.test = False

    def sign(self, data: bytes, trusted_comment: str) -> str:
        with tempfile.TemporaryDirectory(prefix='pes6pkg-') as tmp:
            f = Path(tmp) / 'a-firmar'
            f.write_bytes(data)
            print(f'minisign firma con la clave {self.public.id_hex}: te va a pedir la contraseña.')
            # stdin y stdout heredados: minisign pide la contraseña en esta consola (PUB-8).
            r = subprocess.run([self.exe, '-S', '-s', str(self.key_path), '-m', str(f), '-t', trusted_comment,
                                '-x', str(f) + '.minisig'])
            if r.returncode != 0:
                raise SystemExit('minisign no pudo firmar (¿contraseña equivocada?). No se cambió nada.')
            text = (Path(str(f) + '.minisig')).read_text(encoding='utf-8')
        sig = minisig.parse_signature(text)
        if sig.algorithm != b'ED' or sig.key_id != self.public.key_id:
            raise SystemExit('La firma no salió con la clave o el algoritmo esperados.')
        minisig.verify(data, text, [self.public])
        return text


class TestSigner:
    """Firma con una clave de prueba (KEY-8). Lo que firma lleva la marca de prueba en el comentario no confiable."""

    def __init__(self, key: minisig.TestKey):
        self.key = key
        self.public = key.public
        self.test = True

    def sign(self, data: bytes, trusted_comment: str) -> str:
        return self.key.sign(data, trusted_comment)


def minisign_verify(exe, data: bytes, sig_text: str, pub: minisig.PublicKey):
    """Segunda comprobación, independiente, con `minisign -V` (libsodium). Devuelve True/False."""
    with tempfile.TemporaryDirectory(prefix='pes6pkg-') as tmp:
        f = Path(tmp) / 'archivo'
        f.write_bytes(data)
        Path(str(f) + '.minisig').write_text(sig_text, encoding='utf-8', newline='\n')
        r = subprocess.run([exe, '-V', '-m', str(f), '-P', pub.to_base64(), '-q'], capture_output=True)
        return r.returncode == 0
