"""Formato minisign: claves públicas, firmas `.minisig` y comprobación (design §4.2).

Una firma `ED` es Ed25519 sobre BLAKE2b-512 de los bytes del archivo, más una firma global sobre
`firma (64 bytes) || comentario confiable`. El prehash de minisign NO es Ed25519ph (RFC 8032): es Ed25519 común sobre
los 64 bytes del hash.
"""
import base64
import binascii
import hashlib
from dataclasses import dataclass

from . import ed25519

UNTRUSTED = 'untrusted comment: '
TRUSTED = 'trusted comment: '
TEST_MARK = 'PES6PKG TEST KEY - NOT FOR RELEASE'


class MinisigError(Exception):
    """Un `.minisig` o una clave pública mal formados, o una firma que no vale. `code` es el nombre del error del
    verificador C++ (los vectores los comparan)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PublicKey:
    key_id: bytes  # 8 bytes, como están en el archivo
    key: bytes  # 32 bytes
    comment: str = ''

    @property
    def id_hex(self):
        # minisign muestra el id como entero de 64 bits en little-endian, en hexadecimal mayúscula
        return self.key_id[::-1].hex().upper()

    def to_file(self, comment=None):
        c = comment if comment is not None else f'minisign public key {self.id_hex}'
        b64 = base64.b64encode(b'Ed' + self.key_id + self.key).decode('ascii')
        return f'{UNTRUSTED}{c}\n{b64}\n'

    def to_base64(self):
        return base64.b64encode(b'Ed' + self.key_id + self.key).decode('ascii')


@dataclass(frozen=True)
class Signature:
    algorithm: bytes  # b'ED' (prehash) o b'Ed' (viejo)
    key_id: bytes
    sig: bytes
    trusted_comment: str
    global_sig: bytes
    untrusted_comment: str = ''


def _b64(text, size, what):
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise MinisigError('E_SIG_FORMAT', f'{what}: base64 inválido')
    if len(raw) != size:
        raise MinisigError('E_SIG_FORMAT', f'{what}: {len(raw)} bytes en lugar de {size}')
    return raw


def _lines(text):
    # Se aceptan LF y CRLF (minisign en Windows puede escribir CRLF); el comentario confiable va sin el CR.
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    return [ln[:-1] if ln.endswith('\r') else ln for ln in lines]


def parse_public_key(text):
    lines = _lines(text)
    if len(lines) == 1:
        lines = ['', lines[0]]  # la clave sola, en base64 (como en `minisign -P`)
    if len(lines) != 2:
        raise MinisigError('E_SIG_FORMAT', 'clave pública: hacen falta dos líneas')
    comment = lines[0][len(UNTRUSTED):] if lines[0].startswith(UNTRUSTED) else ''
    if lines[0] and not lines[0].startswith(UNTRUSTED):
        raise MinisigError('E_SIG_FORMAT', 'clave pública: la primera línea no es "untrusted comment: "')
    raw = _b64(lines[1], 42, 'clave pública')
    if raw[:2] != b'Ed':
        raise MinisigError('E_SIG_FORMAT', 'clave pública: no es Ed25519')
    return PublicKey(raw[2:10], raw[10:42], comment)


def parse_signature(text):
    if len(text) > 4096:
        raise MinisigError('E_TOO_BIG', '.minisig de más de 4 KiB')
    lines = _lines(text)
    if len(lines) != 4:
        raise MinisigError('E_SIG_FORMAT', f'.minisig: {len(lines)} líneas en lugar de 4')
    if not lines[0].startswith(UNTRUSTED) or not lines[2].startswith(TRUSTED):
        raise MinisigError('E_SIG_FORMAT', '.minisig: faltan los comentarios')
    raw = _b64(lines[1], 74, 'firma')
    glob = _b64(lines[3], 64, 'firma global')
    return Signature(raw[:2], raw[2:10], raw[10:74], lines[2][len(TRUSTED):], glob, lines[0][len(UNTRUSTED):])


def format_signature(sig: Signature):
    return (f'{UNTRUSTED}{sig.untrusted_comment}\n'
            f'{base64.b64encode(sig.algorithm + sig.key_id + sig.sig).decode("ascii")}\n'
            f'{TRUSTED}{sig.trusted_comment}\n'
            f'{base64.b64encode(sig.global_sig).decode("ascii")}\n')


def blake2b512(data):
    return hashlib.blake2b(data, digest_size=64).digest()


def verify(data: bytes, sig_text: str, keys, revoked=()):
    """Comprueba `data` con su `.minisig`. `keys` es una lista de PublicKey; `revoked`, ids (bytes) revocados.
    Devuelve (índice de la clave en `keys`, comentario confiable). Lanza MinisigError con el código del verificador C++."""
    sig = parse_signature(sig_text)
    if sig.algorithm != b'ED':
        raise MinisigError('E_SIG_ALGORITHM', f'algoritmo {sig.algorithm!r}: solo se acepta ED (con prehash)')
    index = next((i for i, k in enumerate(keys) if k.key_id == sig.key_id), None)
    if index is None:
        raise MinisigError('E_UNKNOWN_KEY', f'clave desconocida {sig.key_id[::-1].hex().upper()}')
    if sig.key_id in set(revoked):
        raise MinisigError('E_REVOKED_KEY', f'clave revocada {sig.key_id[::-1].hex().upper()}')
    pub = keys[index].key
    if not ed25519.verify(pub, blake2b512(data), sig.sig):
        raise MinisigError('E_BAD_SIGNATURE', 'la firma del archivo no vale')
    if not ed25519.verify(pub, sig.sig + sig.trusted_comment.encode('utf-8'), sig.global_sig):
        raise MinisigError('E_BAD_GLOBAL_SIGNATURE', 'la firma global (comentario confiable) no vale')
    return index, sig.trusted_comment


@dataclass(frozen=True)
class TestKey:
    """Clave de PRUEBA: la semilla está en claro. Nunca firma nada publicado (KEY-8)."""
    seed: bytes
    key_id: bytes
    name: str

    @property
    def public(self):
        return PublicKey(self.key_id, ed25519.public_key(self.seed), f'{TEST_MARK} ({self.name})')

    @staticmethod
    def derive(name):
        # Determinista: las mismas pruebas dan los mismos vectores.
        h = hashlib.sha512(f'pes6pkg test key: {name}'.encode()).digest()
        return TestKey(h[:32], h[32:40], name)

    def sign(self, data: bytes, trusted_comment: str, algorithm=b'ED'):
        msg = blake2b512(data) if algorithm == b'ED' else data
        s = ed25519.sign(self.seed, msg)
        g = ed25519.sign(self.seed, s + trusted_comment.encode('utf-8'))
        return format_signature(Signature(algorithm, self.key_id, s, trusted_comment, g,
                                          f'{TEST_MARK} ({self.name})'))


def secret_key_is_encrypted(text):
    """¿La clave secreta de minisign está cifrada con contraseña (KDF scrypt)? Formato: "Ed" || KDF (2) || "B2" || …"""
    lines = _lines(text)
    if len(lines) != 2 or not lines[0].startswith(UNTRUSTED):
        raise MinisigError('E_SIG_FORMAT', 'clave secreta: formato desconocido')
    raw = base64.b64decode(lines[1].strip(), validate=True)
    if len(raw) < 6 or raw[:2] != b'Ed':
        raise MinisigError('E_SIG_FORMAT', 'clave secreta: no es Ed25519')
    return raw[2:4] == b'Sc'
