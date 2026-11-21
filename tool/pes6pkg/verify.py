"""Comprobación como la hace un cliente (design §5), en Python. Es la segunda implementación del algoritmo: el verificador
C++ (client/) y esta tienen que dar el mismo resultado para cada vector (tool/pes6pkg/vectors.py)."""
import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from datetime import timedelta

from . import jsonr, minisig, model

MAX_INDEX = 256 * 1024
MAX_SIG = 4 * 1024
MAX_MANIFEST = 256 * 1024
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_ZIP_ENTRIES = 2000


class VerifyError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


@dataclass
class State:
    """Lo que el cliente recuerda entre consultas (design §6)."""
    index_serial: int = 0
    index_blake2b: str = ''
    revoked: list = field(default_factory=list)  # ids de 8 bytes


def _signed(data, sig_text, keys, state, max_size):
    if len(data) > max_size:
        raise VerifyError('E_TOO_BIG', f'{len(data)} bytes')
    try:
        idx, comment = minisig.verify(data, sig_text, keys, state.revoked)
    except minisig.MinisigError as e:
        raise VerifyError(e.code, str(e))
    try:
        doc = jsonr.loads(data)
    except jsonr.JsonError as e:
        raise VerifyError('E_JSON', str(e))
    return idx, comment, doc


def check_index(data, sig_text, keys, state: State, now, min_serial=0):
    """Devuelve (doc, índice de la clave, estado nuevo). No toca `state`."""
    idx, comment, doc = _signed(data, sig_text, keys, state, MAX_INDEX)
    try:
        serial, issued, expires = model.validate_index(doc)
    except model.ModelError as e:
        raise VerifyError(e.code, str(e))
    if comment != model.index_comment(serial):
        raise VerifyError('E_BAD_COMMENT', f'comentario confiable {comment!r}')
    if not issued < expires or expires - issued > timedelta(days=model.MAX_LIFETIME_DAYS):
        raise VerifyError('E_LIFETIME', 'plazo de vencimiento inválido')
    if now >= expires:
        raise VerifyError('E_EXPIRED', f'vencido el {model.format_utc(expires)}')
    h = minisig.blake2b512(data).hex()
    floor = max(state.index_serial, min_serial)
    if serial < floor:
        raise VerifyError('E_ROLLBACK', f'serial {serial} < {floor}')
    if serial == state.index_serial and state.index_blake2b and h != state.index_blake2b:
        raise VerifyError('E_SAME_SERIAL', f'serial {serial} con otro contenido')
    revoked = list(state.revoked)
    for k in keys[:idx]:  # VER-6: la firma de una clave revoca a las anteriores de la lista
        if k.key_id not in revoked:
            revoked.append(k.key_id)
    return doc, idx, State(serial, h, revoked)


def check_manifest(data, sig_text, keys, state: State, package=None, version=None, installed=None,
                   allow_equal=False, packages_allowed=None):
    """Comprueba un manifiesto firmado. `package`/`version`: los que pidió el índice (None = cualquiera).
    `installed`: versión instalada (None = ninguna). `packages_allowed`: patrones de paquete aceptados (vía de archivo)."""
    _, comment, doc = _signed(data, sig_text, keys, state, MAX_MANIFEST)
    try:
        pkg, ver = model.validate_manifest(doc)
    except model.ModelError as e:
        raise VerifyError(e.code, str(e))
    if comment != model.manifest_comment(pkg, ver):
        raise VerifyError('E_BAD_COMMENT', f'comentario confiable {comment!r}')
    if package is not None and pkg != package:
        raise VerifyError('E_WRONG_PACKAGE', f'{pkg} en lugar de {package}')
    if packages_allowed is not None and not any(
            pkg == p or (p.endswith('*') and pkg.startswith(p[:-1])) for p in packages_allowed):
        raise VerifyError('E_WRONG_PACKAGE', f'{pkg} no se instala por esta vía')
    if version is not None and ver != version:
        raise VerifyError('E_WRONG_VERSION', f'{ver} en lugar de {version}')
    if installed is not None:
        c = model.compare_versions(ver, installed)
        if c < 0 or (c == 0 and not allow_equal):
            raise VerifyError('E_NOT_NEWER', f'{ver} no es más nueva que {installed}')
    return doc


def check_requires(doc, installed_versions):
    for r in doc['requires']:
        have = installed_versions.get(r['package'])
        if have is None or model.compare_versions(have, r['min']) < 0:
            raise VerifyError('E_REQUIRES', f'{r["package"]} {r["min"]} o más nueva')


def check_bytes(data, ref):
    if len(data) != ref['size']:
        raise VerifyError('E_SIZE', f'{len(data)} bytes en lugar de {ref["size"]}')
    if hashlib.sha256(data).hexdigest() != ref['sha256']:
        raise VerifyError('E_HASH', 'SHA-256 distinto')


# ---------------------------------------------------------------- zip estricto (design §5.4)

@dataclass
class ZipEntry:
    name: str
    method: int
    crc: int
    csize: int
    usize: int
    data_offset: int


def open_zip(data):
    """Lee el directorio central con las reglas de §5.4. Devuelve la lista de entradas (sin carpetas)."""
    if len(data) > MAX_ARCHIVE:
        raise VerifyError('E_TOO_BIG', 'zip demasiado grande')
    end = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        raise VerifyError('E_ZIP', 'no es un zip')
    disk, cd_disk, n_disk, n, cd_size, cd_off, clen = struct.unpack_from('<HHHHIIH', data, end + 4)
    if disk or cd_disk or n_disk != n or end + 22 + clen != len(data):
        raise VerifyError('E_ZIP', 'zip de varios discos o con basura al final')
    if n > MAX_ZIP_ENTRIES or n == 0xFFFF or cd_off == 0xFFFFFFFF:
        raise VerifyError('E_ZIP', 'demasiadas entradas o zip64')
    if cd_off + cd_size != end:
        raise VerifyError('E_ZIP', 'directorio central fuera de lugar')
    entries, seen, p = [], set(), cd_off
    spans = []
    for _ in range(n):
        if p + 46 > end or data[p:p + 4] != b'PK\x01\x02':
            raise VerifyError('E_ZIP', 'entrada del directorio central inválida')
        (flags, method, crc, csize, usize, nlen, xlen, mlen, disk_start, loff) = struct.unpack_from(
            '<8xHH4xIIIHHHH6xI', data, p)
        name_b = data[p + 46:p + 46 + nlen]
        p += 46 + nlen + xlen + mlen
        if p > end:
            raise VerifyError('E_ZIP', 'directorio central cortado')
        if flags & 0x1 or disk_start:
            raise VerifyError('E_ZIP', 'entrada cifrada o en otro disco')
        if 0xFFFFFFFF in (csize, usize, loff):
            raise VerifyError('E_ZIP', 'zip64 no permitido')
        if method not in (0, 8):
            raise VerifyError('E_ZIP', f'método {method} no permitido')
        try:
            name = name_b.decode('utf-8' if flags & 0x800 else 'ascii')
        except UnicodeDecodeError:
            raise VerifyError('E_ZIP', 'nombre con bytes inválidos')
        if loff + 30 > cd_off or data[loff:loff + 4] != b'PK\x03\x04':
            raise VerifyError('E_ZIP', 'cabecera local inválida')
        lnlen, lxlen = struct.unpack_from('<HH', data, loff + 26)
        if data[loff + 30:loff + 30 + lnlen] != name_b:
            raise VerifyError('E_ZIP', 'el nombre local no coincide')
        doff = loff + 30 + lnlen + lxlen
        if doff + csize > cd_off:
            raise VerifyError('E_ZIP', 'datos fuera del archivo')
        spans.append((loff, doff + csize))
        if name.endswith('/'):
            if usize or csize > 2:
                raise VerifyError('E_ZIP', 'carpeta con contenido')
            continue
        if not model.valid_path(name):
            raise VerifyError('E_PATH', f'nombre inválido en el zip: {name!r}')
        if name.lower() in seen:
            raise VerifyError('E_ZIP', f'entrada repetida: {name}')
        seen.add(name.lower())
        if method == 0 and csize != usize:
            raise VerifyError('E_ZIP', 'entrada guardada con tamaños distintos')
        entries.append(ZipEntry(name, method, crc, csize, usize, doff))
    spans.sort()
    for (a0, a1), (b0, _) in zip(spans, spans[1:]):
        if b0 < a1:
            raise VerifyError('E_ZIP', 'entradas superpuestas')
    return entries


def read_entry(data, e: ZipEntry, expected_size):
    if e.usize != expected_size:
        raise VerifyError('E_SIZE', f'{e.name}: {e.usize} bytes en lugar de {expected_size}')
    raw = data[e.data_offset:e.data_offset + e.csize]
    if e.method == 0:
        out = raw
    else:
        d = zlib.decompressobj(-15)
        try:
            out = d.decompress(raw, expected_size + 1)
        except zlib.error:
            raise VerifyError('E_ZIP', f'{e.name}: deflate roto')
        if len(out) > expected_size or d.unconsumed_tail:
            raise VerifyError('E_ZIP_BOMB', f'{e.name}: se descomprime a más de {expected_size} bytes')
        if not d.eof:
            raise VerifyError('E_ZIP', f'{e.name}: deflate incompleto')
    if len(out) != expected_size:
        raise VerifyError('E_SIZE', f'{e.name}: {len(out)} bytes')
    if zlib.crc32(out) & 0xFFFFFFFF != e.crc:
        raise VerifyError('E_CRC', f'{e.name}: CRC-32 distinto')
    return out


def check_zip(data, keys, state: State, packages_allowed=None, installed=None, allow_equal=True):
    """Zip de un paquete (o de varios): primero los manifiestos y sus firmas, después cada entrada (VER-8, VER-11).
    `installed`: {paquete: versión}. Devuelve [(doc del manifiesto, {ruta: bytes})]."""
    entries = open_zip(data)
    by_name = {e.name.lower(): e for e in entries}
    prefix = 'kitserver/pes6pkg/installed/'
    manifests = [e for e in entries if e.name.lower().startswith(prefix) and e.name.lower().endswith('.json')]
    if not manifests:
        raise VerifyError('E_ZIP_MISSING', 'el zip no trae ningún manifiesto')
    used = set()
    out = []
    for me in manifests:
        se = by_name.get(me.name.lower() + '.minisig')
        if se is None:
            raise VerifyError('E_SIG_FORMAT', f'{me.name} no tiene su firma')
        if me.usize > MAX_MANIFEST or se.usize > MAX_SIG:
            raise VerifyError('E_TOO_BIG', f'{me.name} demasiado grande')
        mdata = read_entry(data, me, me.usize)
        sdata = read_entry(data, se, se.usize)
        try:
            sig_text = sdata.decode('utf-8')
        except UnicodeDecodeError:
            raise VerifyError('E_SIG_FORMAT', 'firma que no es texto')
        pkg_from_name = me.name[len(prefix):-len('.json')]
        doc = check_manifest(mdata, sig_text, keys, state, package=pkg_from_name,
                             installed=(installed or {}).get(pkg_from_name), allow_equal=allow_equal,
                             packages_allowed=packages_allowed)
        used.update({me.name.lower(), se.name.lower()})
        files = {}
        for f in doc['files']:
            e = by_name.get(f['path'].lower())
            if e is None:
                raise VerifyError('E_ZIP_MISSING', f'falta {f["path"]}')
            if e.name.lower() in used:
                raise VerifyError('E_ZIP', f'{f["path"]} en dos manifiestos')
            used.add(e.name.lower())
            b = read_entry(data, e, f['size'])
            if hashlib.sha256(b).hexdigest() != f['sha256']:
                raise VerifyError('E_HASH', f'{f["path"]}: SHA-256 distinto')
            files[f['path']] = b
        out.append((doc, files))
    extra = [e.name for e in entries if e.name.lower() not in used]
    if extra:
        raise VerifyError('E_ZIP_EXTRA', f'entrada que ningún manifiesto nombra: {extra[0]}')
    return out
