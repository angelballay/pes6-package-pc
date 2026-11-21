"""Reglas del índice y del manifiesto (design §4, FMT-2 a FMT-10, VER-9). El verificador C++ aplica las mismas, en el
mismo orden, y devuelve los mismos códigos de error: los vectores de prueba comparan las dos implementaciones."""
import fnmatch
import re
from datetime import datetime, timezone

INDEX_TYPE = 'pes6pkg-index'
MANIFEST_TYPE = 'pes6pkg-manifest'
SCHEMA = 1
MAX_LIFETIME_DAYS = 180
DEFAULT_LIFETIME_DAYS = 90
MAX_PACKAGES = 64
MAX_FILES = 2000
MAX_URL = 512
MAX_NAME = 64

PACKAGE_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,39}$')
VERSION_RE = re.compile(r'^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){0,3}$')
DATE_RE = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}$')
UTC_RE = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$')
HEX64_RE = re.compile(r'^[0-9a-f]{64}$')
PART_RE = re.compile(r'^[A-Za-z0-9._ -]{1,64}$')
LANG_RE = re.compile(r'^[a-z]{2,3}(-[a-z]{2,4})?$')
RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}
ORIGINAL_LANGS = {'0', 'e', 'f', 'g', 'i', 'p', 's'}
DOC_RE = re.compile(r'^[A-Za-z0-9._ -]{1,64}\.(txt|md)$')
DOCS_DIR = 'Docs'  # documentos de un paquete: Docs/<paquete>/README.txt (install: false)

# Direcciones permitidas (VER-1): compiladas también en el cliente.
INDEX_URL = 'https://raw.githubusercontent.com/angelballay/pes6-package-pc/main/index/index.json'
URL_PREFIXES = (
    'https://raw.githubusercontent.com/angelballay/pes6-package-pc/',
    'https://github.com/angelballay/pes6-hd-text/releases/download/',
    'https://github.com/angelballay/pes6xlife-translations/releases/download/',
)


class ModelError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- versiones (FMT-6)

def parse_version(v):
    if not isinstance(v, str) or not VERSION_RE.match(v):
        return None
    parts = [int(x) for x in v.split('.')]
    if any(x > 65535 for x in parts):
        return None
    return tuple(parts + [0] * (4 - len(parts)))


def compare_versions(a, b):
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        raise ValueError(f'versión inválida: {a!r} o {b!r}')
    return (pa > pb) - (pa < pb)


def version4(v):
    return '.'.join(str(x) for x in parse_version(v))


# ---------------------------------------------------------------- fechas

def parse_utc(s):
    if not isinstance(s, str) or not UTC_RE.match(s):
        return None
    try:
        return datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def format_utc(dt):
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def valid_date(s):
    if not isinstance(s, str) or not DATE_RE.match(s):
        return False
    try:
        datetime.strptime(s, '%Y-%m-%d')
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- rutas (FMT-8, VER-9)

def valid_path(path):
    if not isinstance(path, str) or not path or len(path) > 260:
        return False
    if path.startswith('/') or '\\' in path or ':' in path:
        return False
    for part in path.split('/'):
        if not PART_RE.match(part) or part in ('.', '..') or part[-1] in '. ':
            return False
        if part.split('.')[0].upper() in RESERVED:
            return False
    return True


# Rutas que cada paquete puede escribir (install: true). Patrones de fnmatch sin distinguir mayúsculas; "*" no cruza "/".
ALLOWED = {
    'hdtext': ('Kitserver/pes6_hd_text.dll', 'Kitserver/hdtext.exe', 'Kitserver/GDB/fonts/HD_*.bin',
               'Kitserver/GDB/fonts/FONT_LICENSES.txt', 'Kitserver/GDB/fonts/licenses/*.txt'),
    'translations': ('Kitserver/translations.dll',),
    # provisorio hasta M-2 (design §5.5, §12)
    'pes6xlife-mods': ('Kitserver/pes6xlife_mods.dll', 'Kitserver/pes6xlife_mods.ini'),
}


def _match(path, pattern):
    if path.count('/') != pattern.count('/'):
        return False
    return all(fnmatch.fnmatchcase(a.lower(), b.lower()) for a, b in zip(path.split('/'), pattern.split('/')))


def translation_code(package):
    if not package.startswith('translation-'):
        return None
    code = package[len('translation-'):]
    if not LANG_RE.match(code) or code in ORIGINAL_LANGS:
        return None
    return code


def path_allowed(package, path, install=True):
    if not valid_path(path):
        return False
    if not install:
        # README, LEEME…: en la raíz del zip, o en Docs/<id del paquete>/ (un nivel, solo la carpeta del paquete),
        # así no chocan los de dos paquetes que van en un mismo zip
        parts = path.split('/')
        if len(parts) == 1:
            return bool(DOC_RE.match(path))
        return (len(parts) == 3 and parts[0].lower() == DOCS_DIR.lower() and parts[1].lower() == package
                and bool(DOC_RE.match(parts[2])))
    low = path.lower()
    if low.startswith('kitserver/pes6pkg/'):
        return False  # lo escribe solo el instalador
    code = translation_code(package)
    if code is not None:
        return low == f'dat/{code}_text.afs'
    return any(_match(path, p) for p in ALLOWED.get(package, ()))


def manifest_zip_path(package):
    return f'Kitserver/pes6pkg/installed/{package}.json'


# ---------------------------------------------------------------- direcciones (VER-1)

def valid_url(u):
    return (isinstance(u, str) and u.startswith('https://') and len(u) <= MAX_URL and '?' not in u and '#' not in u
            and '@' not in u.split('/')[2] and ' ' not in u)


def url_allowed(u, prefixes=URL_PREFIXES):
    return valid_url(u) and any(u.startswith(p) for p in prefixes)


# ---------------------------------------------------------------- comentarios confiables (FMT-4)

def index_comment(serial):
    return f'pes6pkg index {serial}'


def manifest_comment(package, version):
    return f'pes6pkg manifest {package} {version}'


# ---------------------------------------------------------------- validación

def _need(obj, key, kind, code='E_FIELD'):
    if not isinstance(obj, dict) or key not in obj:
        raise ModelError(code, f'falta "{key}"')
    v = obj[key]
    if kind is int and (isinstance(v, bool) or not isinstance(v, int)):
        raise ModelError(code, f'"{key}" no es un entero')
    if kind is not int and not isinstance(v, kind):
        raise ModelError(code, f'"{key}" no es {kind.__name__}')
    return v


def _fileref(o, what):
    if not isinstance(o, dict):
        raise ModelError('E_FIELD', f'{what} no es un objeto')
    url = _need(o, 'url', str)
    if not valid_url(url):
        raise ModelError('E_FIELD', f'{what}.url inválida: {url}')
    _need(o, 'size', int)
    if not HEX64_RE.match(_need(o, 'sha256', str)):
        raise ModelError('E_FIELD', f'{what}.sha256 inválido')


def _head(doc, expected_type):
    if not isinstance(doc, dict):
        raise ModelError('E_TYPE', 'no es un objeto')
    if doc.get('type') != expected_type:
        raise ModelError('E_TYPE', f'type distinto de {expected_type}')
    if doc.get('schema') != SCHEMA or isinstance(doc.get('schema'), bool):
        raise ModelError('E_SCHEMA', f'schema {doc.get("schema")!r} desconocido')


def validate_index(doc):
    """Campos del índice. Devuelve (serial, issued, expires). Lanza ModelError."""
    _head(doc, INDEX_TYPE)
    serial = _need(doc, 'serial', int)
    if serial < 1:
        raise ModelError('E_FIELD', 'serial < 1')
    issued, expires = parse_utc(_need(doc, 'issued', str)), parse_utc(_need(doc, 'expires', str))
    if issued is None or expires is None:
        raise ModelError('E_FIELD', 'issued/expires con formato inválido')
    pkgs = _need(doc, 'packages', list)
    if len(pkgs) > MAX_PACKAGES:
        raise ModelError('E_FIELD', 'demasiados paquetes')
    seen = set()
    for i, e in enumerate(pkgs):
        if not isinstance(e, dict):
            raise ModelError('E_FIELD', f'packages[{i}] no es un objeto')
        p = _need(e, 'package', str)
        if not PACKAGE_RE.match(p) or p in seen:
            raise ModelError('E_FIELD', f'package inválido o repetido: {p}')
        seen.add(p)
        if len(_need(e, 'name', str)) > MAX_NAME:
            raise ModelError('E_FIELD', f'{p}: name demasiado largo')
        if parse_version(_need(e, 'version', str)) is None:
            raise ModelError('E_FIELD', f'{p}: versión inválida')
        if not valid_date(_need(e, 'released', str)):
            raise ModelError('E_FIELD', f'{p}: released inválido')
        if not valid_url(_need(e, 'notes', str)):
            raise ModelError('E_FIELD', f'{p}: notes inválido')
        _fileref(e.get('manifest'), f'{p}.manifest')
        _fileref(e.get('archive'), f'{p}.archive')
    return serial, issued, expires


def validate_manifest(doc):
    """Campos del manifiesto, rutas y rutas permitidas. Lanza ModelError."""
    _head(doc, MANIFEST_TYPE)
    package = _need(doc, 'package', str)
    if not PACKAGE_RE.match(package):
        raise ModelError('E_FIELD', f'package inválido: {package}')
    if len(_need(doc, 'name', str)) > MAX_NAME:
        raise ModelError('E_FIELD', 'name demasiado largo')
    if parse_version(_need(doc, 'version', str)) is None:
        raise ModelError('E_FIELD', 'versión inválida')
    if not valid_date(_need(doc, 'released', str)):
        raise ModelError('E_FIELD', 'released inválido')
    for r in _need(doc, 'requires', list):
        if not isinstance(r, dict) or not PACKAGE_RE.match(_need(r, 'package', str)) or \
                parse_version(_need(r, 'min', str)) is None:
            raise ModelError('E_FIELD', 'requires inválido')
    files = _need(doc, 'files', list)
    if len(files) > MAX_FILES:
        raise ModelError('E_FIELD', 'demasiados archivos')
    seen = set()
    for f in files:
        if not isinstance(f, dict):
            raise ModelError('E_FIELD', 'files[] con algo que no es un objeto')
        path = _need(f, 'path', str)
        _need(f, 'size', int)
        if not HEX64_RE.match(_need(f, 'sha256', str)):
            raise ModelError('E_FIELD', f'{path}: sha256 inválido')
        install = _need(f, 'install', bool)
        mode = f.get('mode', 'replace')
        if mode not in ('replace', 'if-absent'):
            raise ModelError('E_FIELD', f'{path}: mode inválido')
        if not valid_path(path) or path.lower() in seen:
            raise ModelError('E_PATH', f'ruta inválida o repetida: {path!r}')
        seen.add(path.lower())
    for f in files:
        if not path_allowed(package, f['path'], f['install']):
            raise ModelError('E_PATH_NOT_ALLOWED', f'{package} no puede escribir {f["path"]}')
    return package, doc['version']
