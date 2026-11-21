"""JSON restringido (FMT-5): el mismo lector estricto que el verificador C++, para que los dos acepten y rechacen lo
mismo. Solo objetos, arrays, cadenas, enteros no negativos (≤ 2^53) y true/false; sin null, sin decimales; claves
únicas; UTF-8 sin BOM ni CR; escapes \\" \\\\ \\/ \\n \\t \\uXXXX (sin sustitutos)."""
import json

MAX_INT = 2**53


class JsonError(Exception):
    code = 'E_JSON'


class _Parser:
    def __init__(self, text, max_depth):
        self.s = text
        self.i = 0
        self.max_depth = max_depth

    def fail(self, what):
        raise JsonError(f'JSON inválido en la posición {self.i}: {what}')

    def ws(self):
        while self.i < len(self.s) and self.s[self.i] in ' \n\t':
            self.i += 1

    def value(self, depth):
        self.ws()
        if self.i >= len(self.s):
            self.fail('se esperaba un valor')
        c = self.s[self.i]
        if c == '{':
            return self.obj(depth + 1)
        if c == '[':
            return self.arr(depth + 1)
        if c == '"':
            return self.string()
        if '0' <= c <= '9':
            return self.number()
        for lit, val in (('true', True), ('false', False)):
            if self.s.startswith(lit, self.i):
                self.i += len(lit)
                return val
        self.fail(f'valor no permitido ({c!r})')

    def obj(self, depth):
        if depth > self.max_depth:
            self.fail('demasiado anidado')
        self.i += 1
        out = {}
        self.ws()
        if self.s.startswith('}', self.i):
            self.i += 1
            return out
        while True:
            self.ws()
            if not self.s.startswith('"', self.i):
                self.fail('se esperaba una clave')
            k = self.string()
            if k in out:
                self.fail(f'clave repetida {k!r}')
            self.ws()
            if not self.s.startswith(':', self.i):
                self.fail('se esperaba ":"')
            self.i += 1
            out[k] = self.value(depth)
            self.ws()
            if self.s.startswith(',', self.i):
                self.i += 1
                continue
            if self.s.startswith('}', self.i):
                self.i += 1
                return out
            self.fail('se esperaba "," o "}"')

    def arr(self, depth):
        if depth > self.max_depth:
            self.fail('demasiado anidado')
        self.i += 1
        out = []
        self.ws()
        if self.s.startswith(']', self.i):
            self.i += 1
            return out
        while True:
            out.append(self.value(depth))
            self.ws()
            if self.s.startswith(',', self.i):
                self.i += 1
                continue
            if self.s.startswith(']', self.i):
                self.i += 1
                return out
            self.fail('se esperaba "," o "]"')

    def string(self):
        self.i += 1
        out = []
        while True:
            if self.i >= len(self.s):
                self.fail('cadena sin cerrar')
            c = self.s[self.i]
            if c == '"':
                self.i += 1
                return ''.join(out)
            if ord(c) < 0x20:
                self.fail('carácter de control en una cadena')
            if c == '\\':
                e = self.s[self.i + 1:self.i + 2]
                if e in ('"', '\\', '/'):
                    out.append(e)
                    self.i += 2
                elif e == 'n':
                    out.append('\n')
                    self.i += 2
                elif e == 't':
                    out.append('\t')
                    self.i += 2
                elif e == 'u':
                    h = self.s[self.i + 2:self.i + 6]
                    if len(h) != 4 or any(x not in '0123456789abcdefABCDEF' for x in h):
                        self.fail('\\u inválido')
                    cp = int(h, 16)
                    if 0xD800 <= cp <= 0xDFFF:
                        self.fail('sustituto UTF-16 suelto')
                    out.append(chr(cp))
                    self.i += 6
                else:
                    self.fail(f'escape no permitido \\{e}')
            else:
                out.append(c)
                self.i += 1

    def number(self):
        j = self.i
        while self.i < len(self.s) and '0' <= self.s[self.i] <= '9':
            self.i += 1
        digits = self.s[j:self.i]
        if len(digits) > 1 and digits[0] == '0':
            self.fail('cero a la izquierda')
        if self.i < len(self.s) and self.s[self.i] in '.eE-+':
            self.fail('solo enteros no negativos')
        n = int(digits)
        if n > MAX_INT:
            self.fail('entero demasiado grande')
        return n


def loads(data: bytes, max_depth=4):
    if data.startswith(b'\xef\xbb\xbf'):
        raise JsonError('JSON con BOM')
    if b'\r' in data:
        raise JsonError('JSON con CR (el fin de línea es LF)')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise JsonError('JSON que no es UTF-8')
    p = _Parser(text, max_depth)
    v = p.value(0)
    p.ws()
    if p.i != len(text):
        p.fail('sobra contenido después del valor')
    return v


def _check_writable(v, depth=0):
    if isinstance(v, bool):
        return
    if isinstance(v, int):
        if v < 0 or v > MAX_INT:
            raise JsonError(f'entero fuera de rango: {v}')
        return
    if isinstance(v, str):
        if any(ord(c) < 0x20 and c not in '\n\t' for c in v):
            raise JsonError('carácter de control en una cadena')
        return
    if isinstance(v, dict):
        for k, x in v.items():
            _check_writable(k)
            _check_writable(x, depth + 1)
        return
    if isinstance(v, list):
        for x in v:
            _check_writable(x, depth + 1)
        return
    raise JsonError(f'tipo no permitido: {type(v).__name__}')


def dumps(v, max_depth=4) -> bytes:
    """Escritura canónica de la herramienta: indentado de 2, UTF-8, LF, fin de línea al final. Se vuelve a leer con el
    lector estricto para garantizar que el cliente lo acepta."""
    _check_writable(v)
    data = (json.dumps(v, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
    loads(data, max_depth)
    return data
