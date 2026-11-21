"""Vectores de prueba del verificador (design §15): índices, manifiestos y zips válidos y uno por cada falla de §5.3,
firmados con claves de PRUEBA deterministas. Los corren el verificador C++ (client/tests) y el de Python
(tool/tests/test_vectors.py) con el mismo `cases.json`, y los dos tienen que dar lo esperado.

No se commitean (hay zips): se generan con `pes6pkg vectors --out <carpeta>`."""
import hashlib
import io
import struct
import zipfile
import zlib
from pathlib import Path

from . import jsonr, minisig, model, verify
from .keys import load_test

NOW = '2026-12-10T00:00:00Z'
TOOL_DIR = Path(__file__).resolve().parent.parent


def _sha(b):
    return hashlib.sha256(b).hexdigest()


class _Gen:
    def __init__(self, out: Path):
        self.out = out
        self.ring = load_test(('k1', 'k2'))
        self.k1, self.k2 = (self.ring.signing[k.key_id] for k in self.ring.keys)
        self.other = minisig.TestKey.derive('otra')
        self.cases = []

    def put(self, name, data):
        (self.out / name).write_bytes(data if isinstance(data, bytes) else data.encode('utf-8'))
        return name

    def case(self, **kw):
        kw.setdefault('now', NOW)
        self.cases.append(kw)

    # ---------------------------------------------------------------- índices
    def index_doc(self, serial=3, issued='2026-12-05T21:30:00Z', expires='2027-03-05T21:30:00Z', **extra):
        d = {'type': model.INDEX_TYPE, 'schema': 1, 'serial': serial, 'issued': issued, 'expires': expires,
             'packages': [{
                 'package': 'hdtext', 'name': 'PES6 HD Text', 'version': '1.0.2', 'released': '2026-12-05',
                 'notes': 'https://github.com/angelballay/pes6-hd-text/releases/tag/v1.0.2',
                 'manifest': {'url': 'https://github.com/angelballay/pes6-hd-text/releases/download/v1.0.2/'
                                     'hdtext-1.0.2.manifest.json', 'size': 9214, 'sha256': 'a' * 64},
                 'archive': {'url': 'https://github.com/angelballay/pes6-hd-text/releases/download/v1.0.2/'
                                    'PES6_HD_Text_v1.0.2.zip', 'size': 47210334, 'sha256': 'b' * 64}}]}
        d.update(extra)
        return d

    def signed(self, name, data: bytes, comment, key=None, alg=b'ED'):
        self.put(name, data)
        self.put(name + '.minisig', (key or self.k1).sign(data, comment, alg))
        return name

    def index_cases(self):
        ok = jsonr.dumps(self.index_doc())
        c3 = model.index_comment(3)
        f = self.signed('idx_ok.json', ok, c3)
        self.case(name='índice válido', kind='index', file=f, expect='OK', expect_serial=3)
        self.case(name='índice válido, mismo serial y mismo contenido', kind='index', file=f, state_serial=3,
                  state_hash=minisig.blake2b512(ok).hex(), expect='OK')
        self.case(name='índice con un serial menor (retroceso)', kind='index', file=f, state_serial=7,
                  expect='E_ROLLBACK')
        self.case(name='índice más viejo que el piso compilado', kind='index', file=f, min_serial=5,
                  expect='E_ROLLBACK')
        self.case(name='mismo serial con otro contenido', kind='index', file=f, state_serial=3,
                  state_hash='0' * 128, expect='E_SAME_SERIAL')
        self.case(name='índice vencido', kind='index', file=f, now='2027-03-06T00:00:00Z', expect='E_EXPIRED')
        self.case(name='firmado con K1 revocada', kind='index', file=f, state_revoked=[self.k1.key_id.hex()],
                  expect='E_REVOKED_KEY')
        # un byte cambiado
        self.put('idx_byte.json', ok.replace(b'"serial": 3', b'"serial": 3 '))
        self.put('idx_byte.json.minisig', (self.out / 'idx_ok.json.minisig').read_bytes())
        self.case(name='un byte cambiado en el índice', kind='index', file='idx_byte.json', expect='E_BAD_SIGNATURE')
        self.signed('idx_legacy.json', ok, c3, alg=b'Ed')
        self.case(name='algoritmo viejo Ed', kind='index', file='idx_legacy.json', expect='E_SIG_ALGORITHM')
        self.signed('idx_other.json', ok, c3, key=self.other)
        self.case(name='clave desconocida', kind='index', file='idx_other.json', expect='E_UNKNOWN_KEY')
        sig = (self.out / 'idx_ok.json.minisig').read_text(encoding='utf-8')
        self.put('idx_tc.json', ok)
        self.put('idx_tc.json.minisig', sig.replace('pes6pkg index 3', 'pes6pkg index 4'))
        self.case(name='comentario confiable cambiado', kind='index', file='idx_tc.json', expect='E_BAD_GLOBAL_SIGNATURE')
        self.signed('idx_comment.json', ok, model.index_comment(4))
        self.case(name='comentario que no coincide con el serial', kind='index', file='idx_comment.json',
                  expect='E_BAD_COMMENT')
        self.signed('idx_k2.json', ok, c3, key=self.k2)
        self.case(name='firmado con la reserva: revoca K1', kind='index', file='idx_k2.json', expect='OK',
                  expect_revoked=[self.k1.key_id.hex()])
        long = jsonr.dumps(self.index_doc(expires='2027-12-05T21:30:00Z'))
        self.signed('idx_lifetime.json', long, c3)
        self.case(name='plazo de más de 180 días', kind='index', file='idx_lifetime.json', expect='E_LIFETIME')
        for n, raw in (('float', ok.replace(b'"size": 9214', b'"size": 92.14')),
                       ('null', ok.replace(b'"name": "PES6 HD Text"', b'"name": null')),
                       ('dupe', ok.replace(b'"schema": 1,', b'"schema": 1,\n  "schema": 1,')),
                       ('cr', ok.replace(b'\n', b'\r\n')),
                       ('bom', b'\xef\xbb\xbf' + ok),
                       ('negativo', ok.replace(b'"size": 9214', b'"size": -9214'))):
            self.signed(f'idx_json_{n}.json', raw, c3)
            self.case(name=f'JSON fuera de las reglas ({n})', kind='index', file=f'idx_json_{n}.json', expect='E_JSON')
        self.signed('idx_type.json', jsonr.dumps(self.index_doc(type='otra-cosa')), c3)
        self.case(name='type distinto', kind='index', file='idx_type.json', expect='E_TYPE')
        self.signed('idx_schema.json', jsonr.dumps(self.index_doc(schema=2)), c3)
        self.case(name='schema desconocido', kind='index', file='idx_schema.json', expect='E_SCHEMA')
        self.signed('idx_extra.json', jsonr.dumps(self.index_doc(mirror='https://example.com/x')), c3)
        self.case(name='campo desconocido: se ignora', kind='index', file='idx_extra.json', expect='OK')
        self.put('idx_fmt.json', ok)
        self.put('idx_fmt.json.minisig', '\n'.join(sig.splitlines()[:3]) + '\n')
        self.case(name='.minisig de tres líneas', kind='index', file='idx_fmt.json', expect='E_SIG_FORMAT')
        bad_url = self.index_doc()
        bad_url['packages'][0]['archive']['url'] = 'http://github.com/x.zip'
        self.signed('idx_url.json', jsonr.dumps(bad_url), c3)
        self.case(name='dirección que no es https', kind='index', file='idx_url.json', expect='E_FIELD')

    # ---------------------------------------------------------------- manifiestos
    def manifest_doc(self, package='hdtext', version='1.0.2', files=None, requires=None):
        files = files if files is not None else [
            {'path': 'Kitserver/pes6_hd_text.dll', 'size': 3, 'sha256': _sha(b'dll'), 'install': True},
            {'path': 'Kitserver/hdtext.exe', 'size': 3, 'sha256': _sha(b'exe'), 'install': True},
            {'path': 'README.txt', 'size': 6, 'sha256': _sha(b'readme'), 'install': False}]
        return {'type': model.MANIFEST_TYPE, 'schema': 1, 'package': package, 'name': 'X', 'version': version,
                'released': '2026-12-05', 'requires': requires or [], 'files': files}

    def man(self, name, doc, comment=None):
        data = jsonr.dumps(doc)
        return self.signed(name, data, comment or model.manifest_comment(doc['package'], doc['version']))

    def manifest_cases(self):
        f = self.man('man_ok.json', self.manifest_doc())
        self.case(name='manifiesto válido', kind='manifest', file=f, package='hdtext', version='1.0.2',
                  installed='1.0.1.2', expect='OK')
        self.case(name='manifiesto de otro paquete', kind='manifest', file=f, package='translation-ru', expect='E_WRONG_PACKAGE')
        self.case(name='manifiesto de otra versión', kind='manifest', file=f, package='hdtext', version='1.0.3',
                  expect='E_WRONG_VERSION')
        self.case(name='versión igual a la instalada', kind='manifest', file=f, installed='1.0.2', expect='E_NOT_NEWER')
        self.case(name='versión igual, reparar permitido', kind='manifest', file=f, installed='1.0.2', allow_equal=True,
                  expect='OK')
        self.case(name='versión menor que la instalada', kind='manifest', file=f, installed='1.0.3', allow_equal=True,
                  expect='E_NOT_NEWER')
        for n, path in (('dotdot', 'Kitserver/../pes6.exe'), ('drive', 'C:/x.dll'), ('backslash', 'Kitserver\\x.dll'),
                        ('reserved', 'Kitserver/NUL.dll'), ('ads', 'Kitserver/x.dll:flujo'), ('slash', '/Kitserver/x.dll'),
                        ('trailing_dot', 'Kitserver/x.dll.')):
            doc = self.manifest_doc(files=[{'path': path, 'size': 1, 'sha256': 'c' * 64, 'install': True}])
            self.man(f'man_path_{n}.json', doc)
            self.case(name=f'ruta tramposa ({n})', kind='manifest', file=f'man_path_{n}.json', expect='E_PATH')
        doc = self.manifest_doc(files=[
            {'path': 'Kitserver/hdtext.exe', 'size': 1, 'sha256': 'c' * 64, 'install': True},
            {'path': 'Kitserver/HDTEXT.exe', 'size': 1, 'sha256': 'c' * 64, 'install': True}])
        self.man('man_dupe.json', doc)
        self.case(name='rutas repetidas por mayúsculas', kind='manifest', file='man_dupe.json', expect='E_PATH')
        doc = self.manifest_doc('translation-ru', '1.0', files=[
            {'path': 'Kitserver/pes6_hd_text.dll', 'size': 1, 'sha256': 'c' * 64, 'install': True}])
        self.man('man_tr_dll.json', doc)
        self.case(name='una traducción que escribe la DLL de HD Text', kind='manifest', file='man_tr_dll.json',
                  expect='E_PATH_NOT_ALLOWED')
        doc = self.manifest_doc('translation-e', '1.0', files=[
            {'path': 'dat/e_text.afs', 'size': 1, 'sha256': 'c' * 64, 'install': True}])
        self.man('man_tr_e.json', doc)
        self.case(name='una traducción que pisa un idioma original', kind='manifest', file='man_tr_e.json',
                  expect='E_PATH_NOT_ALLOWED')
        self.man('man_comment.json', self.manifest_doc(), model.manifest_comment('hdtext', '1.0.3'))
        self.case(name='comentario de otra versión', kind='manifest', file='man_comment.json', expect='E_BAD_COMMENT')
        doc = self.manifest_doc('pes6xlife-mods', '0.1', files=[
            {'path': 'Kitserver/pes6xlife_mods.ini', 'size': 1, 'sha256': 'c' * 64, 'install': True,
             'mode': 'if-absent'}])
        self.man('man_mods.json', doc)
        self.case(name='pes6xlife-mods con un .ini if-absent (FMT-10)', kind='manifest', file='man_mods.json', expect='OK')
        doc = self.manifest_doc('translation-ru', '1.0', files=[
            {'path': 'dat/ru_text.afs', 'size': 1, 'sha256': 'c' * 64, 'install': True}],
            requires=[{'package': 'hdtext', 'min': '1.0.2'}, {'package': 'translations', 'min': '1.1'}])
        self.man('man_req.json', doc)
        self.case(name='requires cumplido', kind='requires', file='man_req.json',
                  installed_versions=[{'package': 'hdtext', 'version': '1.0.2'},
                                      {'package': 'translations', 'version': '1.1'}], expect='OK')
        self.case(name='pide una DLL más nueva', kind='requires', file='man_req.json',
                  installed_versions=[{'package': 'hdtext', 'version': '1.0.2'},
                                      {'package': 'translations', 'version': '1.0'}], expect='E_REQUIRES')
        self.case(name='falta un paquete requerido', kind='requires', file='man_req.json',
                  installed_versions=[{'package': 'translations', 'version': '1.1'}], expect='E_REQUIRES')

    # ---------------------------------------------------------------- zips
    def zip_bytes(self, entries, method=zipfile.ZIP_DEFLATED):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            for name, data in entries:
                info = zipfile.ZipInfo(name, (2026, 12, 5, 0, 0, 0))
                info.compress_type = method
                z.writestr(info, data)
        return buf.getvalue()

    def package_entries(self, package, version, files, key=None, sign=True, requires=None):
        doc = {'type': model.MANIFEST_TYPE, 'schema': 1, 'package': package, 'name': 'X', 'version': version,
               'released': '2026-12-05', 'requires': requires or [],
               'files': [{'path': p, 'size': len(d), 'sha256': _sha(d), 'install': '/' in p} for p, d in files]}
        mb = jsonr.dumps(doc)
        mp = model.manifest_zip_path(package)
        out = list(files) + [(mp, mb)]
        if sign:
            out.append((mp + '.minisig', (key or self.k1).sign(mb, model.manifest_comment(package, version)).encode()))
        return out

    def zip_cases(self):
        rnd = b''.join(hashlib.sha512(b'aleatorio %d' % i).digest() for i in range(2048))  # 128 KiB, deterministas
        text = ('Русский текст для проверки. ' * 4000).encode('utf-8')
        dll = self.package_entries('translations', '1.0', [('Kitserver/translations.dll', rnd), ('README.txt', b'readme')])
        lang = self.package_entries('translation-ru', '1.0', [('dat/ru_text.afs', text), ('LEEME.txt', b'x')])
        allowed = ['translations', 'translation-*']
        self.put('zip_dll.zip', self.zip_bytes(dll))
        self.case(name='zip de la DLL de traducciones', kind='zip', file='zip_dll.zip', allowed=allowed, expect='OK')
        self.put('zip_lang.zip', self.zip_bytes(lang))
        self.case(name='zip de un idioma', kind='zip', file='zip_lang.zip', allowed=allowed, expect='OK')
        self.put('zip_stored.zip', self.zip_bytes(lang, zipfile.ZIP_STORED))
        self.case(name='zip sin comprimir', kind='zip', file='zip_stored.zip', allowed=allowed, expect='OK')
        self.put('zip_tiny.zip', self.zip_bytes(self.package_entries('translation-el', '1.0', [('dat/el_text.afs', b'a')])))
        self.case(name='zip con un bloque deflate fijo', kind='zip', file='zip_tiny.zip', allowed=allowed, expect='OK')
        self.put('zip_older.zip', self.zip_bytes(lang))
        self.case(name='idioma más viejo que el instalado', kind='zip', file='zip_older.zip', allowed=allowed,
                  installed_versions=[{'package': 'translation-ru', 'version': '1.1'}], expect='E_NOT_NEWER')
        self.put('zip_nosig.zip', self.zip_bytes(self.package_entries('translation-ru', '1.0', [('dat/ru_text.afs', text)],
                                                                      sign=False)))
        self.case(name='manifiesto sin firma', kind='zip', file='zip_nosig.zip', allowed=allowed, expect='E_SIG_FORMAT')
        self.put('zip_otherkey.zip', self.zip_bytes(self.package_entries('translation-ru', '1.0', [('dat/ru_text.afs', text)],
                                                                         key=self.other)))
        self.case(name='firmado con otra clave', kind='zip', file='zip_otherkey.zip', allowed=allowed, expect='E_UNKNOWN_KEY')
        self.put('zip_extra.zip', self.zip_bytes(lang + [('Kitserver/otra.dll', b'MZ')]))
        self.case(name='entrada que ningún manifiesto nombra', kind='zip', file='zip_extra.zip', allowed=allowed,
                  expect='E_ZIP_EXTRA')
        self.put('zip_missing.zip', self.zip_bytes([e for e in lang if e[0] != 'dat/ru_text.afs']))
        self.case(name='falta un archivo del manifiesto', kind='zip', file='zip_missing.zip', allowed=allowed,
                  expect='E_ZIP_MISSING')
        changed = [(n, (d[:-1] + b'!') if n == 'dat/ru_text.afs' else d) for n, d in lang]
        self.put('zip_hash.zip', self.zip_bytes(changed))
        self.case(name='un archivo cambiado', kind='zip', file='zip_hash.zip', allowed=allowed, expect='E_HASH')
        hd = self.package_entries('hdtext', '1.0.2', [('Kitserver/pes6_hd_text.dll', b'MZ'), ('Kitserver/hdtext.exe', b'MZ')])
        self.put('zip_hdtext.zip', self.zip_bytes(hd))
        self.case(name='HD Text por la vía de las traducciones', kind='zip', file='zip_hdtext.zip', allowed=allowed,
                  expect='E_WRONG_PACKAGE')
        self.case(name='HD Text por su vía', kind='zip', file='zip_hdtext.zip', allowed=['hdtext'], expect='OK')
        self.put('zip_dotdot.zip', self.zip_bytes(lang + [('../x.dll', b'MZ')]))
        self.case(name='nombre con .. en el zip', kind='zip', file='zip_dotdot.zip', allowed=allowed, expect='E_PATH')
        self.put('zip_dupe.zip', self.zip_bytes(lang + [('DAT/RU_TEXT.AFS', text)]))
        self.case(name='entrada repetida', kind='zip', file='zip_dupe.zip', allowed=allowed, expect='E_ZIP')
        self.put('zip_crc.zip', self._patch_crc(self.zip_bytes(lang), 'dat/ru_text.afs'))
        self.case(name='CRC-32 cambiado', kind='zip', file='zip_crc.zip', allowed=allowed, expect='E_CRC')
        self.put('zip_crypt.zip', self._patch_flags(self.zip_bytes(lang), 'dat/ru_text.afs', 0x1))
        self.case(name='entrada cifrada', kind='zip', file='zip_crypt.zip', allowed=allowed, expect='E_ZIP')
        self.put('zip_bomb.zip', self._bomb())
        self.case(name='zip bomba', kind='zip', file='zip_bomb.zip', allowed=allowed, expect='E_ZIP_BOMB')
        self.put('zip_notzip.zip', b'esto no es un zip')
        self.case(name='no es un zip', kind='zip', file='zip_notzip.zip', allowed=allowed, expect='E_ZIP')

    def _cd_entries(self, data):
        end = data.rfind(b'PK\x05\x06')
        n, = struct.unpack_from('<H', data, end + 10)
        off, = struct.unpack_from('<I', data, end + 16)
        p = off
        for _ in range(n):
            nlen, xlen, mlen = struct.unpack_from('<HHH', data, p + 28)
            loff, = struct.unpack_from('<I', data, p + 42)
            yield p, loff, data[p + 46:p + 46 + nlen].decode()
            p += 46 + nlen + xlen + mlen

    def _patch_crc(self, data, name):
        b = bytearray(data)
        for p, loff, n in self._cd_entries(data):
            if n == name:
                for at in (p + 16, loff + 14):
                    b[at] ^= 0xFF
        return bytes(b)

    def _patch_flags(self, data, name, bit):
        b = bytearray(data)
        for p, loff, n in self._cd_entries(data):
            if n == name:
                for at in (p + 8, loff + 6):
                    b[at] |= bit
        return bytes(b)

    def _bomb(self):
        """Una entrada que dice 1000 bytes (y el manifiesto también), pero se descomprime a 1 MiB."""
        real = b'\0' * (1 << 20)
        declared = real[:1000]
        entries = self.package_entries('translation-ru', '1.0', [('dat/ru_text.afs', declared)])
        data = bytearray(self.zip_bytes(entries))
        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        bomb = comp.compress(real) + comp.flush()
        out = io.BytesIO()
        # se rearma el zip a mano: la entrada del .afs con el deflate de 1 MiB y usize = 1000
        with zipfile.ZipFile(io.BytesIO(bytes(data))) as z:
            items = [(i, z.read(i.filename)) for i in z.infolist()]
        cd, offs = [], []
        for info, payload in items:
            if info.filename == 'dat/ru_text.afs':
                method, crc, csize, usize, raw = 8, zlib.crc32(declared), len(bomb), 1000, bomb
            else:
                c = zlib.compressobj(9, zlib.DEFLATED, -15)
                raw = c.compress(payload) + c.flush()
                method, crc, csize, usize = 8, zlib.crc32(payload), len(raw), len(payload)
            name = info.filename.encode()
            offs.append(out.tell())
            out.write(struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, 0, method, 0, 0x5985, crc, csize, usize, len(name), 0))
            out.write(name + raw)
            cd.append(struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, method, 0, 0x5985, crc, csize, usize,
                                  len(name), 0, 0, 0, 0, 0x20, offs[-1]) + name)
        cd_off = out.tell()
        cd_b = b''.join(cd)
        out.write(cd_b)
        out.write(struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, len(cd), len(cd), len(cd_b), cd_off, 0))
        return out.getvalue()

    # ---------------------------------------------------------------- interoperabilidad con minisign real
    def interop_cases(self):
        src = TOOL_DIR / 'tests' / 'data' / 'interop'
        for n in ('interop.json', 'interop.json.minisig', 'interop.pub'):
            self.put(n, (src / n).read_bytes())
        self.case(name='firma hecha por minisign 0.12 real', kind='signature', file='interop.json', keyring='interop',
                  expect_comment='pes6pkg interop 1', expect='OK')
        for n in ('interop-index.json', 'interop-index.json.minisig', 'interop-index.pub'):
            self.put(n, (src / n).read_bytes())
        self.case(name='índice firmado por minisign 0.12 real, con clave cifrada', kind='index',
                  file='interop-index.json', keyring='interop-index', expect='OK', expect_serial=1)

    def build_cases(self):
        """Un paquete armado de punta a punta por `pes6pkg build` (receta real de HD Text, claves de prueba)."""
        import tempfile
        from contextlib import redirect_stdout
        from . import package, signer
        keybytes = b''.join(k.key for k in self.ring.embedded())

        def pe(extra):
            key = 'VS_VERSION_INFO'.encode('utf-16-le') + b'\0\0'
            blob = b'MZ' + b'\0' * 66 + key
            blob += b'\0' * ((4 - len(blob) % 4) % 4)
            return blob + struct.pack('<13I', 0xFEEF04BD, 0x00010000, 0x10000, 0x20000, 0x10000, 0x20000,
                                      0x3F, 0, 0x40004, 2, 0, 0, 0) + extra
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'src'
            (src / 'Kitserver' / 'GDB' / 'fonts' / 'licenses').mkdir(parents=True)
            (src / 'Kitserver' / 'pes6_hd_text.dll').write_bytes(pe(keybytes))
            (src / 'Kitserver' / 'hdtext.exe').write_bytes(pe(keybytes))
            (src / 'Kitserver' / 'GDB' / 'fonts' / 'HD_teko.bin').write_bytes(b'fuente HD ' * 5000)
            (src / 'Kitserver' / 'GDB' / 'fonts' / 'FONT_LICENSES.txt').write_bytes(b'licencias')
            (src / 'Kitserver' / 'GDB' / 'fonts' / 'licenses' / 'OFL_teko.txt').write_bytes(b'OFL')
            for n in ('README.txt', 'LEEME.txt', 'CHANGELOG.md', 'LICENSE.txt'):
                (src / n).write_bytes(n.encode())
            with redirect_stdout(io.StringIO()):
                _, info = package.build(TOOL_DIR.parent, 'hdtext', '1.0.2', src, Path(tmp) / 'out',
                                        signer.TestSigner(self.k1), self.ring, '2026-12-05')
            zb = (Path(tmp) / 'out' / 'hdtext' / '1.0.2' / info['archive']['name']).read_bytes()
        self.put('build_hdtext.zip', zb)
        self.case(name='paquete armado por pes6pkg build (HD Text)', kind='zip', file='build_hdtext.zip',
                  allowed=['hdtext'], expect='OK')
        self.case(name='el mismo paquete, con HD Text más nueva instalada', kind='zip', file='build_hdtext.zip',
                  allowed=['hdtext'], installed_versions=[{'package': 'hdtext', 'version': '1.0.3'}], expect='E_NOT_NEWER')

    def write(self):
        self.build_cases()
        self.index_cases()
        self.manifest_cases()
        self.zip_cases()
        self.interop_cases()
        interop = minisig.parse_public_key((self.out / 'interop.pub').read_text(encoding='utf-8'))
        interop_index = minisig.parse_public_key((self.out / 'interop-index.pub').read_text(encoding='utf-8'))
        keys = {'default': [{'id': k.key_id.hex(), 'key': k.key.hex()} for k in self.ring.keys],
                'interop': [{'id': interop.key_id.hex(), 'key': interop.key.hex()}],
                'interop-index': [{'id': interop_index.key_id.hex(), 'key': interop_index.key.hex()}]}
        self.put('keys.json', jsonr.dumps(keys, max_depth=8))
        self.put('cases.json', jsonr.dumps({'cases': self.cases}, max_depth=8))
        return len(self.cases)


def generate(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    return _Gen(out).write()


def load_cases(out):
    out = Path(out)
    return jsonr.loads((out / 'cases.json').read_bytes(), max_depth=8)['cases'], \
        jsonr.loads((out / 'keys.json').read_bytes(), max_depth=8)


def run_case(case, folder, keyrings):
    """Corre un caso con el verificador de Python. Devuelve (código, detalle)."""
    folder = Path(folder)
    ring = [minisig.PublicKey(bytes.fromhex(k['id']), bytes.fromhex(k['key']))
            for k in keyrings[case.get('keyring', 'default')]]
    state = verify.State(case.get('state_serial', 0), case.get('state_hash', ''),
                         [bytes.fromhex(x) for x in case.get('state_revoked', [])])
    now = model.parse_utc(case['now'])
    try:
        data = (folder / case['file']).read_bytes()
        kind = case['kind']
        if kind in ('index', 'manifest', 'requires', 'signature'):
            sig = (folder / (case['file'] + '.minisig')).read_text(encoding='utf-8')
        if kind == 'index':
            _, _, new = verify.check_index(data, sig, ring, state, now, case.get('min_serial', 0))
            if 'expect_revoked' in case and sorted(k.hex() for k in new.revoked) != sorted(case['expect_revoked']):
                return 'REVOKED_MISMATCH', [k.hex() for k in new.revoked]
            if 'expect_serial' in case and new.index_serial != case['expect_serial']:
                return 'SERIAL_MISMATCH', new.index_serial
        elif kind in ('manifest', 'requires'):
            doc = verify.check_manifest(data, sig, ring, state, case.get('package'), case.get('version'),
                                        case.get('installed'), case.get('allow_equal', False))
            if kind == 'requires':
                verify.check_requires(doc, {x['package']: x['version'] for x in case['installed_versions']})
        elif kind == 'zip':
            inst = {x['package']: x['version'] for x in case.get('installed_versions', [])}
            verify.check_zip(data, ring, state, case['allowed'], inst)
        elif kind == 'signature':
            try:
                _, comment = minisig.verify(data, sig, ring, state.revoked)
            except minisig.MinisigError as e:
                return e.code, str(e)
            if comment != case['expect_comment']:
                return 'COMMENT_MISMATCH', comment
        else:
            return 'UNKNOWN_KIND', kind
    except verify.VerifyError as e:
        return e.code, str(e)
    return 'OK', ''
