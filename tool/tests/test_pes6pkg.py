"""Pruebas de pes6pkg (solo biblioteca estándar): python -I tool/tests/test_pes6pkg.py"""
import base64
import io
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from pes6pkg import ed25519, index, jsonr, keys, minisig, model, package, pever, reminders, signer, vectors, verify  # noqa
from pes6pkg import cli, publish  # noqa: E402
from pes6pkg.ghcli import DRY, LOCAL, REAL, Gh, Runner  # noqa: E402

INTEROP = HERE / 'data' / 'interop'


def fake_pe(version, extra=b''):
    """Bytes con un recurso de versión como el de un .dll de VS 2019 (lo que lee pever)."""
    a, b, c, d = model.parse_version(version)
    ms, ls = (a << 16) | b, (c << 16) | d
    key = 'VS_VERSION_INFO'.encode('utf-16-le') + b'\0\0'
    blob = b'MZ' + b'\0' * 62 + struct.pack('<HHH', 0x34C, 0x34, 0) + key
    blob += b'\0' * ((4 - len(blob) % 4) % 4)
    blob += struct.pack('<13I', 0xFEEF04BD, 0x00010000, ms, ls, ms, ls, 0x3F, 0, 0x40004, 2, 0, 0, 0)
    return blob + extra


class Crypto(unittest.TestCase):
    def test_rfc8032(self):
        sk = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
        self.assertEqual(ed25519.public_key(sk).hex(),
                         'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        sig = ed25519.sign(sk, b'')
        self.assertEqual(sig.hex()[:32], 'e5564300c360ac729086e2cc806e828a')
        self.assertTrue(ed25519.verify(ed25519.public_key(sk), b'', sig))
        self.assertFalse(ed25519.verify(ed25519.public_key(sk), b'\0', sig))

    def test_interop_minisign_real(self):
        pub = minisig.parse_public_key((INTEROP / 'interop.pub').read_text(encoding='utf-8'))
        data = (INTEROP / 'interop.json').read_bytes()
        sig = (INTEROP / 'interop.json.minisig').read_text(encoding='utf-8')
        self.assertEqual(minisig.verify(data, sig, [pub]), (0, 'pes6pkg interop 1'))
        with self.assertRaises(minisig.MinisigError) as e:
            minisig.verify(data + b' ', sig, [pub])
        self.assertEqual(e.exception.code, 'E_BAD_SIGNATURE')

    def test_crlf_minisig(self):
        pub = minisig.parse_public_key((INTEROP / 'interop.pub').read_text(encoding='utf-8'))
        sig = (INTEROP / 'interop.json.minisig').read_text(encoding='utf-8').replace('\n', '\r\n')
        self.assertEqual(minisig.verify((INTEROP / 'interop.json').read_bytes(), sig, [pub])[1], 'pes6pkg interop 1')

    def test_secret_key_encryption_flag(self):
        enc = 'untrusted comment: x\n' + base64.b64encode(b'EdScB2' + b'\0' * 152).decode() + '\n'
        plain = 'untrusted comment: x\n' + base64.b64encode(b'Ed\0\0B2' + b'\0' * 152).decode() + '\n'
        self.assertTrue(minisig.secret_key_is_encrypted(enc))
        self.assertFalse(minisig.secret_key_is_encrypted(plain))

    def test_test_key_roundtrip_and_mark(self):
        k = minisig.TestKey.derive('k1')
        s = k.sign(b'hola', 'pes6pkg index 1')
        self.assertIn(minisig.TEST_MARK, s)
        self.assertEqual(minisig.verify(b'hola', s, [k.public])[1], 'pes6pkg index 1')


class Json(unittest.TestCase):
    def test_accepts(self):
        self.assertEqual(jsonr.loads(b'{"a": [1, true, "x\\n\\u00e9"], "b": {}}'), {'a': [1, True, 'x\né'], 'b': {}})

    def test_rejects(self):
        for bad in (b'{"a": null}', b'{"a": 1.5}', b'{"a": -1}', b'{"a": 1e3}', b'{"a": 1, "a": 2}',
                    b'\xef\xbb\xbf{}', b'{}\r\n', b'{"a": 01}', b'{"a": "\\x"}', b'{"a": "\\ud800"}', b'{} {}',
                    b'[[[[[1]]]]]', b'{"a": "\x01"}', b'', b'{"a": 9007199254740993}'):
            with self.assertRaises(jsonr.JsonError, msg=bad):
                jsonr.loads(bad)

    def test_dumps_roundtrip(self):
        doc = {'type': 'x', 'n': 3, 'l': ['Русский', True]}
        self.assertEqual(jsonr.loads(jsonr.dumps(doc)), doc)
        self.assertNotIn(b'\r', jsonr.dumps(doc))
        with self.assertRaises(jsonr.JsonError):
            jsonr.dumps({'a': None})


class Model(unittest.TestCase):
    def test_versions(self):
        self.assertEqual(model.compare_versions('1.0.2', '1.0.2.0'), 0)
        self.assertLess(model.compare_versions('1.0.1.2', '1.0.2'), 0)
        self.assertGreater(model.compare_versions('1.0.2.1', '1.0.2'), 0)
        for bad in ('1.02', '1.0.2.3.4', '', 'v1', '1.65536', '1..2'):
            self.assertIsNone(model.parse_version(bad), bad)

    def test_paths(self):
        for ok in ('Kitserver/hdtext.exe', 'dat/ru_text.afs', 'README.txt'):
            self.assertTrue(model.valid_path(ok), ok)
        for bad in ('Kitserver/../x', '/x', 'C:/x', 'a\\b', 'Kitserver/NUL.dll', 'Kitserver/x.', 'Kitserver/x ',
                    'a//b', 'Kitserver/com1'):
            self.assertFalse(model.valid_path(bad), bad)

    def test_allowed(self):
        self.assertTrue(model.path_allowed('hdtext', 'Kitserver/GDB/fonts/HD_teko.bin'))
        self.assertTrue(model.path_allowed('hdtext', 'kitserver/hdtext.EXE'))
        self.assertFalse(model.path_allowed('hdtext', 'Kitserver/kload.cfg'))
        self.assertFalse(model.path_allowed('hdtext', 'Kitserver/hdtext.cfg'))
        self.assertFalse(model.path_allowed('hdtext', 'Kitserver/dat/0_text.afs/unnamed_53_x.bin'))
        self.assertFalse(model.path_allowed('hdtext', 'Kitserver/GDB/fonts/backup/HD_x.bin'))
        self.assertTrue(model.path_allowed('translation-pt-br', 'dat/pt-br_text.afs'))
        self.assertFalse(model.path_allowed('translation-ru', 'dat/e_text.afs'))
        self.assertFalse(model.path_allowed('translation-ru', 'Kitserver/translations.dll'))
        self.assertFalse(model.path_allowed('translation-e', 'dat/e_text.afs'))
        self.assertFalse(model.path_allowed('hdtext', 'Kitserver/pes6pkg/installed/hdtext.json'))
        self.assertTrue(model.path_allowed('hdtext', 'README.txt', install=False))
        self.assertFalse(model.path_allowed('hdtext', 'Kitserver/README.txt', install=False))
        # documentos por carpeta: Docs/<id del paquete>/, un nivel, solo la propia
        self.assertTrue(model.path_allowed('translation-ru', 'Docs/translation-ru/LEEME.txt', install=False))
        self.assertTrue(model.path_allowed('translations', 'docs/TRANSLATIONS/README.md', install=False))
        self.assertFalse(model.path_allowed('translation-ru', 'Docs/translations/README.txt', install=False))
        self.assertFalse(model.path_allowed('translation-ru', 'Docs/translation-ru/sub/README.txt', install=False))
        self.assertFalse(model.path_allowed('translation-ru', 'Docs/translation-ru/x.dll', install=False))
        self.assertFalse(model.path_allowed('translation-ru', 'Docs/translation-ru/README.txt', install=True))

    def test_urls(self):
        self.assertTrue(model.url_allowed('https://github.com/angelballay/pes6-hd-text/releases/download/v1/x.zip'))
        for bad in ('https://example.com/x.zip', 'http://github.com/angelballay/pes6-hd-text/releases/download/x',
                    'https://github.com/angelballay/pes6-hd-text/releases/download/x.zip?y=1',
                    'https://user@github.com/angelballay/pes6-hd-text/releases/download/x'):
            self.assertFalse(model.url_allowed(bad), bad)


class Vectors(unittest.TestCase):
    def test_all_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            n = vectors.generate(tmp)
            cases, ring = vectors.load_cases(tmp)
            self.assertEqual(n, len(cases))
            for c in cases:
                with self.subTest(c['name']):
                    self.assertEqual(vectors.run_case(c, tmp, ring)[0], c['expect'])

    def test_deterministic(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            vectors.generate(a)
            vectors.generate(b)
            self.assertEqual((Path(a) / 'cases.json').read_bytes(), (Path(b) / 'cases.json').read_bytes())
            self.assertEqual((Path(a) / 'idx_ok.json.minisig').read_bytes(), (Path(b) / 'idx_ok.json.minisig').read_bytes())


class Pe(unittest.TestCase):
    def test_fake(self):
        self.assertEqual(pever.read_versions(fake_pe('1.0.2')), ((1, 0, 2, 0), (1, 0, 2, 0)))
        self.assertIsNone(pever.read_versions(b'MZ' + b'\0' * 100))


def hd_folder(root: Path, version='1.0.2', ring=None, dll_extra=None):
    ring = ring or keys.load_test()
    keybytes = b''.join(k.key for k in ring.embedded())
    (root / 'Kitserver' / 'GDB' / 'fonts' / 'licenses').mkdir(parents=True)
    (root / 'Kitserver' / 'pes6_hd_text.dll').write_bytes(fake_pe(version, keybytes if dll_extra is None else dll_extra))
    (root / 'Kitserver' / 'hdtext.exe').write_bytes(fake_pe(version, keybytes))
    (root / 'Kitserver' / 'GDB' / 'fonts' / 'HD_teko.bin').write_bytes(b'fuente' * 1000)
    (root / 'Kitserver' / 'GDB' / 'fonts' / 'FONT_LICENSES.txt').write_text('licencias')
    (root / 'Kitserver' / 'GDB' / 'fonts' / 'licenses' / 'OFL_teko.txt').write_text('OFL')
    for n in ('README.txt', 'LEEME.txt', 'CHANGELOG.md', 'LICENSE.txt'):
        (root / n).write_text(n)


class Build(unittest.TestCase):
    def setUp(self):
        self.ring = keys.load_test()
        self.signer = signer.TestSigner(self.ring.signing[self.ring.keys[0].key_id])

    def build(self, src, out, version='1.0.2', **kw):
        with redirect_stdout(io.StringIO()):
            return package.build(cli.REPO, 'hdtext', version, src, out, self.signer, self.ring, '2026-12-05', **kw)

    def test_build_check_and_determinism(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'src'
            hd_folder(src)
            _, a = self.build(src, Path(tmp) / 'a')
            _, b = self.build(src, Path(tmp) / 'b')
            self.assertEqual(a['archive']['sha256'], b['archive']['sha256'])
            with redirect_stdout(io.StringIO()):
                info, doc = cli._check_dir(Path(tmp) / 'a' / 'hdtext' / '1.0.2', self.ring, use_minisign=False)
            self.assertEqual(len(doc['files']), 9)
            with zipfile.ZipFile(Path(tmp) / 'a' / 'hdtext' / '1.0.2' / 'PES6_HD_Text_v1.0.2.zip') as z:
                self.assertIn('Kitserver/pes6pkg/installed/hdtext.json.minisig', z.namelist())

    def test_version_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'src'
            hd_folder(src, version='1.0.2')
            with self.assertRaises(SystemExit) as e:
                self.build(src, Path(tmp) / 'o', version='1.0.3')
            self.assertIn('PUB-4', str(e.exception))

    def test_binary_without_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'src'
            hd_folder(src, dll_extra=b'')
            with self.assertRaises(SystemExit) as e:
                self.build(src, Path(tmp) / 'o')
            self.assertIn('no trae la clave', str(e.exception))

    def test_translation_recipe_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Path(tmp) / 'packages'
            rec.mkdir()
            (rec / 'translation-ru.json').write_text(json.dumps({
                'recipe': 'pes6pkg-recipe/1', 'package': 'translation-ru', 'name': 'Русский',
                'release': {'repo': 'angelballay/pes6xlife-translations', 'tag': 'ru-v{version}',
                            'archive': 'PES6_Translation_ru_v{version}.zip'},
                'requires': [{'package': 'hdtext', 'min': '1.0.2'}, {'package': 'translations', 'min': '1.0'}],
                'files': [{'path': 'dat/ru_text.afs', 'install': True}, {'path': 'README.txt', 'install': False}]}))
            src = Path(tmp) / 'src'
            (src / 'dat').mkdir(parents=True)
            (src / 'dat' / 'ru_text.afs').write_bytes(b'AFS\0' * 1000)
            (src / 'README.txt').write_text('x')
            (src / 'Kitserver').mkdir()
            (src / 'Kitserver' / 'translations.dll').write_bytes(b'MZ')  # sobra: no va en el zip de idioma
            out = io.StringIO()
            with redirect_stdout(out):
                _, info = package.build(cli.REPO, 'translation-ru', '1.0', src, Path(tmp) / 'o', self.signer, self.ring,
                                        '2026-12-05', recipes_dir=rec)
            self.assertIn('Kitserver/translations.dll está en la carpeta pero no en la receta', out.getvalue())
            with zipfile.ZipFile(Path(tmp) / 'o' / 'translation-ru' / '1.0' / info['archive']['name']) as z:
                self.assertNotIn('Kitserver/translations.dll', z.namelist())
            self.assertEqual(info['tag'], 'ru-v1.0')


class Index(unittest.TestCase):
    def test_next_and_sign(self):
        ring = keys.load_test()
        sg = signer.TestSigner(ring.signing[ring.keys[0].key_id])
        now = datetime(2026, 12, 5, 21, 30, tzinfo=timezone.utc)
        first = index.next_index(None, now)
        self.assertEqual((first['serial'], first['expires']), (1, '2027-03-05T21:30:00Z'))
        entry = vectors._Gen.index_doc(None)['packages'][0]
        second = index.next_index(first, now, [entry])
        self.assertEqual(second['serial'], 2)
        data, sig = index.sign(second, sg, ring)
        doc, _, st = verify.check_index(data, sig, ring.keys, verify.State(), now)
        self.assertEqual(st.index_serial, 2)
        with self.assertRaises(SystemExit):
            index.next_index(second, now, [dict(entry, version='1.0.1')])
        with self.assertRaises(SystemExit):
            index.next_index(second, now, days=181)


class FakeGh:
    def __init__(self):
        self.issues, self.calls, self.n = [], [], 0

    def issues_open(self, repo, label):
        return [dict(i) for i in self.issues if i['open']]

    def issue_comments(self, repo, number):
        return next(i for i in self.issues if i['number'] == number)['comments']

    def issue_create(self, repo, title, body, label, assignee):
        self.n += 1
        self.issues.append({'number': self.n, 'title': title, 'body': body, 'comments': [], 'open': True})
        self.calls.append(('create', title, assignee))

    def issue_comment(self, repo, number, body):
        next(i for i in self.issues if i['number'] == number)['comments'].append(body)
        self.calls.append(('comment', number))

    def issue_close(self, repo, number, comment):
        next(i for i in self.issues if i['number'] == number)['open'] = False
        self.calls.append(('close', number))

    def workflow_enable(self, repo, wf):
        self.calls.append(('enable', wf))


class Reminders(unittest.TestCase):
    EXP = datetime(2027, 3, 5, 21, 30, tzinfo=timezone.utc)

    def day(self, n):
        return date(2027, 3, 5).fromordinal(date(2027, 3, 5).toordinal() - n)

    def test_schedule(self):
        gh = FakeGh()
        did = [(n, reminders.run(gh, 'o/r', 'dueño', self.EXP, self.day(n))) for n in range(32, -3, -1)]
        acts = {n: d for n, d in did if d != 'nada'}
        self.assertEqual(acts, {30: 'creado', 21: 'comentado', 14: 'comentado', 7: 'comentado', 3: 'comentado',
                                1: 'comentado', 0: 'comentado', -1: 'comentado', -2: 'comentado'})
        self.assertEqual(next(c for c in gh.calls if c[0] == 'create'), ('create', 'El índice vence el 2027-03-05', 'dueño'))
        self.assertIn('@dueño', gh.issues[0]['body'])
        self.assertTrue(all(c[0] in ('create', 'comment', 'enable') for c in gh.calls))
        self.assertEqual(sum(1 for c in gh.calls if c[0] == 'enable'), len(did))

    def test_same_day_once_and_late_start(self):
        gh = FakeGh()
        reminders.run(gh, 'o/r', 'd', self.EXP, self.day(25))  # la CI estuvo apagada a los 30: avisa igual
        self.assertEqual(gh.calls[0][0], 'create')
        self.assertEqual(reminders.run(gh, 'o/r', 'd', self.EXP, self.day(21)), 'comentado')
        self.assertEqual(reminders.run(gh, 'o/r', 'd', self.EXP, self.day(21)), 'nada')

    def test_renewed_closes(self):
        gh = FakeGh()
        reminders.run(gh, 'o/r', 'd', self.EXP, self.day(10))
        new = datetime(2027, 6, 1, tzinfo=timezone.utc)
        self.assertEqual(reminders.run(gh, 'o/r', 'd', new, date(2027, 3, 1)), 'cerrado')
        self.assertFalse(gh.issues[0]['open'])

    def test_banner_and_ics(self):
        self.assertIsNone(reminders.banner(self.EXP, self.day(31)))
        self.assertIn('faltan 12 días', reminders.banner(self.EXP, self.day(12)))
        self.assertTrue(reminders.banner(self.EXP, self.day(-1)).startswith('VENCIDO'))
        ics = reminders.ics(self.EXP, 10)
        self.assertEqual([ln for ln in ics.split('\r\n') if ln.startswith('DTSTART')],
                         ['DTSTART;VALUE=DATE:20270203', 'DTSTART;VALUE=DATE:20270219',
                          'DTSTART;VALUE=DATE:20270226', 'DTSTART;VALUE=DATE:20270304'])


class Cli(unittest.TestCase):
    def test_keys_export_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'k.h'
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                cli.main(['--test-keys', 'keys', 'export', '--out', str(out)])
            text = out.read_text(encoding='utf-8')
            self.assertIn('TEST_KEYS[]', text)
            self.assertIn('CLAVES DE PRUEBA', text)

    def test_renew_first_simulated(self):
        real = cli.REPO / 'index' / 'index.json'
        before = real.read_bytes() if real.exists() else None
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                cli.main(['--test-keys', 'renew', '--first', '--out', tmp])
            idx = Path(tmp) / 'simulado' / 'index' / 'index.json'
            ring = keys.load_test()
            doc, _, st = verify.check_index(idx.read_bytes(), (idx.parent / 'index.json.minisig').read_text(encoding='utf-8'),
                                            ring.keys, verify.State(), cli.now_utc())
            self.assertEqual(doc['serial'], 1)
            self.assertIn('no se tocó git', out.getvalue())
            # el .ics de un simulacro no pisa el real de out/
            self.assertTrue(list((Path(tmp) / 'simulado').glob('recordatorios-indice-1.ics')))
            self.assertFalse(list(Path(tmp).glob('recordatorios-indice-1.ics')))
            self.assertEqual(real.read_bytes() if real.exists() else None, before)

    def test_test_keys_never_mix_with_real_builds(self):
        """Con claves de prueba, out/ por defecto es out/prueba/, y un paquete real no entra a un simulacro."""
        import argparse
        self.assertEqual(cli.out_dir(argparse.Namespace(out=None, test_keys=True)), cli.REPO / 'out' / 'prueba')
        self.assertEqual(cli.out_dir(argparse.Namespace(out=None, test_keys=False)), cli.REPO / 'out')
        with self.assertRaises(SystemExit) as e, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            cli.main(['--test-keys', 'release', 'hdtext', '1.0.2', '--dry-run'])
        self.assertIn(str(Path('out') / 'prueba' / 'hdtext'), str(e.exception))

    def test_test_keys_after_subcommand(self):
        with tempfile.TemporaryDirectory() as tmp:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                cli.main(['renew', '--first', '--test-keys', '--out', tmp])
            self.assertTrue((Path(tmp) / 'simulado' / 'index' / 'index.json').exists())

    def test_signer_refuses_key_in_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / '.git').mkdir()
            k = Path(tmp) / 'k1.key'
            k.write_text('untrusted comment: x\n' + base64.b64encode(b'EdScB2' + b'\0' * 152).decode() + '\n')
            with self.assertRaises(SystemExit) as e:
                signer.MinisignSigner(k, keys.load_test().keys[0], minisign_exe='minisign')
            self.assertIn('dentro del repo', str(e.exception))

    def test_signer_refuses_plain_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            k = Path(tmp) / 'k1.key'
            k.write_text('untrusted comment: x\n' + base64.b64encode(b'Ed\0\0B2' + b'\0' * 152).decode() + '\n')
            with self.assertRaises(SystemExit) as e:
                signer.MinisignSigner(k, keys.load_test().keys[0], minisign_exe='minisign')
            self.assertIn('no está cifrada', str(e.exception))


class Rotate(unittest.TestCase):
    def test_meta(self):
        data = {'keys': [{'id': 'A', 'file': 'k1.pub', 'role': 'uso', 'created': 'x'},
                         {'id': 'B', 'file': 'k2.pub', 'role': 'reserva', 'created': 'x'}]}
        out = keys.rotate_meta(data, 'k3.pub', 'C', '2027-01-01')
        self.assertEqual([e['role'] for e in out['keys']], ['revocada', 'uso', 'reserva'])
        self.assertEqual(out['keys'][0]['revoked'], '2027-01-01')
        ring = keys.Keyring([], [e['role'] for e in out['keys']], False, {}, [e['file'] for e in out['keys']])
        self.assertEqual(ring.secret_name('uso'), 'k2.key')
        again = keys.rotate_meta(out, 'k4.pub', 'D', '2027-06-01')
        self.assertEqual([e['role'] for e in again['keys']], ['revocada', 'revocada', 'uso', 'reserva'])


class CiCheck(unittest.TestCase):
    def test_problems(self):
        ring = keys.load_test()
        sg = signer.TestSigner(ring.signing[ring.keys[0].key_id])
        now = datetime(2026, 12, 5, 21, 30, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = index.next_index(None, now)
            base_data, sig = index.sign(first, sg, ring)
            index.write(root, base_data, sig)
            self.assertEqual(cli.ci_problems(root, ['README.md'], None, ring, now, True), [])
            self.assertIn('binario en el repo: out/x.zip', cli.ci_problems(root, ['out/x.zip'], None, ring, now, False))
            # serial salteado
            third = dict(index.next_index(first, now), serial=3)
            d3, s3 = index.sign(third, sg, ring)
            index.write(root, d3, s3)
            self.assertTrue(any('serial' in p for p in cli.ci_problems(root, [], base_data, ring, now, True)))
            # manifiesto que falta en manifests/
            entry = vectors._Gen.index_doc(None)['packages'][0]
            second = index.next_index(first, now, [entry])
            d2, s2 = index.sign(second, sg, ring)
            index.write(root, d2, s2)
            probs = [p.replace(chr(92), '/') for p in cli.ci_problems(root, [], base_data, ring, now, True)]
            self.assertTrue(any('falta manifests' in p for p in probs), probs)
            # firma rota
            (root / 'index' / 'index.json').write_bytes(d2.replace(b'"serial": 2', b'"serial": 2 '))
            self.assertTrue(any('no pasa' in p for p in cli.ci_problems(root, [], base_data, ring, now, True)))


class CiUrls(unittest.TestCase):
    def test_url_outside_prefixes(self):
        ring = keys.load_test()
        sg = signer.TestSigner(ring.signing[ring.keys[0].key_id])
        now = datetime(2026, 12, 5, 21, 30, tzinfo=timezone.utc)
        entry = vectors._Gen.index_doc(None)['packages'][0]
        entry = dict(entry, archive=dict(entry['archive'], url='https://github.com/otro/repo/releases/download/v1/x.zip'))
        with tempfile.TemporaryDirectory() as tmp:
            data, sig = index.sign(index.next_index(None, now, [entry]), sg, ring)
            index.write(Path(tmp), data, sig)
            probs = cli.ci_problems(Path(tmp), [], None, ring, now, True)
            self.assertTrue(any('otro/repo' in p and 'permitidas' in p for p in probs), probs)


class RunnerModes(unittest.TestCase):
    def test_modes(self):
        cmd = [sys.executable, '-c', 'print("hola")']
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(Runner(DRY)(cmd, read=True).strip(), 'hola')  # simulado: las lecturas corren
            self.assertEqual(Runner(DRY)(cmd), '')  # y las escrituras no
            self.assertEqual(Runner(LOCAL)(cmd, read=True), '')  # local: nada corre
            self.assertEqual(Runner(LOCAL)(cmd, read=True, binary=True), b'')
            self.assertEqual(Runner(REAL)(cmd).strip(), 'hola')
        self.assertIn('(simulado)', out.getvalue())
        self.assertIn('  $ ', out.getvalue())  # en modo real se ve cada escritura
        self.assertEqual((Runner(True).mode, Runner(False).mode), (DRY, REAL))

    def test_gh_argv(self):
        """Lo que se le pide a gh 2.101 (docs/RECETA.md, "Qué hace cada paso"): borrador con un solo archivo, subir
        aparte, publicar con --draft=false, borrar con --yes; list/view/download/verify-asset son lecturas."""
        calls = []

        class Rec(Runner):
            def __call__(self, argv, **kw):
                calls.append((list(argv), kw.get('read', False)))
                return ''
        gh = Gh(Rec(REAL))
        gh.release_create_draft('o/r', 'v1', 'T', 'n.md', ['a.zip'])
        gh.release_upload('o/r', 'v1', ['m.json', 'm.json.minisig'])
        gh.release_publish('o/r', 'v1')
        gh.release_delete('o/r', 'v1')
        gh.release_list('o/r')
        gh.release_view('o/r', 'v1')
        gh.release_download('o/r', 'v1', 'd')
        gh.verify_asset('o/r', 'v1', 'a.zip')
        by = {c[0][2]: c for c in calls}
        self.assertEqual(by['create'][0][-2:], ['n.md', 'a.zip'])
        self.assertIn('--draft', by['create'][0])
        self.assertEqual(by['upload'][0][-2:], ['m.json', 'm.json.minisig'])
        self.assertIn('--draft=false', by['edit'][0])
        self.assertIn('--yes', by['delete'][0])
        self.assertIn('tagName,isDraft,isImmutable', by['list'][0])
        for k in ('list', 'view', 'download', 'verify-asset'):
            self.assertTrue(by[k][1], k)
        for k in ('create', 'upload', 'edit', 'delete'):
            self.assertFalse(by[k][1], k)


# ---------------------------------------------------------------- publicar: remoto git local + gh falso

GIT_ID = {'GIT_AUTHOR_NAME': 'prueba', 'GIT_AUTHOR_EMAIL': 'prueba@example.invalid',
          'GIT_COMMITTER_NAME': 'prueba', 'GIT_COMMITTER_EMAIL': 'prueba@example.invalid'}
NOW = datetime(2026, 12, 5, 21, 30, tzinfo=timezone.utc)
REPO_T = 'angelballay/pes6xlife-translations'


def git(*a):
    r = subprocess.run(['git', *a], capture_output=True, text=True, encoding='utf-8')
    if r.returncode:
        raise AssertionError(f'git {a}: {r.stderr}')
    return r.stdout


def rm_tree(p):
    def fix(func, path, _):
        os.chmod(path, stat.S_IWRITE)  # los objetos de git son de solo lectura en Windows
        func(path)
    shutil.rmtree(p, **({'onexc': fix} if sys.version_info >= (3, 12) else {'onerror': fix}))


class FakeReleases:
    """gh falso: releases por repo (borradores y publicados), lo que baja un jugador por URL, y los PR. Como con el
    Runner real, en modo simulado las escrituras no cambian nada."""

    def __init__(self, run):
        self.run = run
        self.rel = {}  # (repo, tag) -> [{draft, immutable, assets {nombre: bytes}, states {nombre: estado}}]
        self.calls = []
        self.prs = []
        self.fail_upload = False

    def _write(self, *call):
        self.calls.append(call)
        return self.run.mode == REAL

    def rows(self, repo, tag):
        return self.rel.get((repo, tag), [])

    def found(self, repo, tag):
        """Lo que encuentra gh por tag: el publicado, o el primer borrador."""
        rows = self.rows(repo, tag)
        return next((r for r in rows if not r['draft']), rows[0] if rows else None)

    def count(self, what):
        return sum(1 for c in self.calls if c[0] == what)

    def release_list(self, repo):
        return [{'tagName': t, 'isDraft': r['draft'], 'isImmutable': r['immutable']}
                for (rp, t), rows in self.rel.items() if rp == repo for r in rows]

    def release_view(self, repo, tag):
        r = self.found(repo, tag)
        if r is None:
            raise SystemExit('release not found')
        return {'tagName': tag, 'isDraft': r['draft'], 'isImmutable': r['immutable'],
                'assets': [{'name': n, 'size': len(b), 'state': r['states'].get(n, 'uploaded'), 'digest': None}
                           for n, b in r['assets'].items()]}

    def release_create_draft(self, repo, tag, title, notes_file, files):
        if not self._write('create', repo, tag, [Path(f).name for f in files]):
            return
        if any(not r['draft'] for r in self.rows(repo, tag)):
            raise SystemExit('a release with the same tag name already exists')
        self.rel.setdefault((repo, tag), []).append({'draft': True, 'immutable': False, 'states': {},
                                                     'assets': {Path(f).name: Path(f).read_bytes() for f in files}})

    def release_upload(self, repo, tag, files):
        if not self._write('upload', repo, tag, [Path(f).name for f in files]):
            return
        r = self.found(repo, tag)
        assert r['draft'], 'subió a un release publicado'
        if self.fail_upload:
            r['assets'][Path(files[0]).name] = b'a medias'
            r['states'][Path(files[0]).name] = 'starter'
            raise SystemExit('Falló: gh release upload (se cortó la red)')
        for f in files:
            r['assets'][Path(f).name] = Path(f).read_bytes()

    def release_download(self, repo, tag, directory):
        self.calls.append(('download', repo, tag))
        for n, b in self.found(repo, tag)['assets'].items():
            (Path(directory) / n).write_bytes(b)

    def release_publish(self, repo, tag):
        if not self._write('publish', repo, tag):
            return
        r = self.found(repo, tag)
        r['draft'], r['immutable'] = False, True

    def release_delete(self, repo, tag):
        if not self._write('delete', repo, tag):
            return
        r = self.found(repo, tag)
        assert r['draft'], 'borró un release publicado'
        self.rows(repo, tag).remove(r)

    def verify_asset(self, repo, tag, path):
        self.calls.append(('verify-asset', repo, tag))
        r = self.found(repo, tag)
        ok = r and not r['draft'] and r['immutable'] and r['assets'].get(Path(path).name) == Path(path).read_bytes()
        return f'Verification succeeded! {Path(path).name} is present in release {tag}\n' if ok else ''

    def pr_create(self, repo, branch, title, body):
        if not self._write('pr', repo, branch):
            return ''
        self.prs.append({'repo': repo, 'branch': branch, 'title': title, 'body': body})
        return f'https://github.com/{repo}/pull/{len(self.prs)}\n'

    def public(self, url, limit):
        """Lo que baja un jugador, sin sesión: solo lo publicado."""
        m = re.match(r'^https://github\.com/([^/]+/[^/]+)/releases/download/([^/]+)/([^/]+)$', url)
        r = self.found(m.group(1), m.group(2)) if m else None
        if r is None or r['draft'] or m.group(3) not in r['assets']:
            raise OSError(f'HTTP 404 {url}')
        return r['assets'][m.group(3)]


class CountingSigner:
    """La clave de uso de prueba, contando las firmas. `fail`: cuántas veces falla (contraseña equivocada);
    `during`: algo que pasa mientras se pide la contraseña."""

    def __init__(self, ring, fail=0, during=None):
        self.inner = signer.TestSigner(ring.signing[ring.keys[0].key_id])
        self.public, self.test = self.inner.public, True
        self.n, self.fail, self.during = 0, fail, during

    def sign(self, data, comment):
        self.n += 1
        if self.during:
            self.during()
        if self.fail:
            self.fail -= 1
            raise SystemExit('minisign no pudo firmar (¿contraseña equivocada?). No se cambió nada.')
        return self.inner.sign(data, comment)


def recipes():
    def rel(tag, archive):
        return {'repo': REPO_T, 'tag': tag, 'archive': archive}
    out = {'translations': {
        'recipe': 'pes6pkg-recipe/1', 'package': 'translations', 'name': 'PES6 Translations',
        'release': rel('dll-v{version}', 'PES6_Translations_DLL_v{version}.zip'),
        'requires': [{'package': 'hdtext', 'min': '1.0.2'}],
        'files': [{'path': 'Kitserver/translations.dll', 'install': True, 'pe_version': True},
                  {'path': 'README.txt', 'install': False}]}}
    for code, name in (('ru', 'Русский'), ('el', 'Ελληνικά')):
        out[f'translation-{code}'] = {
            'recipe': 'pes6pkg-recipe/1', 'package': f'translation-{code}', 'name': name,
            'release': rel(f'{code}-v{{version}}', f'PES6_Translation_{code}_v{{version}}.zip'),
            'requires': [{'package': 'hdtext', 'min': '1.0.2'}, {'package': 'translations', 'min': '1.0'}],
            'files': [{'path': f'dat/{code}_text.afs', 'install': True}, {'path': 'README.txt', 'install': False}]}
    return out


def build_day(tmp: Path, ring, out: Path):
    """Los paquetes del día, armados con `ring` (y la clave de uso de prueba) en `out`."""
    rec = tmp / 'recetas'
    rec.mkdir(exist_ok=True)
    for pkg, r in recipes().items():
        (rec / f'{pkg}.json').write_text(json.dumps(r, ensure_ascii=False), encoding='utf-8')
    sg = signer.TestSigner(keys.load_test().signing[ring.keys[0].key_id])
    src = tmp / 'src-translations'
    (src / 'Kitserver').mkdir(parents=True)
    (src / 'Kitserver' / 'translations.dll').write_bytes(fake_pe('1.0'))
    (src / 'README.txt').write_text('dll')
    todo = [('translations', '1.0', src, rec)]
    for code in ('ru', 'el'):
        s = tmp / f'src-{code}'
        (s / 'dat').mkdir(parents=True)
        (s / 'dat' / f'{code}_text.afs').write_bytes(b'AFS\0' + code.encode() * 500)
        (s / 'README.txt').write_text(code)
        todo.append((f'translation-{code}', '1.0', s, rec))
    if ring.test:
        hd_folder(tmp / 'src-hd', ring=ring)
        todo.append(('hdtext', '1.0.2', tmp / 'src-hd', None))
    with redirect_stdout(io.StringIO()):
        for pkg, ver, s, r in todo:
            package.build(cli.REPO, pkg, ver, s, out, sg, ring, '2026-12-05', recipes_dir=r)


class Publicar(unittest.TestCase):
    """release --no-index, index add, retomar, descartar y completar, contra un repo central en un git local (bare) y
    un gh falso, con las claves de prueba."""
    DAY = ['translations@1.0', 'translation-ru@1.0', 'translation-el@1.0', 'hdtext@1.0.2']

    @classmethod
    def setUpClass(cls):
        cls._env = {k: os.environ.get(k) for k in GIT_ID}
        os.environ.update(GIT_ID)

    @classmethod
    def tearDownClass(cls):
        for k, v in cls._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='pes6pkg-prueba-'))
        self.addCleanup(rm_tree, self.tmp)
        self.ring = keys.load_test()
        self.sg = CountingSigner(self.ring)
        self.out = self.tmp / 'out'
        build_day(self.tmp, self.ring, self.out)
        self.bare, self.clone = self.make_central()
        self.run = Runner(REAL)
        self.run.echo = False
        self.gh = FakeReleases(self.run)

    def make_central(self):
        """main con el índice 1 firmado, como el repo real hoy; y el clon de quien publica."""
        bare = self.tmp / 'central.git'
        git('init', '--quiet', '--bare', '-b', 'main', str(bare))
        seed = self.tmp / 'semilla'
        git('clone', '--quiet', str(bare), str(seed))
        (seed / '.gitattributes').write_bytes(b'index/** -text\nmanifests/** -text\n')
        data, sig = index.sign(index.next_index(None, NOW - timedelta(days=1)),
                               signer.TestSigner(self.ring.signing[self.ring.keys[0].key_id]), self.ring)
        index.write(seed, data, sig)
        git('-C', str(seed), 'add', '.')
        git('-C', str(seed), 'commit', '--quiet', '-m', 'Índice 1')
        git('-C', str(seed), 'push', '--quiet', 'origin', 'HEAD:main')
        clone = self.tmp / 'clon'
        git('clone', '--quiet', str(bare), str(clone))
        return bare, clone

    def pub(self, ask='sí', signer_=None, run=None, ring=None, out=None, make_signer=None, precheck=None, url=None):
        run = run or self.run
        self.gh.run = run
        central = publish.Central(publish.CENTRAL, self.clone, run, url=str(self.bare) if url is None else url)
        return publish.Publisher(ring or self.ring, run, self.gh, central, out or self.out,
                                 make_signer or (lambda: signer_ or self.sg), lambda: NOW,
                                 ask=lambda prompt: ask == 'sí', fetch=self.gh.public, precheck=precheck)

    # -- ayudas
    def say(self, fn, *a):
        out = io.StringIO()
        with redirect_stdout(out):
            fn(*a)
        return out.getvalue()

    def fails(self, fn, *a):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit) as e:
            fn(*a)
        return str(e.exception), out.getvalue()

    def notes(self, tmp):
        p = Path(tmp) / 'notas.md'
        p.write_text('notas', encoding='utf-8')
        return p

    def release(self, pub, spec, with_index=False):
        p, v = spec.split('@')
        return self.say(pub.release, p, v, self.notes, with_index)

    def remote_index(self, ref='main'):
        return jsonr.loads(subprocess.run(['git', '-C', str(self.bare), 'show', f'{ref}:index/index.json'],
                                          capture_output=True).stdout)

    def branches(self):
        return git('-C', str(self.bare), 'branch', '--format=%(refname:short)').split()

    def merge(self, branch):
        git('-C', str(self.bare), 'update-ref', 'refs/heads/main', f'refs/heads/{branch}')

    def published(self, tag, repo=REPO_T):
        r = self.gh.found(repo, tag)
        return bool(r) and not r['draft']

    # -- el día de la publicación
    def test_lote_un_indice_una_firma_un_pr(self):
        pub = self.pub()
        for spec in self.DAY:
            self.assertIn('Falta el índice', self.release(pub, spec))
        self.assertEqual((self.sg.n, self.gh.prs, self.remote_index()['serial']), (0, [], 1))  # sin contraseña ni PR
        creates = [c for c in self.gh.calls if c[0] == 'create']
        self.assertEqual(len(creates), 4)
        self.assertTrue(all(c[3] == [c[3][0]] and c[3][0].endswith('.zip') for c in creates))  # el zip solo, primero
        self.assertEqual(self.gh.count('upload'), 4)

        out = self.say(pub.index_add, self.DAY)
        self.assertEqual(self.sg.n, 1)
        self.assertEqual([p['branch'] for p in self.gh.prs], ['publicar/indice-2'])
        self.assertIn('Índice 2: 4 paquetes', self.gh.prs[0]['title'])
        self.assertEqual(out.count('gh release verify-asset: bien.'), 4)
        doc = self.remote_index('publicar/indice-2')
        self.assertEqual(doc['serial'], 2)
        self.assertEqual(sorted(e['package'] for e in doc['packages']), sorted(s.split('@')[0] for s in self.DAY))
        # la rama pasa lo mismo que la CI: serial = main + 1, firma, manifiestos copiados byte a byte
        chk = self.tmp / 'chk'
        git('clone', '--quiet', '-b', 'publicar/indice-2', str(self.bare), str(chk))
        base = subprocess.run(['git', '-C', str(self.bare), 'show', 'main:index/index.json'], capture_output=True).stdout
        self.assertEqual(publish.ci_problems(chk, git('-C', str(chk), 'ls-files').split(), base, self.ring, NOW, True),
                         [])
        # el checkout de quien publica no se tocó (el PR se armó en un worktree temporal)
        self.assertEqual(git('-C', str(self.clone), 'status', '--porcelain'), '')
        self.assertEqual(jsonr.loads((self.clone / 'index' / 'index.json').read_bytes())['serial'], 1)
        self.assertNotIn('arbol', git('-C', str(self.clone), 'worktree', 'list'))

    def test_prev_sale_de_origin_main(self):
        """Con el PR del índice 2 mergeado y el checkout viejo, el siguiente sale de main: serial 3, con los dos."""
        pub = self.pub()
        self.release(pub, 'translations@1.0')
        self.say(pub.index_add, ['translations@1.0'])
        self.merge('publicar/indice-2')
        self.release(pub, 'translation-ru@1.0')
        self.say(pub.index_add, ['translation-ru@1.0'])
        self.assertEqual(self.gh.prs[-1]['branch'], 'publicar/indice-3')
        doc = self.remote_index('publicar/indice-3')
        self.assertEqual((doc['serial'], sorted(e['package'] for e in doc['packages'])),
                         (3, ['translation-ru', 'translations']))
        self.assertEqual(jsonr.loads((self.clone / 'index' / 'index.json').read_bytes())['serial'], 1)

    def test_contrasena_equivocada_no_publica_y_se_retoma(self):
        bad = CountingSigner(self.ring, fail=1)
        msg, _ = self.fails(self.pub(signer_=bad).release, 'translations', '1.0', self.notes, True)
        self.assertIn('No se publicó nada', msg)
        self.assertIn('retoma el borrador', msg)
        self.assertFalse(self.published('dll-v1.0'))
        self.assertEqual(self.gh.prs, [])
        out = self.release(self.pub(signer_=bad), 'translations@1.0', with_index=True)
        self.assertIn('Retomo el borrador', out)
        self.assertEqual(self.gh.count('create'), 1)  # no lo volvió a subir
        self.assertTrue(self.published('dll-v1.0'))
        self.assertEqual([p['branch'] for p in self.gh.prs], ['publicar/indice-2'])

    def test_contestar_no_deja_un_borrador_que_se_retoma(self):
        out = self.release(self.pub(ask='no'), 'translations@1.0', with_index=True)
        self.assertIn('Quedó en borrador', out)
        self.assertIn('pes6pkg --test-keys release translations 1.0 --discard', out)
        self.assertEqual(self.sg.n, 0)  # no pidió la contraseña
        self.assertFalse(self.published('dll-v1.0'))
        out = self.release(self.pub(), 'translations@1.0', with_index=True)
        self.assertIn('Retomo el borrador', out)
        self.assertTrue(self.published('dll-v1.0'))
        self.assertEqual(len(self.gh.prs), 1)

    def test_borrador_a_medias_se_rehace(self):
        self.gh.fail_upload = True
        self.fails(self.pub().release, 'translations', '1.0', self.notes, False)
        self.gh.fail_upload = False
        out = self.release(self.pub(), 'translations@1.0')
        self.assertIn('lo rehago', out)
        self.assertEqual(len(self.gh.rows(REPO_T, 'dll-v1.0')), 1)
        self.assertTrue(self.published('dll-v1.0'))

    def test_discard(self):
        pub = self.pub(ask='no')
        self.release(pub, 'translations@1.0')
        self.assertIn('Borrado el borrador dll-v1.0', self.say(pub.discard, 'translations', '1.0'))
        self.assertEqual(self.gh.release_list(REPO_T), [])
        self.assertIn('nada que descartar', self.say(pub.discard, 'translations', '1.0'))
        self.release(self.pub(), 'translations@1.0')
        msg, _ = self.fails(pub.discard, 'translations', '1.0')
        self.assertIn('no se descarta', msg)
        self.assertIn('index add translations@1.0', msg)
        self.assertTrue(self.published('dll-v1.0'))

    def test_publicado_sin_indice_se_completa(self):
        pub = self.pub()
        self.release(pub, 'translations@1.0')  # --no-index
        out = self.release(pub, 'translations@1.0', with_index=True)
        self.assertIn('completo el índice', out)
        self.assertEqual((self.gh.count('publish'), self.gh.count('create'), len(self.gh.prs)), (1, 1, 1))
        # mientras el PR no se mergea, un segundo intento no abre otro
        msg, _ = self.fails(pub.release, 'translations', '1.0', self.notes, True)
        self.assertIn('Ya hay una rama publicar/indice-2', msg)
        self.merge('publicar/indice-2')
        self.assertIn('Nada que hacer', self.release(pub, 'translations@1.0', with_index=True))
        self.assertIn('Nada que hacer', self.say(pub.index_add, ['translations@1.0']))
        self.assertEqual(self.sg.n, 1)

    def test_index_add_no_firma_si_falta_alguno(self):
        pub = self.pub()
        self.release(pub, 'translations@1.0')
        self.release(self.pub(ask='no'), 'translation-ru@1.0')  # borrador
        msg, out = self.fails(pub.index_add, ['translations@1.0', 'translation-ru@1.0', 'translation-el@1.0'])
        self.assertIn('2 de 3 paquetes no están listos', msg)
        self.assertIn('ru-v1.0 está en borrador', out)
        self.assertIn('release translation-el 1.0 --no-index', out)
        self.assertEqual((self.sg.n, self.gh.prs, self.branches()), (0, [], ['main']))

    def test_publicado_distinto_no_entra(self):
        pub = self.pub()
        self.release(pub, 'translations@1.0')
        r = self.gh.found(REPO_T, 'dll-v1.0')
        r['assets'][next(n for n in r['assets'] if n.endswith('.zip'))] = b'otra cosa'
        msg, out = self.fails(pub.index_add, ['translations@1.0'])
        self.assertIn('no están listos', msg)
        self.assertIn('no es lo mismo que', out)
        msg, _ = self.fails(pub.release, 'translations', '1.0', self.notes, True)
        self.assertIn('armá una versión nueva', msg)
        self.assertEqual((self.sg.n, self.gh.prs), (0, []))

    def test_main_cambia_mientras_se_firma(self):
        self.release(self.pub(), 'translations@1.0')

        def otro_pr():  # alguien mergea otro índice 2 mientras minisign pide la contraseña
            other = self.tmp / 'otro'
            git('clone', '--quiet', str(self.bare), str(other))
            prev = jsonr.loads((other / 'index' / 'index.json').read_bytes())
            d, s = index.sign(index.next_index(prev, NOW), signer.TestSigner(self.ring.signing[self.ring.keys[0].key_id]),
                              self.ring)
            index.write(other, d, s)
            git('-C', str(other), 'commit', '--quiet', '-am', 'otro índice 2')
            git('-C', str(other), 'push', '--quiet', 'origin', 'HEAD:main')
        msg, _ = self.fails(self.pub(signer_=CountingSigner(self.ring, during=otro_pr)).index_add, ['translations@1.0'])
        self.assertIn('otro PR cambió el índice', msg)
        self.assertEqual((self.branches(), self.gh.prs), (['main'], []))
        # el reintento parte del main nuevo
        self.say(self.pub().index_add, ['translations@1.0'])
        self.assertEqual(self.remote_index('publicar/indice-3')['serial'], 3)

    def test_renew_parte_de_main(self):
        self.say(self.pub().renew)
        doc = self.remote_index('publicar/indice-2')
        self.assertEqual((doc['serial'], doc['packages']), (2, []))
        self.assertIn('Índice 2: renovación', self.gh.prs[0]['title'])

    def test_aviso_si_falta_un_requisito(self):
        pub = self.pub()
        self.release(pub, 'translation-ru@1.0')
        out = self.say(pub.index_add, ['translation-ru@1.0'])
        self.assertIn('AVISO: translation-ru 1.0 pide translations 1.0 o más nueva', out)
        self.assertEqual(len(self.gh.prs), 1)  # avisa, no frena

    def test_entradas_invalidas(self):
        pub = self.pub()
        self.assertIn('<paquete>@<versión>', self.fails(pub.index_add, ['translations'])[0])
        self.assertIn('dos veces', self.fails(pub.index_add, ['translations@1.0', 'translations@1.0'])[0])
        self.assertIn('armalo con', self.fails(pub.index_add, ['translations@9.9'])[0])
        # un build.json que apunta a otro repo: las direcciones no serían de las que aceptan los clientes
        bj = self.out / 'translations' / '1.0' / 'build.json'
        bj.write_text(bj.read_text(encoding='utf-8').replace(REPO_T, 'angelballay/otro'), encoding='utf-8')
        self.assertIn('direcciones que aceptan los clientes', self.fails(pub.index_add, ['translations@1.0'])[0])
        self.assertEqual(self.gh.calls, [])

    def test_origin_ajeno(self):
        msg, _ = self.fails(self.pub(url='https://github.com/otro/repo.git').index_add, ['translations@1.0'])
        self.assertIn('no publico ahí', msg)

    def test_dry_run_con_claves_reales_no_firma_ni_escribe(self):
        """--dry-run con un llavero real (acá, de producción con las claves públicas de prueba): corre las lecturas
        (git fetch, estado en GitHub) pero no sube, no publica, no firma y no pide la contraseña."""
        ring = keys.Keyring(self.ring.keys, ['uso', 'reserva'], False, {}, ['k1.pub', 'k2.pub'])
        out_dir = self.tmp / 'out-real'
        (self.tmp / 'real').mkdir()
        build_day(self.tmp / 'real', ring, out_dir)
        run = Runner(DRY)

        def no_signer():
            raise AssertionError('--dry-run no tiene que abrir la clave')

        def no_ask(prompt):
            raise AssertionError('--dry-run no pregunta')
        pub = self.pub(run=run, ring=ring, out=out_dir, make_signer=no_signer, precheck=lambda: ['no está la clave X'])
        pub.ask = no_ask
        with mock.patch.object(signer, 'find_minisign', return_value=None):
            out = io.StringIO()
            with redirect_stdout(out):
                pub.release('translations', '1.0', self.notes, True)
            msg, out2 = self.fails(pub.index_add, ['translations@1.0'])
        out = out.getvalue()
        self.assertIn('acá minisign pediría la contraseña', out)
        self.assertIn('AVISO para el día real: no está la clave X', out)
        self.assertIn('índice 2 vencería', out)
        self.assertIn('no están listos', msg)  # en simulado no se publicó nada: index add lo dice
        self.assertEqual((self.gh.release_list(REPO_T), self.gh.prs, self.branches()), ([], [], ['main']))
        self.assertTrue(self.gh.count('create'))  # mostró qué haría

    def test_salida_a_un_pipe_con_nombres_no_ascii(self):
        """Con la salida a otro programa (cp1252 en Windows), «Русский» no corta el comando."""
        r = subprocess.run([sys.executable, '-I', str(cli.REPO / 'tool' / 'run.py'), '--test-keys', 'release',
                            'translation-ru', '1.0', '--no-index', '--out', str(self.out)], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr.decode('utf-8', 'replace'))
        self.assertIn(b'release ru-v1.0', r.stdout)

    def test_simulacro_local_no_corre_nada(self):
        """--test-keys por la CLI: release e index add sin git, sin gh y sin red; lo firmado va a out/simulado/."""
        out = io.StringIO()
        with mock.patch.object(subprocess, 'run', side_effect=AssertionError('corrió un comando')), \
                mock.patch.object(publish, 'download', side_effect=AssertionError('usó la red')), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            for spec in self.DAY:
                cli.main(['--test-keys', 'release', *spec.split('@'), '--no-index', '--out', str(self.out)])
            cli.main(['--test-keys', 'index', 'add', *self.DAY, '--out', str(self.out)])
        idx = self.out / 'simulado' / 'index' / 'index.json'
        doc, _, _ = verify.check_index(idx.read_bytes(), (idx.parent / 'index.json.minisig').read_text(encoding='utf-8'),
                                       self.ring.keys, verify.State(), cli.now_utc())
        self.assertEqual((doc['serial'], len(doc['packages'])), (1, 4))
        self.assertTrue((self.out / 'simulado' / 'manifests' / 'hdtext' / '1.0.2.manifest.json.minisig').exists())
        self.assertIn('(simulado) gh release create dll-v1.0', out.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=1)
