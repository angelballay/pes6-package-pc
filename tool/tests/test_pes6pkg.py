"""Pruebas de pes6pkg (solo biblioteca estándar): python -I tool/tests/test_pes6pkg.py"""
import base64
import io
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from pes6pkg import ed25519, index, jsonr, keys, minisig, model, package, pever, reminders, signer, vectors, verify  # noqa
from pes6pkg import cli  # noqa: E402

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
            self.assertTrue(list(Path(tmp).glob('recordatorios-indice-1.ics')))
            self.assertFalse((cli.REPO / 'index' / 'index.json').exists())

    def test_release_refuses_test_keys(self):
        with self.assertRaises(SystemExit) as e, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            cli.main(['--test-keys', 'release', 'hdtext', '1.0.2', '--dry-run'])
        self.assertIn('KEY-8', str(e.exception))

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


if __name__ == '__main__':
    unittest.main(verbosity=1)
