"""`pes6pkg`: armar, firmar, publicar y comprobar los paquetes de los mods de PES6 (design §8, docs/RECETA.md)."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import index as index_mod
from . import jsonr, keys, minisig, model, package, reminders, signer, vectors, verify
from .ghcli import Gh, Runner

REPO = Path(__file__).resolve().parents[2]
CENTRAL = 'angelballay/pes6-package-pc'


def now_utc():
    return datetime.now(timezone.utc).replace(microsecond=0)


def say(text=''):
    print(text, flush=True)


# ---------------------------------------------------------------- llaveros y firmadores

def ring_for(args):
    return keys.load_test(('k1', 'k2')) if args.test_keys else keys.load_production(REPO)


def signer_for(args, ring, role='uso'):
    if ring.test:
        k = ring.keys[0] if role == 'uso' else ring.keys[1]
        return signer.TestSigner(ring.signing[k.key_id])
    pub = ring.active() if role == 'uso' else next(k for k, r in zip(ring.keys, ring.roles) if r == role)
    path = Path(args.key) if getattr(args, 'key', None) else signer.default_key_path(ring.secret_name(role))
    return signer.MinisignSigner(path, pub)


def banner(args, end=False):
    try:
        ring = ring_for(args)
        doc = index_mod.load(REPO, ring)
    except SystemExit:
        return
    if doc:
        reminders.print_banner(index_mod.expires_of(doc), now_utc().date(), end)


# ---------------------------------------------------------------- comandos

def cmd_keys(args):
    if args.what == 'export':
        ring = ring_for(args)
        doc = None
        try:
            doc = index_mod.load(REPO, ring)
        except SystemExit:
            pass
        serial = doc['serial'] if doc else 0
        out = Path(args.out) if args.out else REPO / 'client' / ('pes6pkg_test_keys.h' if ring.test else 'pes6pkg_keys.h')
        out.write_text(keys.c_header(ring, serial, now_utc().strftime('%Y-%m-%d'), ring.test), encoding='utf-8',
                       newline='\n')
        say(f'Escrito {out} ({len(ring.embedded())} claves, piso de serial {serial}).')
        return
    exe = signer.find_minisign()
    if args.what == 'check':
        key = Path(args.key)
        ring = keys.load_production(REPO)
        with tempfile.TemporaryDirectory(prefix='pes6pkg-') as tmp:
            f = Path(tmp) / 'prueba.txt'
            f.write_text('simulacro de pes6pkg keys check\n', encoding='utf-8')
            say(f'minisign va a pedir la contraseña de {key}.')
            if subprocess.run([exe, '-S', '-s', str(key), '-m', str(f), '-t', 'pes6pkg keys check']).returncode:
                raise SystemExit('La clave no abrió con esa contraseña.')
            sig = (Path(str(f) + '.minisig')).read_text(encoding='utf-8')
            i, _ = minisig.verify(f.read_bytes(), sig, ring.keys)
        say(f'Bien: {key} abre y firma, y es la clave {ring.keys[i].id_hex} ({ring.roles[i]}). El índice no cambió.')
        return
    if args.what == 'new':
        meta = REPO / 'keys' / 'keys.json'
        if meta.exists():
            raise SystemExit('Ya hay claves en keys/keys.json. Para cambiarlas está `pes6pkg rotate`.')
        home = signer.default_key_path('k1.key').parent
        home.mkdir(parents=True, exist_ok=True)
        k2dir = home / 'k2-para-copiar-fuera-de-linea'
        k2dir.mkdir(exist_ok=True)
        say('Ceremonia de claves. Usá dos contraseñas DISTINTAS, de 5 o 6 palabras al azar.')
        for name, sk in (('k1', home / 'k1.key'), ('k2', k2dir / 'k2.key')):
            say(f'\n== {name}: minisign te pide la contraseña dos veces')
            if subprocess.run([exe, '-G', '-p', str(REPO / 'keys' / f'{name}.pub'), '-s', str(sk)]).returncode:
                raise SystemExit(f'minisign no pudo crear {name}.')
        ring_meta = {'keys': []}
        for name, role in (('k1', 'uso'), ('k2', 'reserva')):
            pk = minisig.parse_public_key((REPO / 'keys' / f'{name}.pub').read_text(encoding='utf-8'))
            ring_meta['keys'].append({'id': pk.id_hex, 'file': f'{name}.pub', 'role': role,
                                      'created': now_utc().strftime('%Y-%m-%d')})
        meta.write_text(json.dumps(ring_meta, indent=2) + '\n', encoding='utf-8', newline='\n')
        say('\nAhora comprobamos que cada clave firma (otra vez la contraseña de cada una).')
        for sk in (home / 'k1.key', k2dir / 'k2.key'):
            args.key = str(sk)
            args.what = 'check'
            cmd_keys(args)
        args.what = 'export'
        args.out = None
        args.test_keys = False
        cmd_keys(args)
        say(f'\nHacé las copias fuera de línea:\n  - {home / "k1.key"} → dos copias fuera de esta máquina\n'
            f'  - {k2dir / "k2.key"} → dos copias fuera de esta máquina, en otro lugar\n')
        if input('¿Hiciste las cuatro copias? Escribí "sí" para borrar k2.key de esta máquina: ').strip().lower() in ('sí', 'si'):
            p = k2dir / 'k2.key'
            p.write_bytes(os.urandom(p.stat().st_size))
            p.unlink()
            k2dir.rmdir()
            say('k2.key borrada de esta máquina. Commiteá keys/ y client/pes6pkg_keys.h en una rama y abrí el PR.')
        else:
            say(f'k2.key sigue en {k2dir}: borrala cuando tengas las copias.')


def cmd_rotate(args):
    """KEY-5: la de uso pasa a revocada, la de reserva a uso, y una nueva a reserva ."""
    ring = keys.load_production(REPO)
    old = Path(args.old_k2)
    if signer.inside_git_repo(old):
        raise SystemExit(f'{old} está dentro de un repo: copiala a una carpeta fuera de los repos.')
    reserva = next(k for k, r in zip(ring.keys, ring.roles) if r == 'reserva')
    signer.MinisignSigner(old, reserva).sign(b'pes6pkg rotate: prueba de la reserva\n', 'pes6pkg rotate')
    say(f'La reserva {reserva.id_hex} abre y firma.')
    exe = signer.find_minisign()
    nums = [int(f[1:-len('.pub')]) for f in ring.files if f[1:-len('.pub')].isdigit()]
    name = f'k{max(nums) + 1}'
    home = signer.default_key_path('x').parent
    newdir = home / f'{name}-para-copiar-fuera-de-linea'
    newdir.mkdir(parents=True, exist_ok=True)
    say(f'\n== {name} (nueva reserva): minisign te pide su contraseña dos veces (una NUEVA, distinta de las otras)')
    if subprocess.run([exe, '-G', '-p', str(REPO / 'keys' / f'{name}.pub'), '-s', str(newdir / f'{name}.key')]).returncode:
        raise SystemExit('minisign no pudo crear la clave nueva.')
    pk = minisig.parse_public_key((REPO / 'keys' / f'{name}.pub').read_text(encoding='utf-8'))
    meta = REPO / 'keys' / 'keys.json'
    data = keys.rotate_meta(json.loads(meta.read_text(encoding='utf-8')), f'{name}.pub', pk.id_hex,
                            now_utc().strftime('%Y-%m-%d'))
    meta.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8', newline='\n')
    dst = signer.default_key_path(keys.load_production(REPO).secret_name('uso'))
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(old.read_bytes())
    args.what, args.out, args.test_keys = 'export', None, False
    cmd_keys(args)
    say(f'\nListo: la clave de uso ahora es {reserva.id_hex} ({dst}); {pk.id_hex} es la reserva nueva.\n'
        f'1. Copiá {newdir / (name + ".key")} a dos lugares fuera de línea y borrala de esta PC.\n'
        '2. Recompilá los clientes con el pes6pkg_keys.h nuevo y volvé a publicar cada paquete vigente con una versión '
        'mínima nueva: su release firma también el índice con la clave nueva.\n'
        '3. Commiteá keys/ y client/pes6pkg_keys.h y abrí el PR.')


def cmd_build(args):
    ring = ring_for(args)
    sg = signer_for(args, ring)
    req = None
    if args.requires:
        req = [{'package': r.split('=')[0], 'min': r.split('=')[1]} for r in args.requires]
    out, info = package.build(REPO, args.package, args.version, args.from_dir, args.out, sg, ring, args.released,
                              args.recipes, req)
    say(f'Armado {out}:')
    say(f'  {info["archive"]["name"]}  {info["archive"]["size"]} bytes  SHA-256 {info["archive"]["sha256"]}')
    say(f'  {info["manifest"]["name"]} (+ .minisig)')
    if ring.test:
        say('  OJO: firmado con claves de PRUEBA; `release` no lo publica.')


def _check_dir(folder: Path, ring, use_minisign=True):
    info = json.loads((folder / 'build.json').read_text(encoding='utf-8'))
    zb = (folder / info['archive']['name']).read_bytes()
    mb = (folder / info['manifest']['name']).read_bytes()
    ms = (folder / (info['manifest']['name'] + '.minisig')).read_text(encoding='utf-8')
    verify.check_bytes(zb, info['archive'])
    verify.check_bytes(mb, info['manifest'])
    doc = verify.check_manifest(mb, ms, ring.keys, verify.State(revoked=ring.revoked_ids()), info['package'],
                                info['version'])
    res = verify.check_zip(zb, ring.keys, verify.State(revoked=ring.revoked_ids()), [info['package']])
    inner = verify.read_entry(zb, next(e for e in verify.open_zip(zb)
                                       if e.name == model.manifest_zip_path(info['package'])), len(mb))
    if inner != mb:
        raise verify.VerifyError('E_HASH', 'el manifiesto del zip no es el mismo que el asset')
    if info['package'].startswith('translation-') and any(
            p.lower() == 'kitserver/translations.dll' for _, files in res for p in files):
        raise verify.VerifyError('E_PATH_NOT_ALLOWED', 'un zip de idioma no trae la DLL (cambio 1)')
    exe = signer.find_minisign(required=False, pinned=False) if use_minisign else None
    if exe and not ring.test:
        if not signer.minisign_verify(exe, mb, ms, ring.active()):
            raise verify.VerifyError('E_BAD_SIGNATURE', 'minisign -V no acepta la firma del manifiesto')
        say('  minisign -V: la firma del manifiesto vale.')
    return info, doc


def cmd_check(args):
    ring = ring_for(args)
    try:
        info, doc = _check_dir(Path(args.folder), ring)
    except verify.VerifyError as e:
        raise SystemExit(f'NO PASA ({e.code}): {e}')
    say(f'Bien: {info["package"]} {info["version"]}, {len(doc["files"])} archivos comprobados como un cliente.')


def _notes_file(args, tmp):
    if args.notes_file:
        return Path(args.notes_file)
    p = Path(tmp) / 'notas.md'
    p.write_text(args.notes or '', encoding='utf-8')
    return p


def _git(run, *a):
    return run(['git', '-C', str(REPO), *a])


def _publish_index(args, run, gh, ring, sg, entries, title, prev):
    """Firma el índice siguiente y abre el PR. Simulado o con claves de prueba, escribe todo en out/simulado/ y no toca
    ni git ni el índice del repo."""
    doc = index_mod.next_index(prev, now_utc(), entries, args.days)
    data, sig = index_mod.sign(doc, sg, ring)
    simulated = run.dry_run or ring.test
    root = Path(args.out) / 'simulado' if simulated else REPO
    branch = f'publicar/indice-{doc["serial"]}'
    if not simulated:
        _git(run, 'switch', '-c', branch, 'origin/main')
    index_mod.write(root, data, sig)
    for e in entries:
        folder = Path(args.out) / e['package'] / e['version']
        dst = root / 'manifests' / e['package']
        dst.mkdir(parents=True, exist_ok=True)
        for suf in ('', '.minisig'):
            src = folder / f'{e["package"]}-{e["version"]}.manifest.json{suf}'
            (dst / f'{e["version"]}.manifest.json{suf}').write_bytes(src.read_bytes())
    ics = Path(args.out) / f'recordatorios-indice-{doc["serial"]}.ics'
    ics.parent.mkdir(parents=True, exist_ok=True)
    ics.write_text(reminders.ics(model.parse_utc(doc['expires']), doc['serial']), encoding='utf-8', newline='')
    if simulated:
        say(f'(simulado) índice {doc["serial"]} firmado en {root / "index"}; no se tocó git ni el índice del repo.')
    else:
        _git(run, 'add', 'index', 'manifests')
        _git(run, 'commit', '-m', f'Índice {doc["serial"]}: {title}')
        _git(run, 'push', '-u', 'origin', branch)
        pr = gh.pr_create(CENTRAL, branch, f'Índice {doc["serial"]}: {title}',
                          f'{title}. Vence el {doc["expires"][:10]}. Comprobado con `pes6pkg` antes de abrir el PR.')
        say(f'Índice {doc["serial"]} firmado, vence el {doc["expires"][:10]}. PR: {pr.strip()}')
    say(f'Recordatorios de calendario: {ics} (importalo en tu calendario).')
    return doc


def _download(url, limit):
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'pes6pkg'}), timeout=60) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise verify.VerifyError('E_TOO_BIG', url)
    return data


def cmd_release(args):
    ring = ring_for(args)
    if ring.test:
        raise SystemExit('Con claves de prueba no se publica nada (KEY-8).')
    folder = Path(args.out) / args.package / args.version
    info, _ = _check_dir(folder, ring)
    if info.get('test_keys'):
        raise SystemExit('Ese paquete se armó con claves de prueba: armalo de nuevo sin --test-keys.')
    prev = index_mod.load(REPO, ring)
    if prev and model.parse_utc(prev['expires']) <= now_utc():
        say('El índice está vencido: este release también lo renueva (el índice nuevo vence en 90 días).')
    run = Runner(args.dry_run)
    gh = Gh(run)
    repo, tag = info['repo'], info['tag']
    if not args.dry_run and gh.release_exists(repo, tag):
        raise SystemExit(f'Ya existe el release {tag} en {repo}.')
    with tempfile.TemporaryDirectory(prefix='pes6pkg-') as tmp:
        files = [folder / info['archive']['name'], folder / info['manifest']['name'],
                 folder / (info['manifest']['name'] + '.minisig')]  # el zip primero (FMT-9)
        gh.release_create_draft(repo, tag, f'{info["name"]} {info["version"]}', _notes_file(args, tmp), files)
        if not args.dry_run:
            dl = Path(tmp) / 'borrador'
            gh.release_download(repo, tag, dl)
            for f in files:
                if hashlib.sha256((dl / f.name).read_bytes()).digest() != hashlib.sha256(f.read_bytes()).digest():
                    raise SystemExit(f'Lo subido de {f.name} no coincide con lo armado: no se publica.')
            say(f'Borrador {repo} {tag}: lo subido coincide con lo armado.')
            if input('¿Publicar? (queda inmutable) Escribí "sí": ').strip().lower() not in ('sí', 'si'):
                say('Quedó en borrador. No cambió el índice.')
                return
        gh.release_publish(repo, tag)
        archive_url, manifest_url, _ = package.release_urls(info)
        if not args.dry_run:
            verify.check_bytes(_download(archive_url, verify.MAX_ARCHIVE), info['archive'])
            verify.check_bytes(_download(manifest_url, verify.MAX_MANIFEST), info['manifest'])
            say('Las direcciones públicas bajan lo mismo que se armó.')
            out = gh.verify_asset(repo, tag, files[0])
            say('gh release verify-asset: ' + ('bien.' if out else 'no respondió bien (¿release immutability prendido?).'))
    sg = signer_for(args, ring)
    _publish_index(args, run, gh, ring, sg, [package.index_entry(info)], f'{info["name"]} {info["version"]}', prev)
    say('Mergeá el PR y después corré `pes6pkg verify-live`.')


def cmd_renew(args):
    ring = ring_for(args)
    # Con claves de prueba es un simulacro: no lee el índice real del repo (lo firma otra clave).
    prev = None if ring.test else index_mod.load(REPO, ring)
    if prev is None and not args.first:
        raise SystemExit('No hay índice todavía. Para el primero: `pes6pkg renew --first`.')
    run = Runner(args.dry_run or ring.test)
    _publish_index(args, run, Gh(run), ring, signer_for(args, ring), [], 'renovación', prev)


def cmd_status(args):
    ring = ring_for(args)
    doc = index_mod.load(REPO, ring)
    if doc is None:
        say('Todavía no hay índice en el repo.')
        return
    exp = index_mod.expires_of(doc)
    say(f'Índice {doc["serial"]}: emitido {doc["issued"]}, vence {doc["expires"]} '
        f'(faltan {reminders.days_left(exp, now_utc().date())} días).')
    for e in doc['packages']:
        say(f'  {e["package"]} {e["version"]} ({e["released"]})')
    st = Gh(Runner()).workflow_state(CENTRAL, reminders.WORKFLOW)
    if st:
        say(f'Workflow de avisos: {st}' + ('' if st == 'active' else '  ← APAGADO: habilitalo en GitHub (Actions).'))


def cmd_verify_live(args):
    ring = ring_for(args)
    url = args.index_url or model.INDEX_URL
    data = _download(url, verify.MAX_INDEX)
    sig = _download(url + '.minisig', verify.MAX_SIG).decode('utf-8')
    try:
        doc, i, _ = verify.check_index(data, sig, ring.keys, verify.State(revoked=ring.revoked_ids()), now_utc())
    except verify.VerifyError as e:
        raise SystemExit(f'El índice público NO PASA ({e.code}): {e}')
    exe = signer.find_minisign(required=False, pinned=False)
    if exe and not ring.test and not signer.minisign_verify(exe, data, sig, ring.keys[i]):
        raise SystemExit('minisign -V no acepta la firma del índice público.')
    exp = index_mod.expires_of(doc)
    say(f'Índice público {doc["serial"]}: firma de {ring.keys[i].id_hex} ({ring.roles[i]}), vence {doc["expires"]} '
        f'(faltan {reminders.days_left(exp, now_utc().date())} días).')
    for e in doc['packages']:
        if not model.url_allowed(e['manifest']['url']) or not model.url_allowed(e['archive']['url']):
            raise SystemExit(f'{e["package"]}: dirección fuera de las permitidas')
        mb = _download(e['manifest']['url'], verify.MAX_MANIFEST)
        ms = _download(e['manifest']['url'] + '.minisig', verify.MAX_SIG).decode('utf-8')
        verify.check_bytes(mb, e['manifest'])
        verify.check_manifest(mb, ms, ring.keys, verify.State(revoked=ring.revoked_ids()), e['package'], e['version'])
        line = f'  {e["package"]} {e["version"]}: manifiesto bien'
        if args.archives:
            zb = _download(e['archive']['url'], verify.MAX_ARCHIVE)
            verify.check_bytes(zb, e['archive'])
            verify.check_zip(zb, ring.keys, verify.State(revoked=ring.revoked_ids()), [e['package']])
            line += ', zip bien'
        say(line)


def cmd_reminders(args):
    if not args.test_keys and not (REPO / 'keys' / 'keys.json').exists():
        say('Todavía no hay claves ni índice: nada que avisar.')
        return
    ring = ring_for(args)
    doc = index_mod.load(REPO, ring)
    if doc is None:
        say('No hay índice: nada que avisar.')
        return
    today = datetime.strptime(args.today, '%Y-%m-%d').date() if args.today else now_utc().date()
    owner = args.owner or args.repo.split('/')[0]
    did = reminders.run(Gh(Runner(args.dry_run)), args.repo, owner, index_mod.expires_of(doc), today)
    say(f'Avisos de vencimiento: {did}.')


BINARY_SUFFIXES = ('.zip', '.dll', '.exe', '.afs', '.bin', '.key')


def ci_problems(root: Path, files, base_index, ring, now, changed):
    """PUB-7: lo que la CI rechaza. `files`: lo que sigue git; `base_index`: bytes del índice de main (o None);
    `changed`: si el PR cambia el índice. Devuelve una lista de problemas (vacía = bien)."""
    out = [f'binario en el repo: {f}' for f in files if f.lower().endswith(BINARY_SUFFIXES)]
    try:
        doc = index_mod.load(root, ring, trust_revoked=False)
    except SystemExit as e:
        return out + [str(e)]
    if doc is None:
        return out
    if changed:
        prev = jsonr.loads(base_index)['serial'] if base_index else 0
        if doc['serial'] != prev + 1:
            out.append(f'el serial tiene que ser {prev + 1} (el de main + 1), no {doc["serial"]}')
        left = (index_mod.expires_of(doc) - now).days
        if left < 30:
            out.append(f'el índice nuevo vence en {left} días (mínimo 30)')
    for e in doc['packages']:
        mp = root / 'manifests' / e['package'] / f'{e["version"]}.manifest.json'
        if not mp.exists() or not (mp.parent / (mp.name + '.minisig')).exists():
            out.append(f'falta {mp.relative_to(root)} (+ .minisig)')
            continue
        data = mp.read_bytes()
        try:
            verify.check_bytes(data, e['manifest'])
            verify.check_manifest(data, (mp.parent / (mp.name + '.minisig')).read_text(encoding='utf-8'), ring.keys,
                                  verify.State(revoked=ring.revoked_ids()), e['package'], e['version'])
        except verify.VerifyError as x:
            out.append(f'{mp.relative_to(root)}: {x.code} {x}')
    return out


def cmd_ci_check(args):
    if not args.test_keys and not (REPO / 'keys' / 'keys.json').exists():
        # antes de la ceremonia de claves: no puede haber índice; se comprueban solo los binarios
        files = subprocess.run(['git', '-C', str(REPO), 'ls-files'], capture_output=True, text=True,
                               encoding='utf-8').stdout.splitlines()
        problems = [f'binario en el repo: {f}' for f in files if f.lower().endswith(BINARY_SUFFIXES)]
        if index_mod.paths(REPO)[0].exists():
            problems.append('hay índice pero no hay keys/keys.json')
        for p in problems:
            say(f'PROBLEMA: {p}')
        if problems:
            raise SystemExit(f'{len(problems)} problemas (PUB-7)')
        say('ci-check: bien (todavía sin claves ni índice).')
        return
    ring = ring_for(args)
    files = subprocess.run(['git', '-C', str(REPO), 'ls-files'], capture_output=True, text=True,
                           encoding='utf-8').stdout.splitlines()
    base = subprocess.run(['git', '-C', str(REPO), 'show', f'{args.base}:index/index.json'], capture_output=True)
    base_index = base.stdout if base.returncode == 0 else None
    current = index_mod.paths(REPO)[0]
    changed = current.exists() and current.read_bytes() != base_index
    problems = ci_problems(REPO, [f for f in files if f], base_index, ring, now_utc(), changed)
    exe = signer.find_minisign(required=False, pinned=False)
    if exe and current.exists() and not ring.test:
        sig = index_mod.paths(REPO)[1].read_text(encoding='utf-8')
        if not any(signer.minisign_verify(exe, current.read_bytes(), sig, k) for k in ring.keys):
            problems.append('minisign -V no acepta la firma del índice')
    if args.online and current.exists():
        doc = jsonr.loads(current.read_bytes())
        for e in doc['packages']:
            try:
                verify.check_bytes(_download(e['manifest']['url'], verify.MAX_MANIFEST), e['manifest'])
                verify.check_bytes(_download(e['archive']['url'], verify.MAX_ARCHIVE), e['archive'])
            except (verify.VerifyError, OSError) as x:
                problems.append(f'{e["package"]} {e["version"]}: lo publicado no coincide ({x})')
    for p in problems:
        say(f'PROBLEMA: {p}')
    if problems:
        raise SystemExit(f'{len(problems)} problemas (PUB-7)')
    say('ci-check: bien.')


def cmd_vectors(args):
    n = vectors.generate(args.out)
    say(f'{n} casos en {args.out}')


def cmd_web(args):
    """WEB-2: el bloque `release` del translation.json (o del mod.json de la DLL) desde lo publicado."""
    folder = Path(args.out) / args.package / args.version
    info = json.loads((folder / 'build.json').read_text(encoding='utf-8'))
    archive_url, _, _ = package.release_urls(info)
    size = info['archive']['size']
    release = {'version': info['version'], 'date': info['released'], 'download': archive_url,
               'file': info['archive']['name'],
               'size': f'{size / 1048576:.1f} MB' if size >= 1048576 else f'{max(1, round(size / 1024))} KB'}
    web = Path(args.translations_repo) / 'web'
    if args.package == 'translations':
        target = web / 'mods' / 'pes6-translations' / 'mod.json'
    else:
        target = web / 'translations' / model.translation_code(args.package) / 'translation.json'
    data = json.loads(target.read_text(encoding='utf-8'))
    data['release'] = release
    if args.package != 'translations':
        mdoc = jsonr.loads((folder / info['manifest']['name']).read_bytes())
        need = next((r['min'] for r in mdoc['requires'] if r['package'] == 'translations'), None)
        if need:
            rows = [r for r in data.get('requirements', []) if r.get('mod') != 'pes6-translations']
            rows.append({'label': {'es': 'PES6 Translations', 'en': 'PES6 Translations'},
                         'value': {'es': f'{need} o más nueva', 'en': f'{need} or later'}, 'mod': 'pes6-translations'})
            data['requirements'] = rows
        hd = next((r['min'] for r in mdoc['requires'] if r['package'] == 'hdtext'), None)
        guide = web / 'translations' / 'guide.json'
        if hd and guide.exists() and hd not in guide.read_text(encoding='utf-8'):
            say(f'AVISO: guide.json tiene que decir que hace falta PES6 HD Text {hd} o más nueva (WEB-4).')
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8', newline='\n')
    say(f'Escrito el bloque release en {target}.')


def main(argv=None):
    p = argparse.ArgumentParser(prog='pes6pkg', description=__doc__)
    p.add_argument('--test-keys', action='store_true', help='usar las claves de PRUEBA (nunca para publicar)')
    sub = p.add_subparsers(dest='cmd', required=True)

    k = sub.add_parser('keys', help='claves: new | export | check')
    k.add_argument('what', choices=('new', 'export', 'check'))
    k.add_argument('--key', help='clave secreta para `check`')
    k.add_argument('--out', help='dónde escribir el .h de `export`')
    k.set_defaults(fn=cmd_keys)

    t = sub.add_parser('rotate', help='rotar a la clave de reserva (KEY-5)')
    t.add_argument('--old-k2', required=True, help='la clave secreta de reserva, traída de su copia fuera de línea')
    t.set_defaults(fn=cmd_rotate)

    b = sub.add_parser('build', help='armar y firmar un paquete')
    b.add_argument('package')
    b.add_argument('version')
    b.add_argument('--from', dest='from_dir', required=True, help='carpeta con la estructura del zip')
    b.add_argument('--out', default=str(REPO / 'out'))
    b.add_argument('--released', help='AAAA-MM-DD (por defecto, hoy)')
    b.add_argument('--recipes', help='carpeta de recetas (por defecto ./packages o packages/ del repo central)')
    b.add_argument('--requires', nargs='*', help='paquete=versión mínima (reemplaza los de la receta)')
    b.add_argument('--key', help='clave de uso (por defecto %%USERPROFILE%%\\.pes6pkg\\k1.key)')
    b.set_defaults(fn=cmd_build)

    c = sub.add_parser('check', help='comprobar un paquete armado como un cliente')
    c.add_argument('folder', help='out/<paquete>/<versión>')
    c.set_defaults(fn=cmd_check)

    r = sub.add_parser('release', help='publicar un paquete armado y abrir el PR del índice')
    r.add_argument('package')
    r.add_argument('version')
    r.add_argument('--out', default=str(REPO / 'out'))
    r.add_argument('--notes-file')
    r.add_argument('--notes')
    r.add_argument('--days', type=int, default=model.DEFAULT_LIFETIME_DAYS)
    r.add_argument('--key')
    r.add_argument('--dry-run', action='store_true')
    r.set_defaults(fn=cmd_release)

    n = sub.add_parser('renew', help='índice nuevo con los mismos paquetes y vencimiento nuevo')
    n.add_argument('--first', action='store_true', help='el primer índice (serial 1, sin paquetes)')
    n.add_argument('--days', type=int, default=model.DEFAULT_LIFETIME_DAYS)
    n.add_argument('--out', default=str(REPO / 'out'))
    n.add_argument('--key')
    n.add_argument('--dry-run', action='store_true')
    n.set_defaults(fn=cmd_renew)

    s = sub.add_parser('status', help='vencimiento y paquetes del índice')
    s.set_defaults(fn=cmd_status)

    v = sub.add_parser('verify-live', help='comprobar el índice público como un cliente')
    v.add_argument('--index-url')
    v.add_argument('--archives', action='store_true', help='bajar y comprobar también cada zip')
    v.set_defaults(fn=cmd_verify_live)

    m = sub.add_parser('reminders', help='(CI) avisos de vencimiento en un issue')
    m.add_argument('--repo', default=CENTRAL)
    m.add_argument('--owner')
    m.add_argument('--today', help='AAAA-MM-DD (para probar)')
    m.add_argument('--dry-run', action='store_true')
    m.set_defaults(fn=cmd_reminders)

    q = sub.add_parser('ci-check', help='(CI) firma, serial, vencimiento, manifiestos y sin binarios')
    q.add_argument('--base', default='origin/main')
    q.add_argument('--online', action='store_true', help='bajar también lo publicado y compararlo')
    q.set_defaults(fn=cmd_ci_check)

    x = sub.add_parser('vectors', help='generar los vectores de prueba del verificador')
    x.add_argument('--out', required=True)
    x.set_defaults(fn=cmd_vectors)

    w = sub.add_parser('web', help='escribir el bloque release de la web (pes6xlife-translations)')
    w.add_argument('package')
    w.add_argument('version')
    w.add_argument('--translations-repo', required=True)
    w.add_argument('--out', default=str(REPO / 'out'))
    w.set_defaults(fn=cmd_web)

    args = p.parse_args(argv)
    quiet = ('vectors', 'reminders', 'ci-check')
    if args.cmd not in quiet:
        banner(args)
    args.fn(args)
    if args.cmd not in quiet:
        banner(args, end=True)
    return 0
