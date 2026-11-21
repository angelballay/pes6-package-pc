"""Publicar sin dejar nada a medias (PUB-5, docs/RECETA.md).

- Cada release se publica solo (`release --no-index`) o con su índice. Varios releases van a **un** índice con
  `index add`: un PR, una contraseña.
- El índice anterior sale siempre de `origin/main` después de un `git fetch`, y el PR se arma en un worktree temporal
  desde ese commit, sin tocar el checkout de quien publica. Antes del push corre la misma comprobación que la CI.
- Todo lo que se puede comprobar se comprueba antes de tocar GitHub, y la contraseña se pide antes de publicar: un
  error deja a lo sumo un borrador, que el mismo comando retoma (o `--discard` borra).
- Con claves de prueba es un simulacro local: no corre ni git ni gh ni usa la red (`Runner` en modo local)."""
import hashlib
import json
import shutil
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import index as index_mod
from . import jsonr, model, package, reminders, verify
from .ghcli import REAL

CENTRAL = 'angelballay/pes6-package-pc'


def say(text=''):
    print(text, flush=True)


def download(url, limit):
    """Baja sin sesión, como un jugador."""
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'pes6pkg'}), timeout=60) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise verify.VerifyError('E_TOO_BIG', url)
    return data


def confirm(prompt):
    return input(prompt).strip().lower() in ('sí', 'si')


# ---------------------------------------------------------------- un paquete armado

check_dir = package.check_folder  # comprueba out/<paquete>/<versión> como un cliente


def asset_files(folder: Path, info):
    """Lo que va al release, el zip primero (FMT-9)."""
    m = info['manifest']['name']
    return [folder / info['archive']['name'], folder / m, folder / (m + '.minisig')]


@dataclass
class Built:
    info: dict  # build.json
    folder: Path
    files: list  # asset_files
    entry: dict  # su entrada del índice
    manifest: dict
    bundled: list = field(default_factory=list)  # los paquetes que trae adentro (Built), ya armados y publicados aparte

    @property
    def spec(self):
        return f'{self.info["package"]}@{self.info["version"]}'

    @property
    def label(self):
        return f'{self.info["package"]} {self.info["version"]}'


# ---------------------------------------------------------------- repo central

def _norm_remote(u):
    u = u.strip().replace('\\', '/').rstrip('/')
    if u.startswith('git@github.com:'):
        u = 'https://github.com/' + u[len('git@github.com:'):]
    if u.endswith('.git'):
        u = u[:-4]
    return u.lower()


class Central:
    """El repo del índice: su clon local (`git_dir`), su `origin` (`url`) y su nombre en GitHub (para el PR)."""

    def __init__(self, slug, git_dir, run, url=None):
        self.slug = slug
        self.dir = Path(git_dir)
        self.run = run
        self.url = url or f'https://github.com/{slug}.git'

    def git(self, *a, read=False, binary=False, check=True, cwd=None):
        return self.run(['git', '-C', str(cwd or self.dir), *a], read=read, binary=binary, check=check)

    def check_origin(self):
        got = self.git('remote', 'get-url', 'origin', read=True)
        if got and _norm_remote(got) != _norm_remote(self.url):
            raise SystemExit(f'El origin de {self.dir} es {got.strip()}, no {self.url}: no publico ahí.')

    def fetch(self):
        """`git fetch` de main; devuelve el commit de origin/main."""
        self.git('fetch', '--quiet', 'origin', 'main', read=True)
        return self.git('rev-parse', 'origin/main', read=True).strip()

    def index_bytes(self, commit):
        """(bytes del índice, texto de su firma) en ese commit, o (None, None) si todavía no hay índice."""
        names = self.git('ls-tree', '--name-only', commit, 'index/', read=True).split()
        if 'index/index.json' not in names:
            return None, None
        data = self.git('show', f'{commit}:index/index.json', read=True, binary=True)
        sig = self.git('show', f'{commit}:index/index.json.minisig', read=True, binary=True)
        return data, sig.decode('utf-8')

    def index_at(self, commit, ring):
        """El índice de ese commit con la firma comprobada (o None), y sus bytes."""
        data, sig = self.index_bytes(commit)
        if data is None:
            return None, None
        return index_mod.parse(data, sig, ring, where=f'El índice de main de {self.slug}'), data

    def branch_on_remote(self, branch):
        return bool(self.git('ls-remote', '--heads', 'origin', branch, read=True).strip())

    def open_pr(self, gh, commit, base_index, branch, files, message, title, body, check):
        """Arma `branch` desde `commit` en un worktree temporal, escribe `files` ({ruta: bytes}), corre
        `check(raíz, archivos seguidos)` (lo mismo que la CI), vuelve a mirar main, y sube la rama y el PR.
        Si algo falla antes del push, no sube nada."""
        tmp = Path(tempfile.mkdtemp(prefix='pes6pkg-pr-'))
        wt = tmp / 'arbol'
        try:
            self.git('worktree', 'add', '--quiet', '-B', branch, str(wt), commit)
            for rel, data in files.items():
                p = wt / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data)
            self.git('add', '--', *files, cwd=wt)
            self.git('commit', '--quiet', '-m', message, cwd=wt)
            tracked = [f for f in self.git('ls-files', cwd=wt, read=True).splitlines() if f]
            problems = check(wt, tracked)
            if problems:
                raise SystemExit('La comprobación de la CI no pasa sobre la rama nueva; no subí nada:\n  - '
                                 + '\n  - '.join(problems))
            now = self.fetch()
            if now != commit and self.index_bytes(now)[0] != base_index:
                raise SystemExit(f'Mientras tanto otro PR cambió el índice de main de {self.slug}; no subí nada (la CI '
                                 'lo rechazaría por el serial). Volvé a correr el mismo comando: parte del main nuevo.')
            self.git('push', '--quiet', '-u', 'origin', branch)
            try:
                return gh.pr_create(self.slug, branch, title, body)
            except SystemExit as e:
                raise SystemExit(f'{e}\nLa rama {branch} quedó subida pero no se abrió el PR. Abrilo con:\n'
                                 f'  gh pr create --repo {self.slug} --head {branch} --base main --fill')
        finally:
            self.git('worktree', 'remove', '--force', str(wt), check=False)
            self.git('worktree', 'prune', check=False)
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- releases en GitHub

NONE, DRAFT, PUBLISHED = 'ninguno', 'borrador', 'publicado'


@dataclass
class ReleaseState:
    kind: str
    drafts: int = 0
    assets: list = field(default_factory=list)  # [{name, size, state, digest}]
    immutable: bool = False

    def names(self):
        return [a['name'] for a in self.assets]

    def describe(self):
        if self.kind == NONE:
            return 'no existe todavía'
        if self.kind == DRAFT:
            n = f' ({self.drafts} borradores con ese tag)' if self.drafts > 1 else ''
            return f'borrador{n} con ' + (', '.join(self.names()) if self.assets else 'ningún archivo')
        return 'publicado' + (' e inmutable' if self.immutable else ', SIN la marca de inmutable')


def release_state(gh, repo, tag):
    rows = [r for r in gh.release_list(repo) if r.get('tagName') == tag]
    if not rows:
        return ReleaseState(NONE)
    view = gh.release_view(repo, tag) or {}
    assets = [{'name': a.get('name'), 'size': a.get('size'), 'state': a.get('state', 'uploaded'),
               'digest': a.get('digest')} for a in view.get('assets') or []]
    published = [r for r in rows if not r.get('isDraft')]
    if published:
        return ReleaseState(PUBLISHED, len(rows) - len(published), assets, bool(published[0].get('isImmutable')))
    return ReleaseState(DRAFT, len(rows), assets)


def _sha(p: Path):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def draft_mismatch(gh, info, files, state):
    """None si el borrador tiene exactamente lo armado; si no, el motivo."""
    want = [f.name for f in files]
    if sorted(state.names()) != sorted(want):
        have = ', '.join(state.names()) if state.assets else 'ningún archivo'
        return f'tiene {have}; lo armado es {", ".join(want)}'
    by_name = {a['name']: a for a in state.assets}
    for f in files:
        a = by_name[f.name]
        if a['state'] != 'uploaded':
            return f'{f.name} quedó a medio subir'
        if a['size'] is not None and a['size'] != f.stat().st_size:
            return f'{f.name} tiene otro tamaño'
    with tempfile.TemporaryDirectory(prefix='pes6pkg-') as tmp:
        gh.release_download(info['repo'], info['tag'], tmp)
        for f in files:
            got = Path(tmp) / f.name
            if not got.exists() or _sha(got) != _sha(f):
                return f'{f.name} es distinto de lo armado'
    return None


def public_mismatch(info, files, fetch=None):
    """None si las direcciones públicas bajan exactamente lo armado (zip, manifiesto y su firma); si no, el motivo."""
    fetch = fetch or download
    archive_url, manifest_url, _ = package.release_urls(info)
    for url, f, limit in ((archive_url, files[0], verify.MAX_ARCHIVE), (manifest_url, files[1], verify.MAX_MANIFEST),
                          (manifest_url + '.minisig', files[2], verify.MAX_SIG)):
        try:
            data = fetch(url, limit)
        except (OSError, verify.VerifyError) as e:
            return f'{url} no baja ({e})'
        if hashlib.sha256(data).hexdigest() != _sha(f):
            return f'{url} no es lo mismo que {f.name}'
    return None


def create_draft(gh, info, files, notes_file):
    """Borrador con el zip solo, y después el manifiesto y su firma: gh sube en paralelo los archivos de un mismo
    `release create`, así el zip queda primero (FMT-9)."""
    gh.release_create_draft(info['repo'], info['tag'], f'{info["name"]} {info["version"]}', notes_file, files[:1])
    gh.release_upload(info['repo'], info['tag'], files[1:])


def delete_drafts(gh, repo, tag):
    """Borra los borradores de `tag`. Nunca un release publicado: si hay uno con ese tag, no borra nada."""
    for _ in range(10):
        rows = [r for r in gh.release_list(repo) if r.get('tagName') == tag]
        if any(not r.get('isDraft') for r in rows):
            raise SystemExit(f'{repo} tiene un release publicado {tag}: no borro nada por ese tag (si quedó un '
                             'borrador repetido, borralo desde la web de GitHub).')
        if not rows:
            return
        gh.release_delete(repo, tag)
        if gh.run.dry_run:
            return
    raise SystemExit(f'Siguen apareciendo borradores {tag} en {repo}: borralos desde la web de GitHub.')


# ---------------------------------------------------------------- lo que comprueba la CI (PUB-7)

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
        for what in ('manifest', 'archive'):
            if not model.url_allowed(e[what]['url']):
                out.append(f'{e["package"]}: {e[what]["url"]} no está entre las direcciones permitidas (VER-1)')
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


# ---------------------------------------------------------------- publicar

@dataclass
class Plan:
    doc: dict  # el índice nuevo, sin firmar
    prev: dict  # el de main (o None)
    commit: str  # el commit de main del que sale (None en el simulacro local)
    base_index: bytes  # los bytes del índice de ese commit (o None)
    branch: str
    builts: list  # los paquetes que entran (los que ya estaban igual se saltean)
    signer: object = None
    data: bytes = None
    sig: str = None

    @property
    def serial(self):
        return self.doc['serial']


class Publisher:
    """Los pasos de `release`, `index add` y `renew`. La CLI lo arma con lo real; las pruebas, con un remoto git local,
    un gh falso y claves de prueba.

    `central` None = simulacro local (claves de prueba): nada de red, nada de git, y lo firmado va a out/simulado/."""

    def __init__(self, ring, run, gh, central, out, make_signer, now, days=model.DEFAULT_LIFETIME_DAYS,
                 ask=confirm, fetch=None, precheck=None):
        self.ring, self.run, self.gh, self.central = ring, run, gh, central
        self.out, self.make_signer, self.now, self.days = Path(out), make_signer, now, days
        self.ask, self.fetch, self.precheck = ask, fetch, precheck

    # -- utilidades
    @property
    def offline(self):
        return self.central is None or self.run.offline

    @property
    def unsigned(self):
        """`--dry-run` con las claves reales: no se firma nada (ni se pide la contraseña)."""
        return self.run.dry_run and not self.ring.test

    def cmd(self, rest):
        return ('pes6pkg --test-keys ' if self.ring.test else 'pes6pkg ') + rest

    def load(self, package_id, version):
        folder = self.out / package_id / version
        if not (folder / 'build.json').exists():
            raise SystemExit(f'No está {folder / "build.json"}: armalo con '
                             f'`{self.cmd(f"build {package_id} {version} --from <carpeta>")}`.')
        info = json.loads((folder / 'build.json').read_text(encoding='utf-8'))
        if bool(info.get('test_keys')) != self.ring.test:
            raise SystemExit(f'{package_id} {version} se armó con claves de prueba: armalo de nuevo sin --test-keys.'
                             if info.get('test_keys') else
                             f'{package_id} {version} se armó con las claves reales: el simulacro necesita uno armado '
                             'con --test-keys (en otra carpeta, ver docs/ENSAYO.md).')
        try:
            info, manifest = check_dir(folder, self.ring)
        except verify.VerifyError as e:
            raise SystemExit(f'{package_id} {version}: NO PASA ({e.code}): {e}')
        for u in package.release_urls(info)[:2]:
            if not model.url_allowed(u):
                raise SystemExit(f'{package_id}: {u} no está entre las direcciones que aceptan los clientes '
                                 '(model.URL_PREFIXES). Revisá release.repo en la receta.')
        bundled = []
        for x in info.get('bundles') or []:
            bb = self.load(x['package'], x['version'])
            if bb.info['manifest']['sha256'] != x['manifest']['sha256']:
                raise SystemExit(f'{package_id} {version} trae {x["package"]} {x["version"]} adentro, pero {bb.folder} '
                                 f'se armó de nuevo después (otro manifiesto): armá {package_id} otra vez.')
            bundled.append(bb)
        return Built(info, folder, asset_files(folder, info), package.index_entry(info), manifest, bundled)

    def bundle_problems(self, b: Built):
        """Lo que trae adentro (por ejemplo, translations dentro de un idioma) tiene que estar publicado e igual: si
        no, un jugador tendría dos `translations 1.0` distintas."""
        out = []
        for bb in [] if self.offline else b.bundled:
            st = self.state(bb)
            if st.kind != PUBLISHED:
                rel = self.cmd(f'release {bb.info["package"]} {bb.info["version"]} --no-index')
                out.append(f'{b.label} trae {bb.label} adentro, y {bb.info["tag"]} no está publicado. Publicalo primero: '
                           f'`{rel}`.')
            else:
                why = self.public_mismatch(bb)
                if why:
                    out.append(f'{b.label} trae {bb.label} adentro, distinto del publicado ({why}): armá {b.label} de '
                               f'nuevo con el {bb.label} publicado.')
        return out

    def state(self, b: Built):
        if self.offline:
            return ReleaseState(NONE)
        return release_state(self.gh, b.info['repo'], b.info['tag'])

    def public_mismatch(self, b: Built):
        return public_mismatch(b.info, b.files, self.fetch)

    # -- índice
    def plan(self, builts, renew=False, first=False):
        """Todo lo que se puede comprobar del índice nuevo, antes de tocar GitHub. None si no hay nada que sumar."""
        if self.offline:
            say('(simulacro local) sin red ni git: parte de un índice vacío.')
            commit = base = prev = None
        else:
            self.central.check_origin()
            commit = self.central.fetch()
            prev, base = self.central.index_at(commit, self.ring)
            say(f'main de {self.central.slug} ({commit[:10]}): '
                + (f'índice {prev["serial"]}, vence {prev["expires"][:10]}.' if prev else 'todavía sin índice.'))
        if renew and prev is None and not first:
            raise SystemExit('No hay índice todavía. Para el primero: `pes6pkg renew --first`.')
        if prev and index_mod.expires_of(prev) <= self.now():
            say('El índice de main está vencido: el nuevo lo renueva.')
        old = {e['package']: e for e in prev['packages']} if prev else {}
        todo = []
        for b in builts:
            o = old.get(b.info['package'])
            if o and model.compare_versions(b.info['version'], o['version']) == 0:
                if o == b.entry:
                    say(f'{b.label} ya está en el índice {prev["serial"]}: lo salteo.')
                    continue
                raise SystemExit(f'{b.label} ya está en el índice {prev["serial"]} con otros archivos (otro SHA-256). '
                                 'Una versión publicada no se cambia: armá una versión nueva.')
            todo.append(b)
        if builts and not todo:
            return None
        doc = index_mod.next_index(prev, self.now(), [b.entry for b in todo], self.days)
        branch = f'publicar/indice-{doc["serial"]}'
        if not self.offline and self.central.branch_on_remote(branch):
            raise SystemExit(f'Ya hay una rama {branch} en {self.central.slug} (¿un PR del índice {doc["serial"]} sin '
                             'mergear?). Mergealo, o cerralo y borrá la rama, y volvé a correr.')
        have = {e['package']: e['version'] for e in doc['packages']}
        for b in todo:
            for r in b.manifest.get('requires', []):
                got = have.get(r['package'])
                if got is None or model.compare_versions(got, r['min']) < 0:
                    say(f'AVISO: {b.label} pide {r["package"]} {r["min"]} o más nueva y el índice nuevo tiene '
                        f'{r["package"] + " " + got if got else "ninguna"}: los jugadores no van a poder instalarlo '
                        'hasta que esté.')
        # la clave y minisign se comprueban ahora: si faltan, no se toca GitHub
        sg = None if self.unsigned else self.make_signer()
        if self.unsigned and self.precheck:
            for w in self.precheck():
                say(f'(simulado) AVISO para el día real: {w}')
        return Plan(doc, prev, commit, base, branch, todo, sg)

    def sign(self, plan: Plan, on_fail=None):
        if self.unsigned:
            say(f'(simulado) acá minisign pediría la contraseña de la clave {self.ring.active().id_hex} para firmar '
                f'el índice {plan.serial}. No se firma nada.')
            return
        try:
            plan.data, plan.sig = index_mod.sign(plan.doc, plan.signer, self.ring)
        except SystemExit as e:
            raise SystemExit(f'{e}\n{on_fail}' if on_fail else str(e))

    def write(self, plan: Plan, title):
        files = {}
        if plan.data is not None:
            files['index/index.json'] = plan.data
            files['index/index.json.minisig'] = plan.sig.encode('utf-8')
        for b in plan.builts:
            for suf in ('', '.minisig'):
                src = b.folder / f'{b.info["manifest"]["name"]}{suf}'
                files[f'manifests/{b.info["package"]}/{b.info["version"]}.manifest.json{suf}'] = src.read_bytes()
        expires = plan.doc['expires'][:10]
        if plan.data is None:
            names = ['index/index.json', 'index/index.json.minisig'] + sorted(files)
            say(f'(simulado) el índice {plan.serial} vencería el {expires}, con '
                f'{", ".join(e["package"] + " " + e["version"] for e in plan.doc["packages"]) or "ningún paquete"}, y '
                f'se abriría un PR desde la rama {plan.branch} con {", ".join(names)}.')
            return
        if self.offline or self.run.mode != REAL:
            root = self.out / 'simulado'
            for rel, data in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_bytes(data)
            self._ics(plan, root)
            say(f'(simulado) índice {plan.serial} firmado en {root / "index"}; no se tocó git ni el índice del repo.')
            return
        lines = [f'- {b.info["name"]} ({b.label}): {package.release_urls(b.info)[2]}' for b in plan.builts]
        message = f'Índice {plan.serial}: {title}' + ('\n\n' + '\n'.join(lines) if lines else '')
        body = (f'{title}. Vence el {expires}.\n\n' + ('\n'.join(lines) + '\n\n' if lines else '')
                + 'Comprobado con `pes6pkg` antes de abrir el PR: firma, serial, vencimiento, manifiestos'
                + (' y lo publicado.' if lines else '.'))
        pr = self.central.open_pr(self.gh, plan.commit, plan.base_index, plan.branch, files, message,
                                  f'Índice {plan.serial}: {title}', body,
                                  lambda root, tracked: ci_problems(root, tracked, plan.base_index, self.ring,
                                                                    self.now(), True))
        say(f'Índice {plan.serial} firmado, vence el {expires}. PR: {(pr or "").strip()}')
        self._ics(plan, self.out)
        say('Mergeá el PR y después corré `pes6pkg verify-live`.')

    def _ics(self, plan, folder):
        ics = Path(folder) / f'recordatorios-indice-{plan.serial}.ics'
        ics.parent.mkdir(parents=True, exist_ok=True)
        ics.write_text(reminders.ics(model.parse_utc(plan.doc['expires']), plan.serial), encoding='utf-8', newline='')
        say(f'Recordatorios de calendario: {ics} (importalo en tu calendario).')

    # -- releases
    def check_published(self, b: Built, after_publish):
        why = self.public_mismatch(b)
        if why:
            if after_publish:
                raise SystemExit(
                    f'{b.info["repo"]} {b.info["tag"]} quedó publicado, pero las direcciones públicas no bajan lo armado '
                    f'({why}). No se escribió el índice. Si es una demora de GitHub, en unos minutos corré '
                    f'`{self.cmd("index add " + b.spec)}` (vuelve a comprobar y firma). Si sigue igual, no lo sumes '
                    'al índice: armá una versión nueva.')
            return why
        say(f'  {b.label}: las direcciones públicas bajan lo mismo que se armó (zip, manifiesto y firma).')
        out = self.gh.verify_asset(b.info['repo'], b.info['tag'], b.files[0]) or ''
        say(f'  gh release verify-asset: ' + ('bien.' if 'Verification succeeded' in out else
                                              'no respondió bien (¿está prendida la inmutabilidad de releases en el '
                                              'repo? docs/RECETA.md, "Una sola vez", paso 4).'))
        return None

    def release(self, package_id, version, notes_file, with_index=True):
        b = self.load(package_id, version)
        repo, tag = b.info['repo'], b.info['tag']
        again = self.cmd(f'release {package_id} {version}' + ('' if with_index else ' --no-index'))
        say(f'{b.info["name"]} {version}: release {tag} en {repo}.')
        for bb in b.bundled:
            say(f'  Trae adentro {bb.label} (release {bb.info["tag"]}).')
        problems = self.bundle_problems(b)
        if problems:
            raise SystemExit('\n'.join(problems))
        plan = self.plan([b]) if with_index else None
        if with_index and plan is None:
            say('Nada que hacer: ya está publicado y en el índice.')
            return
        st = self.state(b)
        say(f'  En GitHub: {st.describe()}.')
        if st.kind == PUBLISHED:
            why = self.check_published(b, after_publish=False)
            if why:
                raise SystemExit(f'{repo} {tag} ya está publicado y no coincide con lo armado ({why}). Un release '
                                 'publicado no se cambia: armá una versión nueva.')
            if plan is None:
                say(f'Ya estaba publicado y coincide con lo armado. Falta el índice: `{self.cmd("index add " + b.spec)}`'
                    ' (con los demás paquetes del día).')
                return
            say('  Ya estaba publicado y coincide con lo armado: completo el índice.')
            self.sign(plan, on_fail=f'El release sigue publicado, sin índice. Volvé a correr `{again}` (o '
                                    f'`{self.cmd("index add " + b.spec)}` con los demás).')
        else:
            with tempfile.TemporaryDirectory(prefix='pes6pkg-') as tmp:
                resumed = self._ensure_draft(b, st, notes_file(tmp))
            if not self.run.dry_run:
                why = None if resumed else draft_mismatch(self.gh, b.info, b.files, self.state(b))
                if why:
                    raise SystemExit(f'Lo subido no coincide con lo armado ({why}): no se publica. `{again}` rehace el '
                                     f'borrador; `{again} --discard` lo borra.')
                say('  Borrador: lo subido coincide con lo armado.')
                if not self.ask('¿Publicar? (queda inmutable) Escribí "sí": '):
                    say(f'Quedó en borrador: no se publicó nada y el índice no cambió.\n'
                        f'  Para publicarlo: `{again}` (retoma el borrador).\n'
                        f'  Para borrarlo:   `{self.cmd(f"release {package_id} {version} --discard")}`.')
                    return
            if plan:
                self.sign(plan, on_fail=f'No se publicó nada: el borrador {tag} sigue en {repo}. Volvé a correr '
                                        f'`{again}`: retoma el borrador.')
            self.gh.release_publish(repo, tag)
            if not self.run.dry_run:
                say(f'  Publicado {repo} {tag}.')
                self.check_published(b, after_publish=True)
        if plan:
            self.write(plan, f'{b.info["name"]} {version}')
        else:
            say(f'Falta el índice: cuando estén publicados todos los del día, '
                f'`{self.cmd("index add <paquete>@<versión> …")}` con todos juntos.')

    def _ensure_draft(self, b: Built, st, notes):
        """Deja en GitHub un borrador igual a lo armado: retoma el que hay si coincide (devuelve True, ya comparado);
        si no, lo rehace."""
        repo, tag = b.info['repo'], b.info['tag']
        if st.kind == DRAFT:
            why = draft_mismatch(self.gh, b.info, b.files, st) if st.drafts == 1 else f'hay {st.drafts} borradores'
            if why is None:
                say(f'  Retomo el borrador {tag}: ya tiene lo armado.')
                return True
            say(f'  El borrador {tag} no coincide con lo armado ({why}): lo rehago (un borrador no es público).')
            delete_drafts(self.gh, repo, tag)
        create_draft(self.gh, b.info, b.files, notes)
        return False

    def discard(self, package_id, version):
        b = self.load(package_id, version)
        repo, tag = b.info['repo'], b.info['tag']
        if self.offline:
            say('(simulacro local) sin GitHub: no hay borrador que descartar.')
            return
        st = self.state(b)
        if st.kind == NONE:
            say(f'No hay release ni borrador {tag} en {repo}: nada que descartar.')
        elif st.kind == PUBLISHED:
            raise SystemExit(
                f'{repo} {tag} ya está publicado: no se descarta (es inmutable). Tampoco hace falta: mientras no esté '
                'en el índice, ningún jugador lo ve ni el actualizador lo baja. Para sumarlo al índice: '
                f'`{self.cmd("index add " + b.spec)}`. Si no querés publicarlo, armá una versión nueva (el tag no se '
                'puede reusar).')
        else:
            delete_drafts(self.gh, repo, tag)
            if not self.run.dry_run:
                say(f'Borrado el borrador {tag} de {repo}. No se publicó nada y el índice no cambió.')

    def index_add(self, specs):
        builts, seen = [], set()
        for s in specs:
            if s.count('@') != 1 or not all(s.split('@')):
                raise SystemExit(f'{s!r}: tiene que ser <paquete>@<versión> (por ejemplo translation-ru@1.0).')
            p, v = s.split('@')
            if p in seen:
                raise SystemExit(f'{p} aparece dos veces: un paquete va una sola vez por índice.')
            seen.add(p)
            builts.append(self.load(p, v))
        plan = self.plan(builts)
        if plan is None:
            say('Nada que hacer: todos ya están en el índice de main.')
            return
        problems = []
        for b in plan.builts:
            if self.offline:
                break
            problems += self.bundle_problems(b)
            st = self.state(b)
            rel = self.cmd(f'release {b.info["package"]} {b.info["version"]} --no-index')
            if st.kind == NONE:
                problems.append(f'{b.label}: no hay release {b.info["tag"]} en {b.info["repo"]}. Publicalo: `{rel}`.')
            elif st.kind == DRAFT:
                problems.append(f'{b.label}: {b.info["tag"]} está en borrador, sin publicar. `{rel}` lo retoma.')
            else:
                why = self.check_published(b, after_publish=False)
                if why:
                    problems.append(f'{b.label}: publicado, pero {why}. Si es una demora de GitHub, volvé a probar en '
                                    'unos minutos; si no, armá una versión nueva.')
                elif not st.immutable:
                    say(f'  AVISO: {b.info["repo"]} {b.info["tag"]} no tiene la marca de inmutable.')
        if problems:
            for p in problems:
                say(f'NO ESTÁ LISTO: {p}')
            raise SystemExit(f'{len(problems)} de {len(plan.builts)} paquetes no están listos: no se firmó nada ni se '
                             'abrió ningún PR.')
        self.sign(plan, on_fail='Los releases siguen publicados, sin índice. Volvé a correr el mismo `index add`.')
        n = len(plan.builts)
        self.write(plan, plan.builts[0].info['name'] + ' ' + plan.builts[0].info['version'] if n == 1
                   else f'{n} paquetes')

    def renew(self, first=False):
        plan = self.plan([], renew=True, first=first)
        self.sign(plan)
        self.write(plan, 'renovación')
