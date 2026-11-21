"""Recetas (`packages/*.json`) y armado de un paquete: manifiesto firmado y zip determinista (design §4.4, §8.1)."""
import fnmatch
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import jsonr, model, pever, verify


class BuildError(SystemExit):
    pass


RECIPE_FORMATS = ('pes6pkg-recipe/1',)
RECIPE_DRAFT = 'pes6pkg-recipe-draft/1'  # el provisional de pes6xlife-translations (L-1); se acepta con aviso


def recipe_path(package, recipes_dir=None, repo=None):
    """Dónde está la receta: `--recipes <carpeta>`, o `./packages/`, o `packages/` de pes6-package-pc."""
    for d in ([Path(recipes_dir)] if recipes_dir else []) + [Path.cwd() / 'packages'] + ([repo / 'packages'] if repo else []):
        f = d / f'{package}.json'
        if f.exists():
            return f
    raise BuildError(f'No hay receta para {package} (buscada en --recipes, ./packages y el repo central)')


def load_recipe(path: Path, package: str):
    """Formato `pes6pkg-recipe/1` (packages/README.md): package, name, release {repo, tag, archive}, requires y
    files[] con path o glob (+ min), install, pe_version, embeds_keys, mode; `from` es solo una nota para quien arma."""
    raw = json.loads(Path(path).read_text(encoding='utf-8'))
    fmt_name = raw.get('recipe')
    if fmt_name == RECIPE_DRAFT:
        print(f'  aviso: {Path(path).name} usa el formato provisional; cambiá "recipe" a "{RECIPE_FORMATS[0]}"')
    elif fmt_name not in RECIPE_FORMATS:
        raise BuildError(f'{path}: "recipe" tiene que ser "{RECIPE_FORMATS[0]}"')
    if raw.get('package') != package:
        raise BuildError(f'La receta {path} es de {raw.get("package")}, no de {package}')
    rel = raw.get('release') or {}
    for k in ('repo', 'tag', 'archive'):
        if not isinstance(rel.get(k), str) or '{version}' not in rel[k] and k != 'repo':
            raise BuildError(f'{path}: falta release.{k} (con {{version}} en tag y archive)')
    if not isinstance(raw.get('name'), str) or not isinstance(raw.get('files'), list):
        raise BuildError(f'{path}: faltan name o files')
    for r in raw['files']:
        if ('path' in r) == ('glob' in r):
            raise BuildError(f'{path}: cada archivo lleva path o glob (uno de los dos)')
    raw.setdefault('requires', [])
    return raw


def fmt(template, version):
    return template.replace('{version}', version)


def collect(recipe, root: Path):
    """[(ruta del paquete, bytes, regla)] según la receta, desde la carpeta `root` (con la misma estructura que el zip)."""
    out, covered = [], set()
    for rule in recipe['files']:
        install = rule.get('install', True)
        if 'path' in rule:
            matches = [rule['path']]
            if not (root / rule['path']).is_file():
                raise BuildError(f'Falta {rule["path"]} en {root}')
        else:
            pat = rule['glob']
            base = root / pat.rsplit('/', 1)[0]
            names = sorted(p.name for p in base.iterdir() if p.is_file()) if base.is_dir() else []
            matches = [f'{pat.rsplit("/", 1)[0]}/{n}' for n in names if fnmatch.fnmatchcase(n, pat.rsplit('/', 1)[1])]
            if len(matches) < rule.get('min', 1):
                raise BuildError(f'{pat}: {len(matches)} archivos en {root}, la receta pide al menos {rule.get("min", 1)}')
        for m in matches:
            if not model.path_allowed(recipe['package'], m, install):
                raise BuildError(f'{recipe["package"]} no puede llevar {m} (rutas permitidas, VER-9)')
            covered.add(m.lower())
            out.append((m, (root / m).read_bytes(), rule))
    extra = [str(p.relative_to(root)).replace('\\', '/') for p in root.rglob('*') if p.is_file()]
    extra = [e for e in extra if e.lower() not in covered]
    return out, extra


def check_binaries(files, version, ring):
    """PUB-4 (versión) y KEY-3/KEY-8 (claves embebidas)."""
    want = model.parse_version(version)
    for path, data, rule in files:
        if rule.get('pe_version'):
            v = pever.read_versions(data)
            if v is None:
                raise BuildError(f'{path} no tiene recurso de versión')
            for label, got in (('FileVersion', v[0]), ('ProductVersion', v[1])):
                if got != want:
                    raise BuildError(f'{path}: {label} {".".join(map(str, got))}, el paquete es {version} (PUB-4)')
        if rule.get('embeds_keys'):
            for k in ring.embedded():
                if k.key not in data:
                    raise BuildError(f'{path} no trae la clave {k.id_hex} de {"prueba" if ring.test else "keys/"} '
                                     '(¿se compiló con otro pes6pkg_keys.h?)')
            if not ring.test:
                from . import keys as keys_mod
                for t in keys_mod.load_test(('k1', 'k2', 'k3', 'otra')).keys:
                    if t.key in data:
                        raise BuildError(f'{path} trae una clave de PRUEBA ({t.comment}): no se publica (KEY-8)')


def manifest_doc(recipe, version, released, files):
    return {
        'type': model.MANIFEST_TYPE,
        'schema': model.SCHEMA,
        'package': recipe['package'],
        'name': recipe['name'],
        'version': version,
        'released': released,
        'requires': recipe.get('requires', []),
        'files': [dict({'path': p, 'size': len(d), 'sha256': hashlib.sha256(d).hexdigest(),
                        'install': r.get('install', True)}, **({'mode': r['mode']} if 'mode' in r else {}))
                  for p, d, r in files],
    }


def deterministic_zip(entries, released):
    """Zip sin variaciones: orden por ruta, fecha fija, atributos fijos, deflate 9."""
    y, m, d = (int(x) for x in released.split('-'))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for name, data in sorted(entries, key=lambda e: e[0]):
            info = zipfile.ZipInfo(name, (y, m, d, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 0
            info.external_attr = 0x20
            z.writestr(info, data, compresslevel=9)
    return buf.getvalue()


def check_folder(folder: Path, ring, use_minisign=True):
    """Comprueba `out/<paquete>/<versión>` como un cliente: el zip, su manifiesto y, si el zip trae otros paquetes
    incluidos (`bundles` de build.json), que sean esos y con esos manifiestos. Devuelve (build.json, manifiesto)."""
    info = json.loads((folder / 'build.json').read_text(encoding='utf-8'))
    zb = (folder / info['archive']['name']).read_bytes()
    mb = (folder / info['manifest']['name']).read_bytes()
    ms = (folder / (info['manifest']['name'] + '.minisig')).read_text(encoding='utf-8')
    verify.check_bytes(zb, info['archive'])
    verify.check_bytes(mb, info['manifest'])
    doc = verify.check_manifest(mb, ms, ring.keys, verify.State(revoked=ring.revoked_ids()), info['package'],
                                info['version'])
    bundles = info.get('bundles') or []
    want = sorted([info['package']] + [b['package'] for b in bundles])
    res = verify.check_zip(zb, ring.keys, verify.State(revoked=ring.revoked_ids()), want)
    got = sorted(d['package'] for d, _ in res)
    if got != want:
        raise verify.VerifyError('E_WRONG_PACKAGE', f'el zip trae {", ".join(got)}; build.json dice {", ".join(want)}')
    entries = {e.name: e for e in verify.open_zip(zb)}
    for b in [{'package': info['package'], 'manifest': info['manifest']}] + bundles:
        e = entries[model.manifest_zip_path(b['package'])]
        inner = verify.read_entry(zb, e, e.usize)
        if hashlib.sha256(inner).hexdigest() != b['manifest']['sha256']:
            raise verify.VerifyError('E_HASH', f'el manifiesto de {b["package"]} del zip no es el de build.json')
    exe = None
    if use_minisign and not ring.test:
        from . import signer
        exe = signer.find_minisign(required=False, pinned=False)
    if exe and not signer.minisign_verify(exe, mb, ms, ring.active()):
        raise verify.VerifyError('E_BAD_SIGNATURE', 'minisign -V no acepta la firma del manifiesto')
    if exe:
        print('  minisign -V: la firma del manifiesto vale.', flush=True)
    return info, doc


def bundle_from(folder: Path, ring):
    """Un paquete ya armado para incluir en otro zip, sin volver a firmarlo: (build.json, [(entrada, bytes)])."""
    folder = Path(folder)
    if not (folder / 'build.json').exists():
        raise BuildError(f'--bundle {folder}: no hay build.json (tiene que ser out\\<paquete>\\<versión> ya armado)')
    try:
        info, _ = check_folder(folder, ring, use_minisign=False)
    except verify.VerifyError as e:
        raise BuildError(f'--bundle {folder}: NO PASA ({e.code}): {e}')
    if bool(info.get('test_keys')) != ring.test:
        raise BuildError(f'--bundle {folder}: se armó con otras claves que este paquete')
    if info.get('bundles'):
        raise BuildError(f'--bundle {folder}: ese paquete ya incluye otros; no se anidan')
    zb = (folder / info['archive']['name']).read_bytes()
    return info, [(e.name, verify.read_entry(zb, e, e.usize)) for e in verify.open_zip(zb)]


def find_bundle(out_dir: Path, package, ring):
    """Para `"bundles"` en la receta sin --bundle: la versión más nueva armada en out/<paquete>/."""
    base = Path(out_dir) / package
    versions = [d.name for d in base.iterdir() if (d / 'build.json').exists() and model.parse_version(d.name)] \
        if base.is_dir() else []
    if not versions:
        raise BuildError(f'La receta pide incluir {package}, y no hay ninguno armado en {base}: armalo antes, o pasá '
                         f'--bundle <carpeta>.')
    best = max(versions, key=model.parse_version)
    print(f'  incluyo {package} {best} ({base / best}): la versión más nueva armada', flush=True)
    return base / best


def build(repo, package, version, root, out_dir, signer, ring, released=None, recipes_dir=None, requires=None,
          bundles=None):
    if model.parse_version(version) is None:
        raise BuildError(f'Versión inválida: {version}')
    recipe = load_recipe(recipe_path(package, recipes_dir, repo), package)
    if requires:
        recipe['requires'] = requires
    released = released or datetime.now(timezone.utc).strftime('%Y-%m-%d')
    files, extra = collect(recipe, Path(root))
    for e in extra:
        print(f'  aviso: {e} está en la carpeta pero no en la receta: no va en el paquete')
    check_binaries(files, version, ring)
    doc = manifest_doc(recipe, version, released, files)
    model.validate_manifest(doc)
    mpath = model.manifest_zip_path(package)
    # Paquetes incluidos (--bundle, o "bundles" en la receta): se comprueba todo antes de pedir la contraseña
    dirs = [Path(b) for b in bundles or []]
    have = set()
    for d in dirs:
        if (d / 'build.json').exists():
            have.add(json.loads((d / 'build.json').read_text(encoding='utf-8')).get('package'))
    dirs += [find_bundle(out_dir, p, ring) for p in recipe.get('bundles', []) if p not in have]
    own = {p.lower() for p, _, _ in files} | {mpath.lower(), mpath.lower() + '.minisig'}
    included, extra_entries = [], []
    for d in dirs:
        binfo, entries = bundle_from(d, ring)
        bp = binfo['package']
        if bp == package or any(i['package'] == bp for i in included):
            raise BuildError(f'{bp} aparece dos veces en el paquete')
        need = next((r['min'] for r in doc['requires'] if r['package'] == bp), None)
        if need is None:
            raise BuildError(f'{package} no pide {bp} en "requires": no lo incluyo (sumalo a la receta con su versión '
                             'mínima)')
        if model.compare_versions(binfo['version'], need) < 0:
            raise BuildError(f'{package} pide {bp} {need} o más nueva, y {d} es la {binfo["version"]}')
        for name, _ in entries:
            if name.lower() in own:
                raise BuildError(f'{name} está en {package} y en {bp}: un nombre por zip. Los documentos de cada '
                                 f'paquete van en {model.DOCS_DIR}/<paquete>/ (packages/README.md).')
            own.add(name.lower())
        extra_entries += entries
        included.append({'package': bp, 'version': binfo['version'], 'manifest': binfo['manifest'],
                         'archive_sha256': binfo['archive']['sha256']})
        print(f'  incluye {bp} {binfo["version"]} tal cual está armado (sin volver a firmarlo)', flush=True)
    mbytes = jsonr.dumps(doc)
    msig = signer.sign(mbytes, model.manifest_comment(package, version))
    zbytes = deterministic_zip([(p, d) for p, d, _ in files] + [(mpath, mbytes), (mpath + '.minisig', msig.encode())]
                               + extra_entries, released)
    # Comprobación como un cliente, con el llavero que firmó: todos los paquetes del zip
    allowed = [package] + [i['package'] for i in included]
    res = verify.check_zip(zbytes, ring.keys, verify.State(revoked=ring.revoked_ids()), packages_allowed=allowed)
    if sorted(d['package'] for d, _ in res) != sorted(allowed):
        raise BuildError('el zip armado no trae los paquetes esperados')
    out = Path(out_dir) / package / version
    out.mkdir(parents=True, exist_ok=True)
    archive = fmt(recipe['release']['archive'], version)
    mname = f'{package}-{version}.manifest.json'
    (out / archive).write_bytes(zbytes)
    (out / mname).write_bytes(mbytes)
    (out / (mname + '.minisig')).write_bytes(msig.encode())
    info = {
        'package': package, 'name': recipe['name'], 'version': version, 'released': released,
        'repo': recipe['release']['repo'], 'tag': fmt(recipe['release']['tag'], version),
        'archive': {'name': archive, 'size': len(zbytes), 'sha256': hashlib.sha256(zbytes).hexdigest()},
        'manifest': {'name': mname, 'size': len(mbytes), 'sha256': hashlib.sha256(mbytes).hexdigest()},
        'test_keys': ring.test,
    }
    if included:
        info['bundles'] = included
    (out / 'build.json').write_text(json.dumps(info, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return out, info


def release_urls(info):
    base = f'https://github.com/{info["repo"]}/releases'
    return (f'{base}/download/{info["tag"]}/{info["archive"]["name"]}',
            f'{base}/download/{info["tag"]}/{info["manifest"]["name"]}',
            f'{base}/tag/{info["tag"]}')


def index_entry(info):
    archive_url, manifest_url, notes = release_urls(info)
    return {
        'package': info['package'], 'name': info['name'], 'version': info['version'], 'released': info['released'],
        'notes': notes,
        'manifest': {'url': manifest_url, 'size': info['manifest']['size'], 'sha256': info['manifest']['sha256']},
        'archive': {'url': archive_url, 'size': info['archive']['size'], 'sha256': info['archive']['sha256']},
    }
