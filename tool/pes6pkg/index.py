"""El índice del repo: leerlo comprobado, armar el siguiente y firmarlo (design §4.3, PUB-5, PUB-6)."""
from datetime import timedelta
from pathlib import Path

from . import jsonr, minisig, model, verify


def paths(repo: Path):
    return repo / 'index' / 'index.json', repo / 'index' / 'index.json.minisig'


def load(repo: Path, ring, check_expiry_at=None, trust_revoked=True):
    """El índice actual del repo, comprobado con el llavero (firma, campos, comentario). Vencido se acepta (para
    renovarlo) salvo que se pida `check_expiry_at`. Firmado por una clave revocada se acepta solo con `trust_revoked`
    (el último índice antes de una rotación); la CI usa `trust_revoked=False`. None si todavía no hay índice."""
    ip, sp = paths(repo)
    if not ip.exists():
        return None
    data, sig = ip.read_bytes(), sp.read_text(encoding='utf-8')
    if b'\r' in data:
        raise SystemExit(f'{ip} tiene CR: git lo convirtió. Revisá .gitattributes (-text) y volvé a hacer checkout.')
    try:
        idx, comment = minisig.verify(data, sig, ring.keys, () if trust_revoked else ring.revoked_ids())
        doc = jsonr.loads(data)
        serial, issued, expires = model.validate_index(doc)
    except (minisig.MinisigError, jsonr.JsonError, model.ModelError) as e:
        raise SystemExit(f'El índice del repo no pasa la comprobación: {e}')
    if comment != model.index_comment(serial):
        raise SystemExit('El índice del repo tiene otro comentario confiable que su serial.')
    if check_expiry_at is not None and check_expiry_at >= expires:
        raise SystemExit(f'El índice del repo venció el {model.format_utc(expires)}.')
    return doc


def expires_of(doc):
    return model.parse_utc(doc['expires'])


def next_index(prev, now, entries=(), days=model.DEFAULT_LIFETIME_DAYS):
    """El índice siguiente: serial + 1, emitido ahora, vence en `days` días; `entries` reemplaza o suma paquetes."""
    if days < 1 or days > model.MAX_LIFETIME_DAYS:
        raise SystemExit(f'El vencimiento va de 1 a {model.MAX_LIFETIME_DAYS} días.')
    pkgs = {e['package']: e for e in (prev['packages'] if prev else [])}
    for e in entries:
        old = pkgs.get(e['package'])
        if old and model.compare_versions(e['version'], old['version']) <= 0:
            raise SystemExit(f'{e["package"]} {e["version"]} no es más nueva que la publicada ({old["version"]}).')
        pkgs[e['package']] = e
    now = now.replace(microsecond=0)
    doc = {
        'type': model.INDEX_TYPE,
        'schema': model.SCHEMA,
        'serial': (prev['serial'] + 1) if prev else 1,
        'issued': model.format_utc(now),
        'expires': model.format_utc(now + timedelta(days=days)),
        'packages': sorted(pkgs.values(), key=lambda e: e['package']),
    }
    model.validate_index(doc)
    return doc


def sign(doc, signer, ring):
    data = jsonr.dumps(doc)
    sig = signer.sign(data, model.index_comment(doc['serial']))
    # se comprueba como un cliente (sin estado), antes de escribir nada
    verify.check_index(data, sig, ring.keys, verify.State(revoked=ring.revoked_ids()), model.parse_utc(doc['issued']))
    return data, sig


def write(repo: Path, data: bytes, sig: str):
    ip, sp = paths(repo)
    ip.parent.mkdir(parents=True, exist_ok=True)
    ip.write_bytes(data)
    sp.write_bytes(sig.encode('utf-8'))
