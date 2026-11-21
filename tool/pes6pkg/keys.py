"""Llaveros: las claves públicas de producción (`keys/`) y las de prueba (KEY-3, KEY-8)."""
import json
from dataclasses import dataclass
from pathlib import Path

from . import minisig

ROLES = ('uso', 'reserva', 'revocada')


@dataclass
class Keyring:
    keys: list  # PublicKey, en el orden embebido (K1, K2, …)
    roles: list  # rol de cada una
    test: bool
    signing: dict  # solo en el de prueba: key_id -> TestKey
    files: list = None  # nombre del .pub de cada una (producción)

    def secret_name(self, role='uso'):
        """El nombre de la clave secreta del rol: `k2.pub` -> `k2.key`."""
        for f, r in zip(self.files or [], self.roles):
            if r == role:
                return f[:-len('.pub')] + '.key'
        raise SystemExit(f'No hay clave con rol {role} en keys/keys.json')

    def active(self):
        """La clave con la que se firma todo (KEY-4)."""
        for k, r in zip(self.keys, self.roles):
            if r == 'uso':
                return k
        raise SystemExit('No hay clave de uso en keys/keys.json')

    def revoked_ids(self):
        return [k.key_id for k, r in zip(self.keys, self.roles) if r == 'revocada']

    def embedded(self):
        """Las que van embebidas en los clientes: todas menos las revocadas, en orden."""
        return [k for k, r in zip(self.keys, self.roles) if r != 'revocada']


def load_production(repo: Path) -> Keyring:
    meta = repo / 'keys' / 'keys.json'
    if not meta.exists():
        raise SystemExit('Todavía no hay claves de producción: el usuario corre `pes6pkg keys new`.')
    data = json.loads(meta.read_text(encoding='utf-8'))
    keys, roles, files = [], [], []
    for e in data['keys']:
        pk = minisig.parse_public_key((repo / 'keys' / e['file']).read_text(encoding='utf-8'))
        if pk.id_hex != e['id']:
            raise SystemExit(f'keys.json: el id de {e["file"]} es {pk.id_hex}, no {e["id"]}')
        if e['role'] not in ROLES:
            raise SystemExit(f'keys.json: rol desconocido {e["role"]!r}')
        if minisig.TEST_MARK in pk.comment:
            raise SystemExit(f'keys/{e["file"]} es una clave de prueba: no va en keys/ (KEY-8)')
        keys.append(pk)
        roles.append(e['role'])
        files.append(e['file'])
    return Keyring(keys, roles, False, {}, files)


def rotate_meta(data, new_file, new_id, today):
    """keys.json después de rotar (KEY-5): la de uso pasa a revocada, la de reserva a uso y la nueva a reserva."""
    roles = [e['role'] for e in data['keys']]
    if roles.count('uso') != 1 or roles.count('reserva') != 1:
        raise SystemExit('keys.json tiene que tener una clave de uso y una de reserva para rotar')
    out = {'keys': []}
    for e in data['keys']:
        e = dict(e)
        if e['role'] == 'uso':
            e['role'], e['revoked'] = 'revocada', today
        elif e['role'] == 'reserva':
            e['role'] = 'uso'
        out['keys'].append(e)
    out['keys'].append({'id': new_id, 'file': new_file, 'role': 'reserva', 'created': today})
    return out


def load_test(names=('k1', 'k2')) -> Keyring:
    tks = [minisig.TestKey.derive(n) for n in names]
    return Keyring([t.public for t in tks], ['uso'] + ['reserva'] * (len(tks) - 1), True,
                   {t.key_id: t for t in tks})


def c_header(ring: Keyring, min_serial: int, generated: str, test=False):
    """`client/pes6pkg_keys.h` (o el de prueba). Las claves van en el orden del llavero, sin las revocadas."""
    name = 'TEST' if test else 'PRODUCTION'
    lines = [
        f'// Generado por `pes6pkg keys export` el {generated}. No editar a mano.',
        '// ' + ('CLAVES DE PRUEBA: nunca en un build público (KEY-8).' if test else
                 'Claves públicas de producción de PES6 HD Text y sus mods (design §7). Orden: uso, reserva.'),
        '#pragma once',
        '#include "pes6pkg_client.h"',
        '',
        'namespace pes6pkg {',
        '',
        f'static const PublicKey {name}_KEYS[] = {{',
    ]
    for k, r in zip(ring.keys, ring.roles):
        if r == 'revocada':
            continue
        kid = ', '.join(f'0x{b:02x}' for b in k.key_id)
        key = ', '.join(f'0x{b:02x}' for b in k.key)
        lines.append(f'    {{{{{kid}}},  // {r}, id {k.id_hex}')
        lines.append(f'     {{{key}}}}},')
    lines += [
        '};',
        f'static const size_t {name}_KEY_COUNT = sizeof({name}_KEYS) / sizeof({name}_KEYS[0]);',
        f'static const uint64_t {name}_MIN_SERIAL = {min_serial};',
        '',
        '}  // namespace pes6pkg',
        '',
    ]
    return '\n'.join(lines)
