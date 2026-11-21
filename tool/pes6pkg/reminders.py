"""Avisos de vencimiento del índice (PUB-10 a PUB-12): el issue de la CI, el cartel de cada comando y el calendario."""
import sys
from datetime import date, timedelta

THRESHOLDS = (30, 21, 14, 7, 3, 1)
LABEL = 'vencimiento'
WORKFLOW = 'vencimiento.yml'
CALENDAR_DAYS = (30, 14, 7, 1)


def days_left(expires_dt, today: date):
    return (expires_dt.date() - today).days


def banner(expires_dt, today: date):
    """El cartel de PUB-11, o None si faltan más de 30 días."""
    d = days_left(expires_dt, today)
    fecha = expires_dt.date().isoformat()
    if d > 30:
        return None
    if d <= 0:
        return (f'VENCIDO: el índice venció el {fecha}: los jugadores no ven avisos de actualización. '
                'Corré: pes6pkg renew')
    return f'ATENCIÓN: el índice vence el {fecha} (faltan {d} días). Corré: pes6pkg renew'


def print_banner(expires_dt, today: date, end=False):
    text = banner(expires_dt, today)
    if text and (not end or days_left(expires_dt, today) <= 7):
        print('=' * len(text), file=sys.stderr)
        print(text, file=sys.stderr)
        print('=' * len(text), file=sys.stderr)


def _marker(today):
    return f'<!-- pes6pkg-aviso {today.isoformat()} -->'


def _message(owner, expires_dt, today):
    d = days_left(expires_dt, today)
    fecha = expires_dt.date().isoformat()
    head = (f'@{owner} el índice firmado de pes6-package-pc **venció el {fecha}**: los jugadores ya no ven avisos de '
            'actualización.' if d <= 0 else
            f'@{owner} el índice firmado de pes6-package-pc **vence el {fecha}** (faltan {d} días).')
    return (f'{head}\n\nPara renovarlo (docs/RECETA.md, "Renovar"):\n\n'
            '1. `pes6pkg renew` en tu máquina (te pide la contraseña de la clave de uso).\n'
            '2. Mergeá el PR que abre.\n'
            '3. `pes6pkg verify-live`, e importá el `.ics` nuevo en tu calendario.\n\n'
            f'Este aviso se repite a los {", ".join(map(str, THRESHOLDS))} días y todos los días después de vencido. '
            'Se cierra solo cuando `main` tiene el índice renovado.\n\n' + _marker(today))


def run(gh, repo, owner, expires_dt, today: date):
    """Un paso de la tarea diaria. Devuelve qué hizo ('creado', 'comentado', 'cerrado', 'nada')."""
    title = f'El índice vence el {expires_dt.date().isoformat()}'
    d = days_left(expires_dt, today)
    issues = gh.issues_open(repo, LABEL)
    done = 'nada'
    for i in issues:  # issues de un vencimiento anterior: ya se renovó
        if i['title'] != title:
            gh.issue_close(repo, i['number'], f'Renovado: el índice de `main` vence el {expires_dt.date().isoformat()}.')
            done = 'cerrado'
    if d > 30:
        gh.workflow_enable(repo, WORKFLOW)
        return done
    current = next((i for i in issues if i['title'] == title), None)
    if current is None:
        gh.issue_create(repo, title, _message(owner, expires_dt, today), LABEL, owner)
        done = 'creado'
    elif d in THRESHOLDS or d <= 0:
        bodies = [current.get('body') or ''] + gh.issue_comments(repo, current['number'])
        if not any(_marker(today) in b for b in bodies):
            gh.issue_comment(repo, current['number'], _message(owner, expires_dt, today))
            done = 'comentado'
    gh.workflow_enable(repo, WORKFLOW)  # PUB-10: que GitHub no la apague por inactividad
    return done


def ics(expires_dt, serial):
    """Recordatorios de calendario (PUB-12): un evento de día entero a los 30, 14, 7 y 1 días, con alarma a las 9."""
    fecha = expires_dt.date()
    lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//pes6pkg//recordatorios del indice//ES', 'CALSCALE:GREGORIAN']
    stamp = expires_dt.strftime('%Y%m%dT%H%M%SZ')
    for n in CALENDAR_DAYS:
        day = fecha - timedelta(days=n)
        lines += [
            'BEGIN:VEVENT',
            f'UID:pes6pkg-indice-{serial}-{n}d@pes6-package-pc',
            f'DTSTAMP:{stamp}',
            f'DTSTART;VALUE=DATE:{day.strftime("%Y%m%d")}',
            f'DTEND;VALUE=DATE:{(day + timedelta(days=1)).strftime("%Y%m%d")}',
            f'SUMMARY:PES6: renovar el índice firmado (vence el {fecha.isoformat()}\\, faltan {n} días)',
            'DESCRIPTION:En tu máquina: pes6pkg renew\\, mergeá el PR y corré pes6pkg verify-live (docs/RECETA.md).',
            'BEGIN:VALARM', 'ACTION:DISPLAY', 'DESCRIPTION:Renovar el índice de pes6-package-pc', 'TRIGGER:PT9H',
            'END:VALARM',
            'END:VEVENT',
        ]
    lines.append('END:VCALENDAR')
    return '\r\n'.join(lines) + '\r\n'
