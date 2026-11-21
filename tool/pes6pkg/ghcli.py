"""Lo que la herramienta le pide a `gh` y a `git`. Todo pasa por `run`, así las pruebas lo reemplazan por uno falso y
`--dry-run` solo muestra lo que escribiría."""
import json
import subprocess

REAL, DRY, LOCAL = 'real', 'simulado', 'local'


def _show(argv):
    """El comando en una línea, sin los textos largos (el cuerpo de un PR, las notas)."""
    parts = []
    for a in argv:
        a = str(a)
        if len(a) > 70 or '\n' in a:
            a = (a.splitlines() or [''])[0][:40] + '…'
        parts.append(f'"{a}"' if ' ' in a else a)
    return ' '.join(parts)


class Runner:
    """Corre comandos. Modos: `real` corre todo; `simulado` (`--dry-run`) corre solo las lecturas (`read=True`) y
    muestra las escrituras; `local` (simulacro con claves de prueba) no corre nada ni usa la red."""

    def __init__(self, mode=REAL):
        if mode is True or mode is False:  # compatibilidad: Runner(dry_run)
            mode = DRY if mode else REAL
        if mode not in (REAL, DRY, LOCAL):
            raise ValueError(mode)
        self.mode = mode
        self.log = []
        self.echo = True  # en modo real, muestra cada escritura antes de correrla

    @property
    def dry_run(self):
        return self.mode != REAL

    @property
    def offline(self):
        return self.mode == LOCAL

    def __call__(self, argv, capture=True, check=True, cwd=None, read=False, binary=False):
        self.log.append(list(argv))
        if self.mode == LOCAL or (self.mode == DRY and not read):
            print('  (simulado) ' + _show(argv), flush=True)
            return b'' if binary else ''
        if not read and self.echo:
            print('  $ ' + _show(argv), flush=True)
        if binary:
            r = subprocess.run(argv, capture_output=True, cwd=cwd)
            if check and r.returncode != 0:
                raise SystemExit(f'Falló: {" ".join(argv)}\n{r.stderr.decode("utf-8", "replace").strip()}')
            return r.stdout if r.returncode == 0 else b''
        r = subprocess.run(argv, capture_output=capture, text=True, encoding='utf-8', cwd=cwd)
        if check and r.returncode != 0:
            raise SystemExit(f'Falló: {" ".join(argv)}\n{(r.stderr or "").strip()}')
        return r.stdout if capture else ''


class Gh:
    def __init__(self, run: Runner):
        self.run = run

    # ------------------------------------------------------------ releases
    def release_list(self, repo):
        """[{tagName, isDraft, isImmutable}] de los releases del repo, borradores incluidos."""
        out = self.run(['gh', 'release', 'list', '--repo', repo, '--json', 'tagName,isDraft,isImmutable',
                        '--limit', '1000'], read=True)
        return json.loads(out) if out else []

    def release_exists(self, repo, tag):
        return any(r['tagName'] == tag for r in self.release_list(repo))

    def release_view(self, repo, tag):
        """{isDraft, isImmutable, assets: [{name, size, digest}]} (gh también encuentra un borrador por su tag)."""
        out = self.run(['gh', 'release', 'view', tag, '--repo', repo, '--json', 'tagName,isDraft,isImmutable,assets'],
                       read=True)
        return json.loads(out) if out else None

    def release_create_draft(self, repo, tag, title, notes_file, files):
        self.run(['gh', 'release', 'create', tag, '--repo', repo, '--draft', '--title', title,
                  '--notes-file', str(notes_file), *[str(f) for f in files]])

    def release_upload(self, repo, tag, files):
        self.run(['gh', 'release', 'upload', tag, '--repo', repo, *[str(f) for f in files]])

    def release_download(self, repo, tag, directory):
        self.run(['gh', 'release', 'download', tag, '--repo', repo, '--dir', str(directory), '--clobber'], read=True)

    def release_publish(self, repo, tag):
        self.run(['gh', 'release', 'edit', tag, '--repo', repo, '--draft=false'])

    def release_delete(self, repo, tag):
        """Borra el release (solo se usa con borradores: lo comprueba quien llama)."""
        self.run(['gh', 'release', 'delete', tag, '--repo', repo, '--yes'])

    def verify_asset(self, repo, tag, path):
        return self.run(['gh', 'release', 'verify-asset', tag, str(path), '--repo', repo], check=False, read=True)

    # ------------------------------------------------------------ PR
    def pr_create(self, repo, branch, title, body):
        return self.run(['gh', 'pr', 'create', '--repo', repo, '--head', branch, '--base', 'main', '--title', title,
                         '--body', body])

    # ------------------------------------------------------------ issues y workflows (avisos de vencimiento)
    def issues_open(self, repo, label):
        out = self.run(['gh', 'issue', 'list', '--repo', repo, '--label', label, '--state', 'open',
                        '--json', 'number,title,body', '--limit', '50'], read=True)
        return json.loads(out) if out else []

    def issue_comments(self, repo, number):
        out = self.run(['gh', 'issue', 'view', str(number), '--repo', repo, '--json', 'comments'], read=True)
        return [c['body'] for c in json.loads(out)['comments']] if out else []

    def issue_create(self, repo, title, body, label, assignee):
        self.run(['gh', 'label', 'create', label, '--repo', repo, '--color', 'D93F0B',
                  '--description', 'Vencimiento del índice firmado'], check=False)
        self.run(['gh', 'issue', 'create', '--repo', repo, '--title', title, '--body', body, '--label', label,
                  '--assignee', assignee])

    def issue_comment(self, repo, number, body):
        self.run(['gh', 'issue', 'comment', str(number), '--repo', repo, '--body', body])

    def issue_close(self, repo, number, comment):
        self.run(['gh', 'issue', 'close', str(number), '--repo', repo, '--comment', comment])

    def workflow_enable(self, repo, workflow):
        self.run(['gh', 'workflow', 'enable', workflow, '--repo', repo], check=False)

    def workflow_state(self, repo, workflow):
        out = self.run(['gh', 'workflow', 'view', workflow, '--repo', repo, '--json', 'state'], check=False, read=True)
        try:
            return json.loads(out)['state'] if out else None
        except (ValueError, KeyError):
            return None
