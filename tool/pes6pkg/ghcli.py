"""Lo que la herramienta le pide a `gh` y a `git`. Todo pasa por `run`, así las pruebas lo reemplazan por uno falso y
`--dry-run` solo muestra los comandos."""
import json
import subprocess


class Runner:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.log = []

    def __call__(self, argv, capture=True, check=True, cwd=None):
        self.log.append(list(argv))
        if self.dry_run:
            print('  (simulado) ' + ' '.join(argv))
            return ''
        r = subprocess.run(argv, capture_output=capture, text=True, encoding='utf-8', cwd=cwd)
        if check and r.returncode != 0:
            raise SystemExit(f'Falló: {" ".join(argv)}\n{(r.stderr or "").strip()}')
        return r.stdout if capture else ''


class Gh:
    def __init__(self, run: Runner):
        self.run = run

    def release_exists(self, repo, tag):
        out = self.run(['gh', 'release', 'list', '--repo', repo, '--json', 'tagName', '--limit', '200'], check=False)
        return bool(out) and any(r['tagName'] == tag for r in json.loads(out))

    def release_create_draft(self, repo, tag, title, notes_file, files):
        self.run(['gh', 'release', 'create', tag, '--repo', repo, '--draft', '--title', title,
                  '--notes-file', str(notes_file), *[str(f) for f in files]])

    def release_download(self, repo, tag, directory):
        self.run(['gh', 'release', 'download', tag, '--repo', repo, '--dir', str(directory), '--clobber'])

    def release_publish(self, repo, tag):
        self.run(['gh', 'release', 'edit', tag, '--repo', repo, '--draft=false'])

    def verify_asset(self, repo, tag, path):
        return self.run(['gh', 'release', 'verify-asset', tag, str(path), '--repo', repo], check=False)

    def pr_create(self, repo, branch, title, body):
        return self.run(['gh', 'pr', 'create', '--repo', repo, '--head', branch, '--base', 'main', '--title', title,
                         '--body', body])

    def issues_open(self, repo, label):
        out = self.run(['gh', 'issue', 'list', '--repo', repo, '--label', label, '--state', 'open',
                        '--json', 'number,title,body', '--limit', '50'])
        return json.loads(out) if out else []

    def issue_comments(self, repo, number):
        out = self.run(['gh', 'issue', 'view', str(number), '--repo', repo, '--json', 'comments'])
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
        out = self.run(['gh', 'workflow', 'view', workflow, '--repo', repo, '--json', 'state'], check=False)
        try:
            return json.loads(out)['state'] if out else None
        except (ValueError, KeyError):
            return None
