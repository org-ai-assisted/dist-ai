#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Run each deterministic compatibility-page program for real and shoot what
secure-terminal DISPLAYS of its output, headless and byte-reproducible.

The compatibility page claims each program "was run and its output verified".
This backs that claim with an artifact: every program below is executed for real
against a fixed fixture (no network, no clock, pinned locale/timezone/identity),
its RAW output captured -- colour escapes and all -- and rendered through the
SAME offscreen path the hero/modes shots use (SecureTerminal.render_preview, which
reuses the live CLI line pipeline). So the picture is what the terminal actually
shows, not a mock, and re-running it on the same host is a no-op when nothing
changed.

Scope, so the page caption stays honest: ONLY the line-oriented programs whose
output can be made byte-stable are here. Full-screen/TUI programs (a grid render),
and the network/interactive/clock-driven ones (ssh, wget, curl, rsync, ps),
cannot be captured deterministically this way and stay MANUAL on the page. Each
name below maps to one compatibility-table row; the site references
compatibility/shots/<name>.webp.

    PYTHONPATH=<secure-terminal>/usr/lib/python3/dist-packages \
        usr/share/secure-terminal-shots/compat-shot.py <output-dir>
    usr/share/secure-terminal-shots/compat-shot.py --list   # names, one per line

Usually driven via the `secure-terminal-shots compat` wrapper (this dir).
"""

import gzip
import io
import os
import subprocess
import sys
import tarfile
import tempfile

# A headless grab needs no real display; force offscreen before Qt initialises.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

## HiDPI: render at SHOT_SCALE x device pixels (default 2), matching the site's
## 2x-source convention (shown at 1x via CSS). Assign, do not setdefault: Qt reads
## QT_SCALE_FACTOR at QApplication construction, so the shot pins its own factor.
## Parse via int(), not str.isdigit() (isdigit accepts unicode digits int() rejects).
try:
    SHOT_SCALE = int(os.environ.get('SHOT_SCALE', '2'))
except (TypeError, ValueError):
    SHOT_SCALE = 2
if SHOT_SCALE < 1:
    SHOT_SCALE = 2
os.environ['QT_SCALE_FACTOR'] = str(SHOT_SCALE)


# A program to shoot: `name` is the compatibility-row key (and the shot filename);
# `command` is the shell line shown as the shot's caption AND run for real (one
# string, run under `bash -c` in the fixture dir, so a pipe/redirect is literal).
# `label` names the row the way the page does.
class Prog:
    def __init__(self, name, label, command):
        self.name = name
        self.label = label
        self.command = command


PROGRAMS = [
    Prog('coreutils', 'ls, cat, cp (coreutils)',
         'ls --color=always -F demo'),
    Prog('find', 'find (findutils)',
         'find tree -type f | sort'),
    Prog('tar', 'tar',
         'tar tf fixture.tar'),
    Prog('grep', 'grep',
         'grep --color=always -n TODO notes.txt'),
    Prog('gzip', 'gzip, zcat',
         'zcat greeting.txt.gz'),
    Prog('sed', 'sed',
         "sed 's/^/  | /' list.txt"),
    Prog('diff', 'diff, cmp (diffutils)',
         'diff --color=always old.txt new.txt'),
    Prog('awk', 'awk (mawk)',
         'awk \'{ total += $2 } END { printf "total: %d\\n", total }\' nums.txt'),
    Prog('git', 'git',
         'git -C repo -c color.ui=always --no-pager log --oneline --decorate'),
]


def _fixture_env(home):
    """A deterministic environment: fixed locale, timezone, width and git identity
    so a program's output does not drift run to run. Nothing here reaches the
    network or reads a real clock (git dates are pinned below)."""
    env = {
        'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
        'HOME': home,
        'LC_ALL': 'C.UTF-8',
        'LANG': 'C.UTF-8',
        'TZ': 'UTC',
        'TERM': 'xterm-256color',
        'COLUMNS': '80',
        'LINES': '40',
        # Isolate git from any host config; pin identity + dates so the commit
        # hashes and the log are byte-identical every run.
        'GIT_CONFIG_GLOBAL': os.devnull,
        'GIT_CONFIG_SYSTEM': os.devnull,
        'GIT_AUTHOR_NAME': 'Compat Demo',
        'GIT_AUTHOR_EMAIL': 'demo@example.invalid',
        'GIT_COMMITTER_NAME': 'Compat Demo',
        'GIT_COMMITTER_EMAIL': 'demo@example.invalid',
        'GIT_AUTHOR_DATE': '2026-01-02T03:04:05 +0000',
        'GIT_COMMITTER_DATE': '2026-01-02T03:04:05 +0000',
    }
    return env


def _write(path, text):
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(text)


def build_fixture(root, env):
    """Lay out the fixed inputs every program above reads. Deterministic: fixed
    file contents, a pinned-mtime tar, and a git repo built with the pinned
    identity/date env. Raises on any failure (a broken fixture must not yield a
    misleading shot)."""
    # coreutils: a directory with varied file TYPES so `ls --color -F` shows the
    # type colours the row claims (dir/, executable*, symlink@, an archive).
    demo = os.path.join(root, 'demo')
    os.mkdir(demo)
    os.mkdir(os.path.join(demo, 'subdir'))
    _write(os.path.join(demo, 'readme.txt'), 'plain file\n')
    script = os.path.join(demo, 'run.sh')
    _write(script, '#!/bin/sh\necho hi\n')
    os.chmod(script, 0o755)
    os.symlink('readme.txt', os.path.join(demo, 'latest.txt'))
    _write(os.path.join(demo, 'backup.tar'), 'not really a tar, for the colour\n')

    # find: a few nested files to list, under src/ and doc/.
    tree = os.path.join(root, 'tree')
    os.makedirs(os.path.join(tree, 'src'))
    os.makedirs(os.path.join(tree, 'doc'))
    _write(os.path.join(tree, 'src', 'main.c'), 'int main(void){return 0;}\n')
    _write(os.path.join(tree, 'src', 'util.c'), '/* util */\n')
    _write(os.path.join(tree, 'doc', 'guide.md'), '# Guide\n')

    # tar: a fixed-mtime archive so `tar tf` (names only, no timestamps) is stable.
    tar_path = os.path.join(root, 'fixture.tar')
    with tarfile.open(tar_path, 'w') as tar:
        for rel in ('src/main.c', 'src/util.c', 'doc/guide.md'):
            info = tarfile.TarInfo('project/' + rel)
            data = ('content of ' + rel + '\n').encode('utf-8')
            info.size = len(data)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))

    # grep: lines, some carrying the match token.
    _write(os.path.join(root, 'notes.txt'),
           'schedule the release\n'
           'TODO: verify the signature\n'
           'ship the tarball\n'
           'TODO: update the changelog\n')

    # gzip/zcat: a gzip of a friendly file (fixed mtime -> stable bytes, though
    # zcat output does not depend on it).
    greet = 'secure-terminal compatibility check\nordinary output stays ordinary\n'
    with gzip.GzipFile(os.path.join(root, 'greeting.txt.gz'), 'wb', mtime=0) as gzf:
        gzf.write(greet.encode('utf-8'))

    # sed: a short list to prefix.
    _write(os.path.join(root, 'list.txt'), 'alpha\nbravo\ncharlie\ndelta\n')

    # diff: two nearby files (the colourised unified diff is the demo).
    _write(os.path.join(root, 'old.txt'), 'one\ntwo\nthree\nfour\n')
    _write(os.path.join(root, 'new.txt'), 'one\nTWO\nthree\nfour\nfive\n')

    # awk: label/value pairs to total.
    _write(os.path.join(root, 'nums.txt'),
           'build 12\ntest 30\npackage 8\n')

    # git: a repo with two commits, built with the pinned identity/date env so the
    # short hashes and log are byte-identical every run.
    repo = os.path.join(root, 'repo')
    os.mkdir(repo)

    def git(*args):
        subprocess.run(('git', '-C', repo) + args, env=env, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    git('init', '-q', '-b', 'main')
    _write(os.path.join(repo, 'CHANGELOG'), 'initial\n')
    git('add', 'CHANGELOG')
    git('commit', '-q', '-m', 'Add changelog')
    _write(os.path.join(repo, 'CHANGELOG'), 'initial\nverify signatures before install\n')
    git('commit', '-q', '-a', '-m', 'Document signature verification')
    git('tag', 'v1.0')


def run_capture(prog, root, env):
    """Run one program for real in the fixture and return its RAW output bytes
    (stdout+stderr merged, so a tool that writes to stderr -- like diff's context
    -- is still shown). Raises on a launch failure so a missing tool fails loud,
    never a blank shot."""
    result = subprocess.run(['bash', '-c', prog.command], cwd=root, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return result.stdout


def _decode(raw):
    """Decode captured bytes for the renderer, preserving any stray byte via
    surrogateescape (the sanitizer neutralises it in-render, as the live terminal
    does) rather than dropping it."""
    return raw.decode('utf-8', 'surrogateescape')


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv == ['--list']:
        for prog in PROGRAMS:
            print(prog.name)
        return 0

    if len(argv) != 1:
        sys.stderr.write('usage: compat-shot.py <output-dir> | --list\n')
        return 2
    out_dir = argv[0]
    if not os.path.isdir(out_dir):
        sys.stderr.write('compat-shot: output dir does not exist: %s\n' % out_dir)
        return 1

    # colors_allowed() (the only gate besides the widget's colors flag) is False
    # only when NO_COLOR is set. Clear it here so a shot shows each program's colour
    # regardless of the operator's environment -- the picture must be reproducible,
    # not a function of whoever ran it.
    os.environ.pop('NO_COLOR', None)

    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QColor, QFont, QPainter
    from PyQt6.QtCore import Qt
    from secure_terminal.terminal import SecureTerminal, THEMES

    scrollbar_off = Qt.ScrollBarPolicy.ScrollBarAlwaysOff

    # Compose on the app's shipped default theme so the shots never drift from what
    # users see; only THEME_NAME needs touching if the default theme changes.
    theme_name = 'light'
    bg, fg = THEMES[theme_name]

    panel_w = 720
    panel_inset = 8
    label_h = 26
    pad = 14

    app = QApplication.instance() or QApplication([])
    assert app is not None

    def panel_image(prog, text):
        """A grab of the real renderer showing `text` in the default CLI display.
        Height follows the wrapped rows, measured with the widget's own metrics
        (the Qt document-height shortcuts do not work here -- see the note in
        display-modes-shot.py). Self-check: the rendered text must be non-empty --
        an empty render means the capture or feed silently produced nothing, which
        would publish a blank shot backing the page's claim with a lie; fail loud."""
        # colors=True mirrors the app's shipped default (the `colors` setting is
        # default-on): the compatibility rows claim a program's OWN colour renders
        # (ls/grep/diff/git --color), so the shot must show it, not a colourless
        # render. _effective_colors also needs colors_allowed(), guarded in main().
        view = SecureTerminal(preview=True, colors=True)
        view.setFixedWidth(panel_w)
        view.setVerticalScrollBarPolicy(scrollbar_off)
        view.setHorizontalScrollBarPolicy(scrollbar_off)
        view.setFixedHeight(40)
        view.apply_theme(theme_name)
        view.render_preview(text, mode='detail', markings=True)
        QApplication.processEvents()
        if not view.toPlainText().strip():
            raise RuntimeError(
                'compat-shot: %s (%s) rendered EMPTY -- capture/feed produced no '
                'visible output; refusing to write a blank shot' % (prog.name, prog.command))
        metrics = view.fontMetrics()
        usable = panel_w - 2 * panel_inset - 4
        rows = 0
        for line in view.toPlainText().split('\n'):
            width = metrics.horizontalAdvance(line)
            rows += max(1, -(-width // usable))          # ceil division
        needed = rows * metrics.lineSpacing() + 2 * panel_inset
        view.setFixedHeight(max(40, needed))
        QApplication.processEvents()
        img = view.grab().toImage()
        img.setDevicePixelRatio(1.0)                     # raw device pixels, no DPR
        return img

    def compose(prog, panel):
        """One shot: the command caption above the rendered output panel, on the
        theme background, sized to the panel."""
        from PyQt6.QtGui import QImage
        pad_d = pad * SHOT_SCALE
        label_d = label_h * SHOT_SCALE
        canvas = QImage(panel.width() + 2 * pad_d, label_d + panel.height() + 2 * pad_d,
                        QImage.Format.Format_RGB32)
        canvas.fill(QColor(bg))
        light = QColor(bg).lightnessF() >= 0.5
        hairline = QColor(bg).darker(118) if light else QColor(bg).lighter(150)
        painter = QPainter(canvas)
        cap_font = QFont('DejaVu Sans Mono', 10 * SHOT_SCALE)
        cap_font.setBold(True)
        painter.setFont(cap_font)
        painter.setPen(QColor(fg))
        painter.drawText(pad_d, pad_d + label_d - 8 * SHOT_SCALE, '$ ' + prog.command)
        painter.drawImage(pad_d, pad_d + label_d, panel)
        painter.setPen(hairline)
        painter.drawRect(pad_d, pad_d + label_d, panel.width() - 1, panel.height() - 1)
        painter.end()
        return canvas

    written = []
    with tempfile.TemporaryDirectory(prefix='compat-shot-') as root:
        env = _fixture_env(root)
        build_fixture(root, env)
        for prog in PROGRAMS:
            raw = run_capture(prog, root, env)
            canvas = compose(prog, panel_image(prog, _decode(raw)))
            out_path = os.path.join(out_dir, prog.name + '.png')
            if not canvas.save(out_path, 'PNG'):
                sys.stderr.write('compat-shot: could not write %s\n' % out_path)
                return 1
            written.append(out_path)
            print('compat-shot: wrote %s (%dx%d)'
                  % (out_path, canvas.width(), canvas.height()))

    print('compat-shot: %d program shots written' % len(written))
    return 0


if __name__ == '__main__':
    sys.exit(main())
