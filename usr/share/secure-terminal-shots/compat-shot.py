#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Build the deterministic compatibility-page fixture and emit the program table.

The compatibility page claims each program "was run and its output verified". This
backs that claim: every program below runs for real against a fixed fixture (no
network, no clock, pinned locale/timezone/identity), and its output is captured as a
REAL secure-terminal WINDOW by comparison-capture.sh (labwc + grim), not a mock. The
progress-bar programs additionally demonstrate the three line-editing modes
(full / read-safe / append-only): the SAME emitter is shot under each mode, so the
page shows how a CR/erase redraw is honoured in place, kept in place without the
escapes, or stacked one frame per update with an overwrite-attempt marker.

This module is the SINGLE SOURCE for (a) the fixture files and (b) the program table.
It does NOT render: the real-window capture lives in comparison-capture.sh (grim
captures a compositor WINDOW, so the shot is the app exactly as onscreen). Modes:

    compat-shot.py --fixture-dir <dir>   build the fixture into <dir>, run each row's
                                         `verify` tools (in a throwaway copy so they do
                                         not perturb a shot's fixture), then print the
                                         program table (one TAB-separated row per shot:
                                         name<TAB>line_editing<TAB>command) to stdout.
    compat-shot.py --list                print shot names, one per line.

Scope, so the page stays honest: the plain programs are line-oriented tools whose output
is byte-stable against the fixed fixture. The progress emitters carry NO clock and use a
fixed step count, so their frames -- and the append-only stack height -- are reproducible;
clock/rate-driven progress (pv, dd, wget, curl, apt) is NOT reproducible-and-multi-frame
and is excluded / stays MANUAL on the page. Each name maps to one compatibility-table
figure; the site references compatibility/shots/<name>.webp.

Usually driven via the `secure-terminal-shots compat` wrapper (this dir).
"""

import gzip
import io
import os
import shutil
import subprocess
import sys
import tarfile


# A program to shoot in a real secure-terminal window. `name` is the compatibility
# figure key (and the shot filename); `command` is the shell line TYPED into the terminal
# for real (the shot shows the real shell prompt echoing it). `line_editing` is the mode
# the window is launched under (full/read-safe/append-only) -- the same emitter shot under
# each mode is how the page contrasts them. `expect_rc` documents the row's expected exit
# for the verify pass (diff exits 1 on differences -- that IS the demo). `verify` are
# the OTHER tools the row's label claims: each is run for real (rc 0) in a THROWAWAY
# fixture copy so "was run and verified" covers every named tool without perturbing the
# shot's own fixture.
class Prog:
    def __init__(self, name, command, line_editing='full', expect_rc=0, verify=()):
        self.name = name
        self.command = command
        self.line_editing = line_editing
        self.expect_rc = expect_rc
        self.verify = tuple(verify)


# The plain line-oriented programs (one figure each, default line-editing).
PLAIN_PROGRAMS = [
    # coreutils row claims ls, cat, cp: shoot ls, verify cat + cp actually run.
    Prog('coreutils', 'ls --color=always -F demo',
         verify=('cat demo/readme.txt', 'cp demo/readme.txt demo/copy.txt')),
    Prog('find', 'find tree -type f | sort'),
    Prog('tar', 'tar tf fixture.tar'),
    Prog('grep', 'grep --color=always -n TODO notes.txt'),
    # gzip row claims gzip + zcat: shoot zcat, verify gzip compresses.
    Prog('gzip', 'zcat greeting.txt.gz', verify=('gzip -kf list.txt',)),
    Prog('sed', "sed 's/^/  | /' list.txt"),
    # diff exits 1 on differences (the demo); cmp is the other tool the row claims.
    Prog('diff', 'diff --color=always old.txt new.txt',
         expect_rc=1, verify=('cmp old.txt old.txt',)),
    Prog('awk', 'awk \'{ total += $2 } END { printf "total: %d\\n", total }\' nums.txt'),
    Prog('git', 'git -C repo -c color.ui=always --no-pager log --oneline --decorate'),
]

# The progress emitters: each is shot under ALL THREE line-editing modes (the SAME emitter, only
# the launch mode differs) so the page contrasts full / read-safe / append-only on one redraw.
# ONLY emitters that are BOTH byte-deterministic AND multi-frame qualify -- a FIXED step count and
# NO time/rate fields. crbar (a scripted bash loop) and tqdm (fixed iterations, a time-less
# bar_format) meet this: 20 frames, no clock, so re-running is a no-op AND append-only stacks 20
# lines. pv and dd were investigated and DROPPED: their redraw frames are driven by a sub-second
# wall clock, so they cannot be both deterministic and multi-frame -- freezing the clock (faketime)
# either breaks the tool (pv's select() dies, dd's SIGUSR1 handler is clobbered) or removes the
# frames, and rate-limiting jitters the frame count. Live network progress (wget/curl/apt) is
# likewise non-reproducible and stays MANUAL on the page.
PROGRESS_EMITTERS = [
    ('crbar', 'bash progress-crbar.sh'),
    ('tqdm', 'python3 progress-tqdm.py'),
]
LINE_EDITING_MODES = ('full', 'read-safe', 'append-only')


def progress_programs():
    """One Prog per (emitter x line-editing mode): name progress-<tool>-<mode>."""
    progs = []
    for tool, command in PROGRESS_EMITTERS:
        for mode in LINE_EDITING_MODES:
            progs.append(Prog('progress-%s-%s' % (tool, mode), command, line_editing=mode))
    return progs


def all_programs():
    return PLAIN_PROGRAMS + progress_programs()


def _fixture_env(home):
    """A deterministic environment: fixed locale, timezone, width and git identity so a
    program's output does not drift run to run. Nothing here reaches the network or reads
    a real clock (git dates are pinned below; the progress emitters freeze the clock)."""
    env = {
        'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
        'HOME': home,
        'LC_ALL': 'C.UTF-8',
        'LANG': 'C.UTF-8',
        'TZ': 'UTC',
        'TERM': 'xterm-256color',
        'COLUMNS': '80',
        'LINES': '40',
        # Isolate git from any host config; pin identity + dates so the commit hashes
        # and the log are byte-identical every run.
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


# A deterministic coloured CR progress bar: a fixed step count, no clock. Uses \r
# (return to column 0) + \033[K (erase-to-end-of-line) + SGR colour, and its final line
# is SHORTER than the bar -- so the three line-editing modes render DISTINCTLY:
#   full       -> \r + erase both honoured: one clean coloured "Download complete." line
#   read-safe  -> \r acts but \033[K is stripped: the short final line overwrites from
#                 column 0 and the wider bar's tail is NOT erased, so a remnant trails
#   append-only-> \r neutralised: every frame kept on its own line with a gutter marker
_CRBAR = r"""#!/bin/bash
## Deterministic coloured CR progress bar (fixed steps, CR + erase-line, no clock).
steps=20
width=24
for (( i=1; i<=steps; i++ )); do
   filled=$(( i * width / steps ))
   bar=''
   for (( c=0; c<filled; c++ )); do bar+='#'; done
   for (( c=filled; c<width; c++ )); do bar+=' '; done
   printf '\r\033[K\033[36mFetching \033[32m[%s]\033[0m %3d%%' "${bar}" "$(( i * 100 / steps ))"
done
printf '\r\033[K\033[32mFetch complete.\033[0m\n'
"""

# A tqdm bar with NO time/rate fields in the format (so it is byte-stable) and forced
# to refresh every iteration (mininterval=0, miniters=1) so the append-only stack height
# is a fixed 20 frames. ncols pins the width.
_TQDM = r"""#!/usr/bin/python3 -Bsu
from tqdm import tqdm
for _ in tqdm(range(20), ncols=56, mininterval=0, miniters=1,
              bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt}',
              desc='Indexing'):
    pass
"""


def build_fixture(root, env):
    """Lay out the fixed inputs every program reads. Deterministic: fixed file contents,
    a pinned-mtime tar, a git repo built with the pinned identity/date env, and the
    progress emitters' scripts + a fixed-size data file. Raises on any failure (a broken
    fixture must not yield a misleading shot)."""
    # coreutils: a directory with varied file TYPES so `ls --color -F` shows the type
    # colours the row claims (dir/, executable*, symlink@, an archive).
    demo = os.path.join(root, 'demo')
    os.mkdir(demo)
    os.mkdir(os.path.join(demo, 'subdir'))
    _write(os.path.join(demo, 'readme.txt'), 'plain file\n')
    script = os.path.join(demo, 'run.sh')
    _write(script, '#!/bin/sh\necho hi\n')
    os.chmod(script, 0o700)
    os.symlink('readme.txt', os.path.join(demo, 'latest.txt'))
    _write(os.path.join(demo, 'backup.tar'), 'not really a tar, for the colour\n')

    # find: a few nested files to list, under src/ and doc/.
    tree = os.path.join(root, 'tree')
    os.makedirs(os.path.join(tree, 'src'))
    os.makedirs(os.path.join(tree, 'doc'))
    _write(os.path.join(tree, 'src', 'main.c'), 'int main(void){return 0;}\n')
    _write(os.path.join(tree, 'src', 'util.c'), '/* util */\n')
    _write(os.path.join(tree, 'doc', 'guide.md'), '# Guide\n')

    # tar: a fixed-mtime archive so `tar tf` (names only) is stable.
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

    # gzip/zcat: a gzip of a friendly file (fixed mtime -> stable bytes).
    greet = 'secure-terminal compatibility check\nordinary output stays ordinary\n'
    with gzip.GzipFile(os.path.join(root, 'greeting.txt.gz'), 'wb', mtime=0) as gzf:
        gzf.write(greet.encode('utf-8'))

    # sed: a short list to prefix.
    _write(os.path.join(root, 'list.txt'), 'alpha\nbravo\ncharlie\ndelta\n')

    # diff: two nearby files (the colourised unified diff is the demo).
    _write(os.path.join(root, 'old.txt'), 'one\ntwo\nthree\nfour\n')
    _write(os.path.join(root, 'new.txt'), 'one\nTWO\nthree\nfour\nfive\n')

    # awk: label/value pairs to total.
    _write(os.path.join(root, 'nums.txt'), 'build 12\ntest 30\npackage 8\n')

    # git: a repo with two commits, built with the pinned identity/date env so the short
    # hashes and log are byte-identical every run.
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

    # progress emitters: the scripts (crbar + tqdm; both self-contained, no data file).
    _write(os.path.join(root, 'progress-crbar.sh'), _CRBAR)
    _write(os.path.join(root, 'progress-tqdm.py'), _TQDM)


def _run_checked(command, cwd, env, expect_rc):
    """Run `command` under bash -c in `cwd`; raise unless it exits `expect_rc`. A missing
    tool (bash exits 127) or a genuine failure must FAIL LOUD, never silently back the
    page's 'was run and verified' claim."""
    result = subprocess.run(['bash', '-c', command], cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != expect_rc:
        raise RuntimeError(
            'compat-shot: `%s` exited %d (expected %d) -- refusing to back the '
            '"was run and verified" claim with a command that did not run cleanly:\n%s'
            % (command, result.returncode, expect_rc,
               result.stdout.decode('utf-8', 'replace')[:500]))


def run_verify(root, env):
    """Run every row's shot command AND its verify tools for real, rc-checked, in a
    THROWAWAY COPY of the fixture -- so the "was run and verified" claim covers every
    named tool, without a verify side effect (cp adding a file, gzip writing one)
    perturbing the pristine fixture the window shots are taken against."""
    scratch = os.path.join(root, '.verify')
    # Copy every fixture entry except the scratch dir itself.
    os.mkdir(scratch)
    for entry in os.listdir(root):
        if entry == '.verify':
            continue
        src = os.path.join(root, entry)
        dst = os.path.join(scratch, entry)
        if os.path.isdir(src):
            shutil.copytree(src, dst, symlinks=True)
        else:
            shutil.copy2(src, dst)
    for prog in all_programs():
        _run_checked(prog.command, scratch, env, prog.expect_rc)
        for command in prog.verify:
            _run_checked(command, scratch, env, 0)
    shutil.rmtree(scratch)


def print_table():
    """Emit the program table, one row per shot: name<TAB>line_editing<TAB>command. The command
    never contains a tab or newline, so a plain TAB split in the consumer is unambiguous."""
    for prog in all_programs():
        sys.stdout.write('%s\t%s\t%s\n' % (prog.name, prog.line_editing, prog.command))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv == ['--list']:
        for prog in all_programs():
            print(prog.name)
        return 0

    if len(argv) == 2 and argv[0] == '--fixture-dir':
        root = argv[1]
        if not os.path.isdir(root):
            sys.stderr.write('compat-shot: fixture dir does not exist: %s\n' % root)
            return 1
        env = _fixture_env(root)
        build_fixture(root, env)
        run_verify(root, env)
        print_table()
        return 0

    sys.stderr.write('usage: compat-shot.py --fixture-dir <dir> | --list\n')
    return 2


if __name__ == '__main__':
    sys.exit(main())
