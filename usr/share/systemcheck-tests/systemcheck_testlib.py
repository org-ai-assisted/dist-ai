#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared helpers for the systemcheck test suite.

Resolves the systemcheck sources under test:
  * SYSTEMCHECK_REPO=/path/to/systemcheck -> <repo>/usr/libexec/systemcheck
  * unset                                 -> /usr/libexec/systemcheck (installed)

Bash under test is always SOURCED from the real files: the fragments resolve
their siblings via ${SYSTEMCHECK_REPO:-} / ${HELPER_SCRIPTS_PATH:-}, which the
child bash inherits from this environment, so a checkout runs in place.
"""

import base64
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


def systemcheck_dir() -> str:
    """Return the directory holding the systemcheck .bsh fragments."""
    repo = os.environ.get('SYSTEMCHECK_REPO', '').strip()
    if repo:
        cand = os.path.join(repo, 'usr', 'libexec', 'systemcheck')
        if os.path.isdir(cand):
            return cand
        ## SKIP (exit 77) rather than FAIL when the checkout does not have the
        ## expected layout -- mirrors the dist-ai suite convention.
        print(
            f"SYSTEMCHECK_REPO={repo!r} has no usr/libexec/systemcheck; skipping.",
            file=sys.stderr,
        )
        sys.exit(77)
    installed = '/usr/libexec/systemcheck'
    if os.path.isdir(installed):
        return installed
    print('systemcheck sources not found (set SYSTEMCHECK_REPO); skipping.',
          file=sys.stderr)
    sys.exit(77)


def bsh_files() -> list[str]:
    """Absolute paths of every *.bsh fragment plus the log-checker script."""
    directory = systemcheck_dir()
    out = []
    for name in sorted(os.listdir(directory)):
        if name.endswith('.bsh') or name == 'log-checker':
            out.append(os.path.join(directory, name))
    return out


def _has_bash_shebang(path: str) -> bool:
    """True if the file's first line is a bash shebang."""
    try:
        with open(path, 'rb') as handle:
            first_line = handle.readline(256)
    except OSError:
        return False
    return first_line.startswith(b'#!') and b'bash' in first_line


def bash_scripts() -> list[str]:
    """Absolute paths of EVERY bash script shipped by systemcheck, not just the
    *.bsh fragments: the fragments, the log-checker, the main `systemcheck`
    entrypoint, and every other file carrying a bash shebang (canary,
    canary-daemon, check-env, check_tor_running, crypt-check, pkexec-test,
    updatecheck-daemon, user-sysmaint-split-check, ...).

    Source tree (SYSTEMCHECK_REPO set): walk the checkout, skipping VCS and
    Debian packaging directories. Installed: use the package file list from
    `dpkg -L systemcheck` so no prefix has to be guessed.
    """
    repo = os.environ.get('SYSTEMCHECK_REPO', '').strip()
    if repo and os.path.isdir(repo):
        ## Validate the checkout layout (and SKIP if wrong) exactly like the
        ## installed branch below, so a mis-set SYSTEMCHECK_REPO cannot be
        ## silently walked as if it were the systemcheck source tree.
        systemcheck_dir()
        candidates = []
        skip_dirs = {'.git', '.github', 'debian'}
        for dirpath, dirs, names in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for name in names:
                candidates.append(os.path.join(dirpath, name))
    else:
        ## Trigger the standard SKIP if the sources are not present at all.
        systemcheck_dir()
        try:
            proc = subprocess.run(
                ['dpkg', '-L', 'systemcheck'],
                capture_output=True, text=True, check=False,
            )
        except FileNotFoundError:
            ## No dpkg (non-Debian host): SKIP rather than crash, matching the
            ## suite's missing-sources convention.
            print('dpkg not found; cannot enumerate installed scripts; skipping.',
                  file=sys.stderr)
            sys.exit(77)
        if proc.returncode != 0:
            ## Surface the real error instead of silently yielding an empty
            ## list that looks like "package has no files".
            print(f"dpkg -L systemcheck failed (rc={proc.returncode}): "
                  f"{proc.stderr.strip()}", file=sys.stderr)
        candidates = proc.stdout.splitlines()

    scripts = []
    for path in sorted(set(candidates)):
        if not os.path.isfile(path):
            continue
        if path.endswith('.bsh') or os.path.basename(path) == 'log-checker' \
                or _has_bash_shebang(path):
            scripts.append(path)
    return scripts


def read(path: str) -> str:
    with open(path, encoding='utf-8', errors='replace') as handle:
        return handle.read()


def has_bsh() -> str:
    """helper-scripts has.bsh. The systemcheck entrypoint sources it before the
    fragments (uwt_tool.bsh, sourced by preparation.bsh, calls `has` at source
    time), so every harness sources it first too."""
    hs_root = os.environ.get('HELPER_SCRIPTS_PATH', '').strip() or '/'
    return os.path.join(hs_root, 'usr', 'libexec', 'helper-scripts', 'has.bsh')


def fragment_sources(*fragments: str) -> list[str]:
    """The real files a check fragment needs, in the entrypoint's order:
    has.bsh, preparation.bsh (emit_message & co.), then `fragments`."""
    return [has_bsh(), os.path.join(systemcheck_dir(), 'preparation.bsh'),
            *fragments]


def _source_block(sources) -> str:
    return '\n'.join(f'source {shlex.quote(path)}' for path in sources)


def run_sourced(sources, call: str, setup: str = '') -> str:
    """Source the real `sources`, run `setup` (stubs / globals; AFTER the source
    so a stub shadows the real definition), then `call`; return stdout stripped.
    errexit + pipefail, no nounset (the fragments read optional globals). A
    non-zero exit fails with bash's stderr."""
    script = '\n'.join([
        'set -o errexit', 'set -o pipefail', _source_block(sources), setup, call,
    ])
    proc = subprocess.run(['bash', '-c', script], capture_output=True,
                          text=True, timeout=30)
    if proc.returncode != 0:
        raise AssertionError(
            f"bash exited {proc.returncode}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def function_definition(sources, name: str) -> str:
    """`declare -f name` after sourcing the real `sources`: the body as bash
    itself parsed it, for static assertions. An undefined name fails."""
    return run_sourced(sources, f'declare -f -- {shlex.quote(name)}')


## Records every message emission. $output_x / $output_cli are variables holding
## a command name, so pointing them at this function captures the severity and
## message a check would have sent to msgcollector, without needing msgcollector.
_SCENARIO_PREAMBLE = r"""
set +e
output_opts=()
__systemcheck_rec() {
  local channel="-" sev="-" msg="" have_msg=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --messagex) channel="x"; shift ;;
      --messagecli) channel="cli"; shift ;;
      --typex|--typecli) sev="${2:--}"; shift 2 2>/dev/null || shift ;;
      --message) msg="${2:-}"; have_msg=1; shift 2 2>/dev/null || shift ;;
      *) shift ;;
    esac
  done
  if [ "$have_msg" = 1 ]; then
    printf 'REC\t%s\t%s\t%s\n' "$channel" "$sev" "${msg//$'\n'/\\n}"
  fi
}
output_x=__systemcheck_rec
output_cli=__systemcheck_rec
output_general=true
verbose="${verbose:-1}"
silent="${silent:-0}"
EXIT_CODE="${EXIT_CODE:-0}"
status_ok='<font color="green">OK.</font>'
PROJECT_NAME="${PROJECT_NAME:-Kicksecure}"
PROJECT_HOMEPAGE="${PROJECT_HOMEPAGE:-https://www.kicksecure.com}"
who_ami="${who_ami:-user}"
"""


class ScenarioResult:
    """The captured emissions of one check-function run."""

    def __init__(self, records, exit_code, stdout, stderr):
        ## records: list of (channel, severity, message) tuples.
        self.records = records
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr

    def severities(self) -> set:
        return {sev for _c, sev, _m in self.records if sev != '-'}

    def has_severity(self, severity: str) -> bool:
        return any(sev == severity for _c, sev, _m in self.records)

    def messages(self) -> list:
        return [msg for _c, _s, msg in self.records]

    def joined(self) -> str:
        return '\n'.join(self.messages())


def _assemble_scenario_script(check_file: str, call: str, env_setup: str,
                              stubs: str, prefix: str = '') -> str:
    ## Sourcing runs under errexit so a subject that fails to load (a sibling
    ## source path that does not resolve) aborts before the SOURCED marker;
    ## stubs and env_setup follow the source so they shadow the real code.
    return '\n'.join([
        _SCENARIO_PREAMBLE, prefix,
        'set -o errexit', _source_block(fragment_sources(check_file)),
        'set +o errexit', 'printf "SOURCED\\n"',
        stubs, env_setup,
        call, 'printf "EXITCODE\\t%s\\n" "${EXIT_CODE:-0}"',
    ])


def _parse_scenario_output(proc) -> ScenarioResult:
    records = []
    exit_code = None
    sourced = False
    for line in proc.stdout.splitlines():
        if line.startswith('REC\t'):
            _tag, channel, sev, msg = line.split('\t', 3)
            records.append((channel, sev, msg))
        elif line.startswith('EXITCODE\t'):
            exit_code = line.split('\t', 1)[1]
        elif line == 'SOURCED':
            sourced = True
    if not sourced:
        raise AssertionError(
            'scenario never got past sourcing the subject (or, isolated, '
            'past bubblewrap sandbox setup): '
            + (proc.stderr.strip() or f"exit {proc.returncode}"))
    ## The call runs under `set +e`, so only an `exit` or a crash skips the
    ## EXITCODE marker; an assertion on records alone would then pass vacuously.
    if exit_code is None:
        raise AssertionError(
            'scenario call never returned: '
            + (proc.stderr.strip() or f"exit {proc.returncode}"))
    return ScenarioResult(records, exit_code, proc.stdout, proc.stderr)


def run_check_scenario(check_file: str, call: str, env_setup: str = '',
                       stubs: str = '') -> ScenarioResult:
    """Run one check function in isolation and capture what it emits.

    check_file : absolute path of the check_*.bsh fragment.
    call       : the function invocation, e.g. "check_dpkg".
    env_setup  : bash setting the globals that steer the branch under test.
    stubs      : bash defining stub commands (leaprun, dpkg, hostname, ...) that
                 the check calls as bare names.

    Absolute-path guards (e.g. `[ -f /usr/share/qubes/marker-vm ]`) and binaries
    called by absolute path cannot be steered this way; use
    run_check_scenario_isolated for those.
    """
    script = _assemble_scenario_script(check_file, call, env_setup, stubs)
    ## timeout so a check that blocks on a missing stub (or a bad parse) fails
    ## the test loudly instead of wedging the whole suite/CI run.
    proc = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                          timeout=30)
    return _parse_scenario_output(proc)


_BWRAP_OK = None


def bwrap_available() -> bool:
    """True if bubblewrap can create an unprivileged mount namespace here.
    Cached; used to SKIP the isolated tests on restricted CI."""
    global _BWRAP_OK
    if _BWRAP_OK is None:
        _BWRAP_OK = False
        if shutil.which('bwrap'):
            try:
                probe = subprocess.run(
                    ['bwrap', '--bind', '/', '/', '--dev', '/dev',
                     '--proc', '/proc', '--tmpfs', '/tmp',  # nosec B108 -- bwrap --tmpfs mount target inside the namespace, not a host temp path
                     'bash', '-c', 'true'],
                    capture_output=True, timeout=15)
                _BWRAP_OK = probe.returncode == 0
            except (OSError, subprocess.SubprocessError):
                _BWRAP_OK = False
    return _BWRAP_OK


def _nearest_existing_dir(path: str) -> str:
    while not os.path.isdir(path):
        path = os.path.dirname(path)
    return path


def tmpfs_mounts(hide_dirs, place_paths) -> list[str]:
    """The bwrap --tmpfs targets for an isolated scenario (none nested).

    bwrap cannot create a mount point under a read-only host dir, so a placed
    file's absent parent is reached by emptying its nearest EXISTING ancestor
    (the in-sandbox prefix then `mkdir -p`s the parent inside that tmpfs). An
    absent hide_dir needs no mount: its contents are already absent. A target
    under another target is dropped: it is already inside a writable tmpfs."""
    targets = {d for d in hide_dirs if os.path.isdir(d)}
    targets.update(_nearest_existing_dir(os.path.dirname(p))
                   for p in place_paths)
    return sorted(t for t in targets
                  if not any(o != t and _is_under(t, o) for o in targets))


def _is_under(path: str, directory: str) -> bool:
    return path == directory or path.startswith(directory.rstrip('/') + '/')


def run_check_scenario_isolated(check_file: str, call: str, env_setup: str = '',
                                stubs: str = '', hide_dirs=(), place=(),
                                bind_files=()) -> ScenarioResult:
    """Like run_check_scenario, but inside a bubblewrap mount namespace so
    absolute-path guards and binaries can be neutralized:

      hide_dirs  : directories to EMPTY with a tmpfs overlay so their files
                   disappear -- e.g. '/usr/share/qubes' makes the marker-vm guard
                   file absent (the non-Qubes branch). A hide_dir that does not
                   exist on the host is skipped: the guard file is already absent,
                   so there is nothing to hide (this is what makes the tests run
                   on a non-Qubes CI host).
      place      : iterable of (abs_path, content, is_exec) to materialize inside
                   the sandbox. The parent directory -- or, when absent, its
                   nearest existing ancestor (see tmpfs_mounts) -- is overlaid
                   with a writable tmpfs, then the file is written there. Use
                   ONLY for a
                   dedicated directory whose other files the check does not need
                   (e.g. '/usr/share/qubes/marker-vm', a fake
                   '/usr/libexec/systemcheck/crypt-check'); the tmpfs hides the
                   rest of that directory. Do NOT use it for a file in a shared
                   bin directory -- a tmpfs over '/usr/bin' would hide bash.
      bind_files : iterable of (abs_path, content, is_exec) bound over abs_path a
                   SINGLE FILE at a time (no parent tmpfs), so the rest of the
                   directory is untouched -- use it for a binary in a shared
                   directory such as '/usr/bin/disallowed-test'. Requires abs_path
                   to exist on the host, or its parent to be writable so
                   bubblewrap can create the mount point.

    SkipTest when bubblewrap / user namespaces are unavailable; the
    systemcheck-tests-bwrap runner (--strict-skips) turns that into FATAL unless
    the orchestrator authorized the skip. A sandbox that bubblewrap CAN create but
    fails to set up for this scenario is a test failure (AssertionError from
    _parse_scenario_output: the script never reached its markers).
    """
    if not bwrap_available():
        raise unittest.SkipTest(
            'bubblewrap unavailable or unprivileged user namespaces disabled')

    tmpfs_dirs = tmpfs_mounts(hide_dirs, [p for p, _c, _x in place])
    ## A tmpfs over the subject's own dir (e.g. placing a fake crypt-check
    ## into the installed /usr/libexec/systemcheck) would empty what the
    ## scenario sources; refuse it by name instead of a sourcing failure.
    for source in fragment_sources(check_file):
        for directory in tmpfs_dirs:
            if _is_under(source, directory):
                raise AssertionError(
                    f"isolated scenario would tmpfs {directory!r}, hiding "
                    f"sourced subject {source!r}; set SYSTEMCHECK_REPO / "
                    "HELPER_SCRIPTS_PATH to checkouts")
    prefix_lines = []
    for abs_path, content, is_exec in place:
        ## base64 so arbitrary content (shebangs, quotes, newlines) round-trips
        ## through the shell prefix without quoting hazards.
        encoded = base64.b64encode(content.encode()).decode()
        prefix_lines.append(
            f"mkdir -p -- {shlex.quote(os.path.dirname(abs_path))}")
        prefix_lines.append(
            f"printf %s {shlex.quote(encoded)} | base64 -d > {shlex.quote(abs_path)}")
        if is_exec:
            prefix_lines.append(f"chmod 0755 -- {shlex.quote(abs_path)}")

    script = _assemble_scenario_script(check_file, call, env_setup, stubs,
                                       prefix='\n'.join(prefix_lines))
    cmd = ['bwrap', '--bind', '/', '/', '--dev', '/dev', '--proc', '/proc']
    for directory in tmpfs_dirs:
        cmd += ['--tmpfs', directory]

    tmp_paths = []
    for abs_path, content, is_exec in bind_files:
        fd, tmp = tempfile.mkstemp(prefix='fake_bind_')
        os.write(fd, content.encode())
        os.close(fd)
        ## These stand in for real system files read-only-bound into the
        ## sandbox, so they must carry the modes the code under test expects.
        os.chmod(tmp, 0o755 if is_exec else 0o644)  # nosec B103
        tmp_paths.append(tmp)
        cmd += ['--ro-bind', tmp, abs_path]

    cmd += ['bash', '-c', script]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
    finally:
        for tmp in tmp_paths:
            try:
                os.unlink(tmp)
            except OSError:
                # the temp file was already removed
                pass
    return _parse_scenario_output(proc)


class SystemcheckTestBase(unittest.TestCase):
    """Base class exposing the resolved source directory + file list."""

    dir: str
    files: list[str]
    preparation: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = systemcheck_dir()
        cls.files = bsh_files()
        cls.preparation = os.path.join(cls.dir, 'preparation.bsh')


class ScenarioTestBase(SystemcheckTestBase):
    """Base for scenario / path tests. Shared by every test_check_scenarios*.py
    file so the check-path helpers live in one place."""

    def check(self, basename: str) -> str:
        """Absolute path of a check_*.bsh fragment by basename."""
        return os.path.join(self.dir, basename)

    def assertCleanRun(self, result) -> None:
        """Fail if the scenario crashed in bash. Without this, a test asserting
        "no records emitted" would pass vacuously when the function actually
        errored out early (undefined command, unbound var, ...) and emitted
        nothing."""
        for marker in ('command not found', 'unbound variable',
                       'syntax error', ': line '):
            self.assertNotIn(
                marker, result.stderr,
                f"bash error during scenario: {result.stderr.strip()!r}")


class LogCheckerHardeningBase(SystemcheckTestBase):
    """Shared harness: SOURCE the real log-checker (source-able, so this defines
    its functions without auto-running or leaking strict-mode), then call the
    function under test, overlaying the absolute paths it reads with a bubblewrap
    tmpfs so the case under test is deterministic on any host (Qubes or CI)."""

    def _log_checker(self) -> str:
        return os.path.join(self.dir, 'log-checker')

    def _wrap(self, cmd: list, tmpfs_dirs: list) -> list:
        """Prefix cmd with a bubblewrap tmpfs overlay for each EXISTING tmpfs_dir.
        A dir absent on the host already yields the 'empty' state, so no overlay
        (and no bwrap) is needed there -- this is what lets the check_service_logs
        tests run plain on a non-Qubes CI container with no /usr/share/qubes."""
        dirs = [d for d in tmpfs_dirs if os.path.isdir(d)]
        if not dirs:
            return cmd
        if not bwrap_available():
            raise unittest.SkipTest(
                'bubblewrap unavailable; cannot isolate ' + ' '.join(dirs))
        prefix = ['bwrap', '--bind', '/', '/', '--dev', '/dev', '--proc', '/proc']
        for directory in dirs:
            prefix += ['--tmpfs', directory]
        return prefix + cmd

    def _run(self, body: str, tmpfs_dirs: list) -> subprocess.CompletedProcess:
        ## Source the source-able script (was_executed is false here -> no
        ## auto-run, no strict leak), then run the caller-supplied body under the
        ## same options the executed script sets, so the functions behave as in
        ## production.
        script = (
            f'source {shlex.quote(self._log_checker())}\n'
            ## Match the executed script's own options so the function runs as in
            ## production (pipefail on -> the grep brace-masks are genuinely
            ## exercised); the source itself did not enable strict (was_executed
            ## is false when sourced).
            'set -o errexit\n'
            'set -o nounset\n'
            'set -o pipefail\n'
            f'{body}'
        )
        cmd = self._wrap(['bash', '-c', script], tmpfs_dirs)
        ## stdin=DEVNULL so nothing can block on a terminal; timeout fails a hang
        ## loudly instead of wedging CI.
        return subprocess.run(cmd, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=30)

    ## Stubs for the externals/sinks the functions call as bare names. Defined
    ## AFTER the source so they shadow the real definitions; kept to the identity
    ## transform so assertions are deterministic and offline.
    @staticmethod
    def _stubs(journal_line: str) -> str:
        return (
            'leaprun() { case "$1" in'
            f" read-journalctl-logs-this-boot) printf '%s\\n' {shlex.quote(journal_line)} ;;"
            ' *) : ;; esac ; }\n'
            'sanitize-string() { cat ; }\n'
            'br_add_to_file() { cp -- "$1" "$1_br" ; }\n'
            'stcatn() { cat -- "$@" ; }\n'
            'safe-rm() { : ; }\n'
        )

    def _run_check_service_logs(self, journal_line: str, fixed: list,
                                patterns: list) -> subprocess.CompletedProcess:
        tmp = tempfile.mkdtemp()
        fixed_arr = ' '.join(shlex.quote(item) for item in fixed)
        patterns_arr = ' '.join(shlex.quote(item) for item in patterns)
        body = (
            self._stubs(journal_line)
            + f'TMPDIR={shlex.quote(tmp)}\n'
            + f'journal_ignore_fixed_list=( {fixed_arr} )\n'
            + f'journal_ignore_patterns_list=( {patterns_arr} )\n'
            + 'check_service_logs this_boot\n'
        )
        ## Hide the Qubes marker so the 'virtualbox' auto-append does not make
        ## journal_ignore_patterns_list non-empty on a Qubes host.
        return self._run(body, ['/usr/share/qubes'])

    def _run_prep_temp_dir(self, setup: str = '') -> subprocess.CompletedProcess:
        ## prep_temp_dir hardcodes TMPDIR=/var/cache/systemcheck-log-checker, so
        ## isolate /var/cache with a tmpfs: a clean per-run dir, writable by us.
        body = (
            'safe-rm() { command rm --recursive --force -- "${@:3}" ; }\n'
            f'{setup}'
            'if prep_temp_dir ; then echo PREP_OK ; else echo "PREP_FAIL rc=$?" ; fi\n'
        )
        return self._run(body, ['/var/cache'])
