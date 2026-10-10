#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared helpers for the msgcollector test suite.

Resolves the msgcollector scripts under test:
  * MSGCOLLECTOR_REPO=/path/to/msgcollector -> <repo>/usr/libexec/msgcollector/<name>
  * unset                                   -> /usr/libexec/msgcollector/<name> (installed)

A missing subject is an environment bug, so resolution raises instead of
skipping.

Bash functions are tested by SOURCING the real script (msgcollector is
source-able, msgdispatcher_run_check is a pure library) in a fresh bash and
calling the function -- see sourced_bash_argv.
"""

import os
import re
import subprocess

## Hang guard for one sourced call. Generous on purpose: each call sources the
## whole subject, which is slow on a loaded runner, and a too-tight value turns
## load into a false 'hang'. A real infinite loop still trips it.
HANG_TIMEOUT = 60.0


def _libexec_file(name: str) -> str:
    repo = os.environ.get('MSGCOLLECTOR_REPO', '').strip()
    if repo:
        base = os.path.join(repo, 'usr', 'libexec', 'msgcollector')
    else:
        base = '/usr/libexec/msgcollector'
    path = os.path.join(base, name)
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"{path} not found (set MSGCOLLECTOR_REPO to a msgcollector checkout, "
            'or install the package)')
    return path


def msgcollector_script() -> str:
    """Absolute path of the msgcollector script under test."""
    return _libexec_file('msgcollector')


def dispatch_script() -> str:
    """Absolute path of msgdispatcher_dispatch_x (the PyQt5 GUI renderer)."""
    return _libexec_file('msgdispatcher_dispatch_x.py')


def run_check_script() -> str:
    """Absolute path of msgdispatcher_run_check (defines output_func)."""
    return _libexec_file('msgdispatcher_run_check')


def sourced_bash_argv(subject: str, funcs: tuple[str, ...], body: str,
                      *args: str) -> list[str]:
    """argv that runs `body` in a fresh, non-strict bash after sourcing the
    REAL `subject`, the way a consumer sources it. In `body`, "$@" is `args`.

    Exits 3 when any of `funcs` is undefined after sourcing: a nested source
    with a wrong HELPER_SCRIPTS_PATH only warns in a non-strict shell, and the
    function under test would then silently call a missing helper."""
    script = (
        'subject="$1"\n'
        'shift\n'
        'source -- "${subject}"\n'
        f'if ! declare -F -- {" ".join(funcs)} >/dev/null; then\n'
        '   printf \'%s\\n\' "sourced_bash: ${subject}: a required function'
        ' is undefined after sourcing" >&2\n'
        '   exit 3\n'
        'fi\n'
        + body + '\n'
    )
    return ['bash', '-c', script, 'bash', subject, *args]


def run_sourced(subject: str, funcs: tuple[str, ...], body: str, *args: str,
                text: bool = True, env: 'dict | None' = None,
                timeout: float = HANG_TIMEOUT) -> subprocess.CompletedProcess:
    """Run sourced_bash_argv(...) and capture its output, under the shared
    HANG_TIMEOUT (TimeoutExpired propagates: a fuzzer reads it as a hang)."""
    return subprocess.run(sourced_bash_argv(subject, funcs, body, *args),
                          capture_output=True, text=text, env=env,
                          timeout=timeout)


def read(path: str) -> str:
    with open(path, encoding='utf-8', errors='replace') as handle:
        return handle.read()


def extract_python_class(path: str, name: str) -> str:
    """Return the source of a top-level python class `name` from `path` (from
    the `class NAME` line to the next column-0 statement or EOF). Lets a test
    exercise a class defined inside an executable script that cannot be imported
    (it would run its GUI main). Raises LookupError if not found."""
    match = re.search(rf"^class {re.escape(name)}\b.*?(?=^\S|\Z)",
                      read(path), re.DOTALL | re.MULTILINE)
    if not match:
        raise LookupError(f"class {name!r} not found in {path}")
    return match.group(0)
