#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared helpers for the onion-time-pre-script suite.

The subject is a bash script sourced by sdwdate's preparation loop. Individual
top-level functions are extracted and run in isolation with stubbed
collaborators, so no Tor control port, no privleap and no root are needed.
"""

import os
import re
import subprocess
import sys
import unittest


def pre_script_path() -> str:
    """
    Resolve the onion-time-pre-script under test.

    ONION_TIME_PRE_SCRIPT_BIN -> that file, else
    ONION_TIME_PRE_SCRIPT_REPO -> a helper-scripts checkout, else installed.
    """
    direct = os.environ.get('ONION_TIME_PRE_SCRIPT_BIN', '').strip()
    if direct:
        return direct
    repo = os.environ.get('ONION_TIME_PRE_SCRIPT_REPO', '').strip()
    if repo:
        return os.path.join(
            repo, 'usr', 'libexec', 'helper-scripts', 'onion-time-pre-script'
        )
    return '/usr/libexec/helper-scripts/onion-time-pre-script'


def require_pre_script() -> str:
    """
    Return the subject path, or exit 77 (the runner's SKIP code) when the
    subject is absent. An absent subject means the suite could not run, not
    that onion-time-pre-script is broken -- failing here would redden the PR
    gate on every host without helper-scripts installed.
    """
    path = pre_script_path()
    if not os.path.exists(path):
        print(
            'SKIP: onion-time-pre-script not found -- install helper-scripts '
            'or set ONION_TIME_PRE_SCRIPT_BIN / ONION_TIME_PRE_SCRIPT_REPO',
            file=sys.stderr,
        )
        sys.exit(77)
    return path


_FUNC_RE_TMPL = r'^%s\(\) \{\n(.*?)^\}'


def extract_bash_function(path: str, name: str) -> str:
    """
    Return the full definition of a top-level bash function `name` from `path`.
    Assumes the closing brace is at column 0 (the fragment style). Raises
    LookupError if not found.
    """
    with open(path, 'r', encoding='utf-8') as handle:
        text = handle.read()
    match = re.search(
        _FUNC_RE_TMPL % re.escape(name), text, re.DOTALL | re.MULTILINE
    )
    if not match:
        raise LookupError('function %r not found in %s' % (name, path))
    return '%s() {\n%s}\n' % (name, match.group(1))


def run_bash(script: str, env: 'dict | None' = None) -> 'subprocess.CompletedProcess':
    """
    Run `script` under bash and return the completed process.

    Deliberately WITHOUT nounset: the subject's fragments rely on optional
    globals, and the EXIT trap reads $exit_code before it is ever set. The
    return code is handed back rather than raised, because exit-path tests
    assert on it.
    """
    return subprocess.run(
        ['bash', '-c', script],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def stub_env(**overrides: str) -> dict:
    """The current environment plus canned stub values."""
    return dict(os.environ, **overrides)


class PreScriptTestBase(unittest.TestCase):
    """Base class exposing the resolved subject path."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.path = require_pre_script()
