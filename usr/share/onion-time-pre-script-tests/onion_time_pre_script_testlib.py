#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared helpers for the onion-time-pre-script suite.

The subject is a source-able bash script: sourcing it defines its functions
without running main, installing traps or enabling strict mode. Tests source
the real file, stub the collaborators that would reach Tor, privleap or root,
and call the function under test directly.
"""

import os
import subprocess
import sys
import unittest

SUBJECT_RELPATH = os.path.join(
    'usr', 'libexec', 'helper-scripts', 'onion-time-pre-script'
)


def helper_scripts_root() -> str:
    """
    Root of the helper-scripts tree under test.

    ONION_TIME_PRE_SCRIPT_REPO -> that checkout, else '' (the installed
    package). Also the HELPER_SCRIPTS_PATH the subject resolves its sourced
    siblings from, so subject and siblings always come from the same tree.
    """
    repo = os.environ.get('ONION_TIME_PRE_SCRIPT_REPO', '').strip()
    if repo:
        return os.path.abspath(repo)
    return ''


def pre_script_path(root: str) -> str:
    """The onion-time-pre-script inside the helper-scripts tree `root`."""
    return os.path.join(root or '/', SUBJECT_RELPATH)


def run_bash(script: str, env: 'dict | None' = None) -> 'subprocess.CompletedProcess':
    """
    Run `script` under bash and return the completed process.

    The return code is handed back rather than raised, because exit-path
    tests assert on it.
    """
    return subprocess.run(
        ['bash', '-c', script],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


class PreScriptTestBase(unittest.TestCase):
    """Base class: resolves the subject and runs bash with it sourced."""

    root: str
    path: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.root = helper_scripts_root()
        cls.path = pre_script_path(cls.root)
        ## helper-scripts is a required dependency: absent means a broken
        ## environment, never a skip.
        if not os.path.isfile(cls.path):
            print(
                'FATAL: onion-time-pre-script not found at %s -- install '
                'helper-scripts or set ONION_TIME_PRE_SCRIPT_REPO' % cls.path,
                file=sys.stderr,
            )
            sys.exit(1)

    def run_sourced(
        self, body: str, **env_overrides: str
    ) -> 'subprocess.CompletedProcess':
        """
        Source the real subject, then run `body` in the same bash process.

        The subject path travels in the environment, not spliced into the
        script text, so no quoting of the path is involved.
        """
        script = 'source "${ONION_TIME_PRE_SCRIPT}"\n' + body
        env = dict(
            os.environ,
            HELPER_SCRIPTS_PATH=self.root,
            ONION_TIME_PRE_SCRIPT=self.path,
            **env_overrides,
        )
        return run_bash(script, env)
