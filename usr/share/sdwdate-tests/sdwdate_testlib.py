#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared helpers for the sdwdate suite.

sdwdate.sdwdate is imported for real (it is the subject), which pulls in
guimessages + sanitize_string from helper-scripts and dateutil + stem via
sdwdate.timesanitycheck. The module also notifies systemd at import time; that
is harmless without NOTIFY_SOCKET, and the notifier is stubbed anyway.
"""

import logging
import os
import sys
import tempfile
import unittest


def sdwdate_dist_packages() -> str:
    """
    Resolve the dist-packages directory holding the sdwdate package.

    SDWDATE_REPO -> that checkout, else the installed package.
    """
    repo = os.environ.get('SDWDATE_REPO', '').strip()
    if repo:
        return os.path.join(repo, 'usr', 'lib', 'python3', 'dist-packages')
    return '/usr/lib/python3/dist-packages'


def import_sdwdate():
    """
    Import and return the sdwdate.sdwdate module, or exit 77 (the runner's SKIP
    code) when it or one of its imports is unavailable.

    Under a --component run the runner treats an unauthorized SKIP as a
    FAILURE, so a missing dependency in CI still turns the gate red rather
    than passing vacuously.
    """
    dist_packages = sdwdate_dist_packages()
    module_path = os.path.join(dist_packages, 'sdwdate', 'sdwdate.py')
    if not os.path.exists(module_path):
        print(
            'SKIP: %s not found -- install sdwdate or set SDWDATE_REPO'
            % module_path,
            file=sys.stderr,
        )
        sys.exit(77)
    if dist_packages not in sys.path:
        sys.path.insert(0, dist_packages)
    try:
        import sdwdate.sdwdate as sdwdate_module
    except ImportError as exc:
        print(
            'SKIP: cannot import sdwdate.sdwdate (%s) -- needs helper-scripts '
            'on PYTHONPATH plus python3-sdnotify, python3-dateutil, '
            'python3-stem' % exc,
            file=sys.stderr,
        )
        sys.exit(77)
    return sdwdate_module


class FakePopen:
    """
    Stand-in for the onion-time-pre-script child process.

    Mirrors only what SdwdateClass.preparation uses: communicate() returning
    the byte pair, kill(), and returncode.
    """

    def __init__(self, stdout: str, stderr: str, returncode: int) -> None:
        self._stdout = stdout.encode('UTF-8')
        self._stderr = stderr.encode('UTF-8')
        self.returncode = returncode
        self.killed = False

    def communicate(self):
        return (self._stdout, self._stderr)

    def kill(self) -> None:
        self.killed = True


class NullNotifier:
    """Stand-in for sdnotify.SystemdNotifier."""

    def __init__(self) -> None:
        self.messages = []

    def notify(self, message: str) -> None:
        self.messages.append(message)


class PreparationTestBase(unittest.TestCase):
    """
    Drives SdwdateClass.preparation with a scripted sequence of
    onion-time-pre-script results and records what it would have slept.

    preparation() never touches self, so it is called unbound with None rather
    than constructing an SdwdateClass (whose __init__ reads pool config off
    disk).
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.sdwdate = import_sdwdate()

    def setUp(self) -> None:
        module = self.sdwdate
        self.slept = []
        self.runs = []
        self.processes = []
        self._saved = {}

        ## LOGGER is created in main(), so it does not exist on a bare import.
        self._stub(module, 'LOGGER', logging.getLogger('sdwdate-tests'))
        self.sdwdate.LOGGER.addHandler(logging.NullHandler())
        self.sdwdate.LOGGER.propagate = False
        self._stub(module, 'SDNOTIFY_OBJECT', NullNotifier())

        ## write_status() writes both of these globals, which main() creates via
        ## global_files(). Its first write swallows errors, so an unwritable
        ## path would hide a real failure behind a vacuous pass. Give it real
        ## files.
        self.status_path = self._temp_file('status')
        self.msg_path = self._temp_file('msg')
        self._stub(module, 'status_file_path', self.status_path)
        self._stub(module, 'msg_path', self.msg_path)

        ## write_preparation_output() writes this global (systemcheck reads it).
        ## Give it a real file so a missing write shows as an empty file rather
        ## than a swallowed NameError.
        self.preparation_output_path = self._temp_file('preparation_output')
        self._stub(
            module, 'preparation_output_path', self.preparation_output_path)

        ## Record instead of actually sleeping: the assertions are about the
        ## requested interval, and real sleeps would make the suite take
        ## minutes.
        self._stub(module.time, 'sleep', self.slept.append)

    def tearDown(self) -> None:
        for (owner, name), value in self._saved.items():
            if value is self._MISSING:
                delattr(owner, name)
            else:
                setattr(owner, name, value)

    _MISSING = object()

    def _temp_file(self, suffix: str) -> str:
        handle, path = tempfile.mkstemp(prefix='sdwdate-tests-%s.' % suffix)
        os.close(handle)
        self.addCleanup(os.unlink, path)
        return path

    def _stub(self, owner, name: str, value) -> None:
        self._saved[(owner, name)] = getattr(owner, name, self._MISSING)
        setattr(owner, name, value)

    def run_preparation(self, results) -> bool:
        """
        Run preparation() against `results`, a list of (stdout, returncode)
        pairs. A final success is appended so the otherwise infinite loop
        terminates.
        """
        queue = list(results) + [('done', 0)]

        def fake_popen(path, stdout=None, stderr=None):
            entry = queue.pop(0)
            self.runs.append(entry)
            process = FakePopen(entry[0], '', entry[1])
            self.processes.append(process)
            return process

        self._stub(self.sdwdate.subprocess, 'Popen', fake_popen)
        returned = self.sdwdate.SdwdateClass.preparation(None)
        ## Guard against a vacuous pass: the loop must actually have consumed
        ## every scripted result, and reported success at the end.
        self.assertTrue(returned, 'preparation() did not report success')
        self.assertEqual(
            len(self.runs),
            len(results) + 1,
            'preparation() did not run the pre-script once per scripted result',
        )
        return returned
