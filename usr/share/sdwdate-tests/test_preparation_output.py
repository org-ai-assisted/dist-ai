#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
SdwdateClass.preparation exposes onion-time-pre-script's output to systemcheck.

systemcheck displays an 'onion-time-pre-script reports:' line but must not run
the script itself: that would be a second copy of the Tor bootstrap chain, and
the script actively requests clock corrections (anondate-set) and sends Tor
newnym -- side effects a passive diagnostic must not trigger. So sdwdate writes
its own last output to preparation_output_path on every preparation loop, and
systemcheck reads that file.

The write must happen once per run and reflect the current output, including on
the success return and on the unchanged-output branch (which otherwise
'continue's without further work).
"""

import unittest

from sdwdate_testlib import PreparationTestBase

## onion-time-pre-script exit 2 == "wait, show busy icon and retry".
BUSY = 2

## FakePopen leaves stderr empty and puts the scripted string on stdout;
## joint_message is stderr + '\n' + stdout.
SUCCESS_OUTPUT = '\ndone'


class TestPreparationOutput(PreparationTestBase):
    def _read_output(self) -> str:
        with open(self.preparation_output_path) as file_object:
            return file_object.read()

    def _record_writes(self) -> list:
        """Wrap the real write_preparation_output so each call is observable."""
        module = self.sdwdate
        recorded = []
        original = module.write_preparation_output

        def recording(output):
            recorded.append(output)
            original(output)

        self._stub(module, 'write_preparation_output', recording)
        return recorded

    def test_output_written_on_success(self) -> None:
        """
        The success run must be persisted. On the pre-fix code nothing was
        written, so the file stays empty -- this is the canary.
        """
        self.run_preparation([])
        self.assertEqual(self._read_output(), SUCCESS_OUTPUT)

    def test_file_holds_the_most_recent_run(self) -> None:
        """A failing run followed by success leaves the latest output, not the stale one."""
        self.run_preparation([('WARN BOOTSTRAP PROGRESS=80', BUSY)])
        self.assertEqual(self._read_output(), SUCCESS_OUTPUT)

    def test_written_once_per_run_with_current_output(self) -> None:
        """Every run exposes its own output, in order, while Tor is still down."""
        recorded = self._record_writes()
        self.run_preparation(
            [('WARN BOOTSTRAP PROGRESS=80', BUSY),
             ('WARN BOOTSTRAP PROGRESS=85', BUSY)])
        self.assertEqual(
            recorded,
            ['\nWARN BOOTSTRAP PROGRESS=80',
             '\nWARN BOOTSTRAP PROGRESS=85',
             SUCCESS_OUTPUT])

    def test_written_even_when_output_unchanged(self) -> None:
        """
        The write must precede the unchanged-output 'continue', so systemcheck
        still sees a current report even when the status line does not move.
        """
        recorded = self._record_writes()
        same = ('WARN BOOTSTRAP PROGRESS=80', BUSY)
        self.run_preparation([same, same, same])
        self.assertEqual(
            recorded,
            ['\nWARN BOOTSTRAP PROGRESS=80',
             '\nWARN BOOTSTRAP PROGRESS=80',
             '\nWARN BOOTSTRAP PROGRESS=80',
             SUCCESS_OUTPUT])


if __name__ == '__main__':
    unittest.main()
