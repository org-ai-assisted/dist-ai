#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Scenario tests for the systemcheck audio self-test: check_audio.

check_audio is a verbose-only diagnostic that plays a short sound via pw-play
(PipeWire) so the user can confirm audio output works. Its branches:

  * verbose < 1                 -> silent, no emission (never plays a sound);
  * pw-play absent              -> info "Skipped" (the non-gui / cli / server
                                   variants have no pw-play -- not a failure);
  * pw-play present, file absent-> info "Skipped" (defensive: sound-theme-
                                   freedesktop is a Depends, so normally present);
  * pw-play present, file present, playback ok   -> info;
  * pw-play present, file present, playback fails -> warning, EXIT_CODE unchanged
                                   (audio is not a system-integrity failure).

pw-play presence is steered via PATH (a fake bin dir); the test sound file lives
at a hardcoded absolute path, so the file-present cases run inside a bubblewrap
mount namespace that materializes it (and a fake pw-play the real `timeout` can
exec). Those cases SkipTest when bubblewrap / user namespaces are unavailable.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario,
    run_check_scenario_isolated,
)

FILE = 'check_audio.bsh'
AUDIO = '/usr/share/sounds/freedesktop/stereo/audio-test-signal.oga'

## PATH pointing only at a fresh empty dir -> pw-play cannot be found, whatever
## the host has installed, so the "absent" branch is deterministic.
PATH_WITHOUT_PW_PLAY = 'PATH="$(mktemp --directory)"'

## An isolated-run PATH with /usr/local/bin first, where the fake pw-play is
## placed, so both `command -v pw-play` and the real `timeout` resolve the stub
## ahead of any host pw-play.
ISOLATED_ENV = 'verbose=1\nPATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"'


def _fake_pw_play(exit_code: int):
    ## A real executable (not a shell function): `timeout` execs pw-play via
    ## PATH, so a function stub would not be seen. Placed at /usr/local/bin.
    return ('/usr/local/bin/pw-play',
            f'#!/bin/bash\nexit {exit_code}\n', True)


class TestAudioScenarios(ScenarioTestBase):
    def test_not_verbose_is_silent(self) -> None:
        ## verbose 0 -> early return, nothing emitted, no sound.
        r = run_check_scenario(self.check(FILE), 'check_audio',
                               env_setup='verbose=0')
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])
        self.assertEqual(r.exit_code, '0')

    def test_pw_play_absent_info_skip(self) -> None:
        ## pw-play not on PATH -> info skip, no warning, EXIT_CODE stays 0.
        r = run_check_scenario(self.check(FILE), 'check_audio',
                               env_setup='verbose=1\n' + PATH_WITHOUT_PW_PLAY)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertIn('Skipped', r.joined())
        self.assertIn('pw-play', r.joined())
        self.assertEqual(r.exit_code, '0')

    def test_file_missing_info_skip(self) -> None:
        ## pw-play present but the sound file absent -> info skip, EXIT_CODE 0.
        r = run_check_scenario_isolated(
            self.check(FILE), 'check_audio', env_setup=ISOLATED_ENV,
            place=[_fake_pw_play(0)], hide_dirs=['/usr/share/sounds'])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertIn('Skipped', r.joined())
        self.assertIn('missing', r.joined())
        self.assertEqual(r.exit_code, '0')

    def test_playback_ok_info(self) -> None:
        ## pw-play present + file present + exit 0 -> info, no warning.
        r = run_check_scenario_isolated(
            self.check(FILE), 'check_audio', env_setup=ISOLATED_ENV,
            place=[_fake_pw_play(0), (AUDIO, 'fake ogg bytes', False)])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertIn('test sound', r.joined())
        self.assertEqual(r.exit_code, '0')

    def test_playback_failure_warns_without_failing(self) -> None:
        ## pw-play present + file present + nonzero exit -> warning, but audio is
        ## not a system-integrity failure so EXIT_CODE must stay 0.
        r = run_check_scenario_isolated(
            self.check(FILE), 'check_audio', env_setup=ISOLATED_ENV,
            place=[_fake_pw_play(1), (AUDIO, 'fake ogg bytes', False)])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('warning'))
        self.assertFalse(r.has_severity('info'))
        self.assertIn('could not play', r.joined())
        self.assertEqual(r.exit_code, '0')


if __name__ == '__main__':
    unittest.main()
