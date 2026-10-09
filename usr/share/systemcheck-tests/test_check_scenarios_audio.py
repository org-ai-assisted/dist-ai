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

pw-play presence is steered via PATH (a fake bin dir). The test sound file lives
at a hardcoded absolute path, so the pw-play-present cases run in a bubblewrap
mount namespace: systemcheck-tests-bwrap test_check_scenarios_audio_isolated.py.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario,
)

FILE = 'check_audio.bsh'

## PATH pointing only at a fresh empty dir -> pw-play cannot be found, whatever
## the host has installed, so the "absent" branch is deterministic.
PATH_WITHOUT_PW_PLAY = 'PATH="$(mktemp --directory)"'


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


if __name__ == '__main__':
    unittest.main()
