#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
SdwdateClass.preparation retry pacing.

The loop lengthens its wait after each failed onion-time-pre-script run, but
drops back whenever the script's output differs from the previous run. Each run
spawns six Tor control port helpers, so an output that changes on every run
(Tor's bootstrap line carries an incrementing retry counter) used to hold the
loop at a one second interval indefinitely, burning most of a core on a
Gateway that had no network yet.

The floor is what bounds that cost, and it has to hold no matter what the
pre-script prints. The ceiling still has to be reachable, and a genuine status
change still has to shorten the interval.
"""

import unittest

from sdwdate_testlib import PreparationTestBase

FLOOR_SECONDS = 3
CEILING_SECONDS = 10

## Tor's bootstrap line while the network is unreachable. COUNT= increments on
## every failed connection attempt, so consecutive runs never repeat.
WARN_TEMPLATE = (
    'WARN BOOTSTRAP PROGRESS=80 TAG=conn_or '
    'SUMMARY="Connecting to the Tor network" WARNING="No route to host" '
    'REASON=NOROUTE COUNT=%d RECOMMENDATION=warn'
)

## Exit code 2 is onion-time-pre-script's "wait, show busy icon and retry".
BUSY = 2


class TestPreparationBackoff(PreparationTestBase):
    def test_output_changing_every_run_respects_the_floor(self) -> None:
        """
        The regression. An output that never repeats must not drive the retry
        interval below the floor.
        """
        results = [(WARN_TEMPLATE % count, BUSY) for count in range(20)]
        self.run_preparation(results)

        self.assertTrue(self.slept, 'preparation() never slept')
        self.assertGreaterEqual(
            min(self.slept),
            FLOOR_SECONDS,
            'retry interval dropped below the floor: %r' % self.slept,
        )

    def test_unchanged_output_reaches_the_ceiling(self) -> None:
        """The backoff must still ramp when the status is genuinely static."""
        results = [(WARN_TEMPLATE % 26, BUSY)] * 30
        self.run_preparation(results)

        self.assertEqual(
            max(self.slept),
            CEILING_SECONDS,
            'backoff never reached the ceiling: %r' % self.slept,
        )

    def test_interval_never_exceeds_the_ceiling(self) -> None:
        results = [(WARN_TEMPLATE % 26, BUSY)] * 40
        self.run_preparation(results)

        self.assertLessEqual(
            max(self.slept),
            CEILING_SECONDS,
            'retry interval exceeded the ceiling: %r' % self.slept,
        )

    def test_status_change_shortens_the_interval_again(self) -> None:
        """
        Responsiveness guard. After ramping to the ceiling on a static status,
        a real change must drop the wait back to the floor rather than leave
        the loop crawling.
        """
        static = [(WARN_TEMPLATE % 26, BUSY)] * 20
        changed = [('NOTICE BOOTSTRAP PROGRESS=95 TAG=enough_dirinfo', BUSY)]
        self.run_preparation(static + changed)

        self.assertEqual(
            max(self.slept),
            CEILING_SECONDS,
            'did not ramp before the change: %r' % self.slept,
        )
        self.assertEqual(
            self.slept[-1],
            FLOOR_SECONDS,
            'a changed status did not shorten the interval: %r' % self.slept,
        )

    def test_every_interval_is_within_bounds(self) -> None:
        """Mixed churn and quiet: no interval may escape either bound."""
        results = []
        for count in range(15):
            results.append((WARN_TEMPLATE % count, BUSY))
            results.append((WARN_TEMPLATE % count, BUSY))
        self.run_preparation(results)

        for interval in self.slept:
            self.assertGreaterEqual(interval, FLOOR_SECONDS, repr(self.slept))
            self.assertLessEqual(interval, CEILING_SECONDS, repr(self.slept))

    def test_immediate_success_does_not_sleep(self) -> None:
        """
        Boot latency guard. The first run happens with no preceding wait, so a
        Gateway whose Tor is already up is not delayed by the floor.
        """
        self.run_preparation([])

        self.assertEqual(
            self.slept, [], 'slept before reporting success: %r' % self.slept
        )

    def test_every_pre_script_child_is_reaped(self) -> None:
        """
        Each attempt must reap its child. At the rate this loop can run, a
        leaked process per attempt would be its own resource problem.
        """
        results = [(WARN_TEMPLATE % count, BUSY) for count in range(5)]
        self.run_preparation(results)

        self.assertEqual(len(self.processes), len(results) + 1)
        for index, process in enumerate(self.processes):
            self.assertTrue(process.killed, 'child %d not reaped' % index)


if __name__ == '__main__':
    unittest.main()
