#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression tests for sdwdate_gui_client reconnect backoff.

Under Qubes a down or disabled gateway has no server socket, so each qrexec
Connect fails fast and the session drops at once. Reconnecting at a FIXED rate
would then issue one gateway qrexec call per second and flood dom0's
qrexec-policy log. main_loop must therefore back off EXPONENTIALLY (capped),
not sleep a constant delay.

These assert the growth and the cap; a regression to a fixed delay (the old
asyncio.sleep(1)) fails test_main_loop_backs_off_exponentially.
"""

# pylint: disable=wrong-import-position,invalid-name

import asyncio
import unittest
import unittest.mock as mock

try:
    from sdwdate_gui import sdwdate_gui_client as client
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard  # pylint: disable=import-outside-toplevel

    subject_guard.skip_if_subject_absent(exc)


class _StopLoop(BaseException):
    """
    Sentinel used to break out of the otherwise-infinite main_loop.

    Inherits BaseException (like KeyboardInterrupt / SystemExit) so a broad
    'except Exception' anywhere in main_loop can never swallow it and leave the
    test spinning.
    """


class TestReconnectBackoff(unittest.IsolatedAsyncioTestCase):
    """reconnect_backoff grows the delay exponentially up to the cap."""

    def setUp(self) -> None:
        ## reconnect_delay is class state; start each test from the initial.
        client.GlobalData.reconnect_delay = client.INITIAL_RECONNECT_DELAY
        self.addCleanup(
            setattr,
            client.GlobalData,
            'reconnect_delay',
            client.INITIAL_RECONNECT_DELAY,
        )

    async def test_backoff_doubles_each_call(self) -> None:
        delays: list[float] = []
        real_sleep = asyncio.sleep

        async def fake_sleep(delay, *args, **kwargs):
            delays.append(delay)
            return await real_sleep(0, *args, **kwargs)

        with mock.patch.object(asyncio, 'sleep', fake_sleep):
            for _ in range(4):
                await client.reconnect_backoff()

        self.assertEqual(
            delays,
            [1.0, 2.0, 4.0, 8.0],
            'reconnect_backoff did not double the delay each call',
        )

    async def test_backoff_caps_at_max(self) -> None:
        client.GlobalData.reconnect_delay = client.MAX_RECONNECT_DELAY
        real_sleep = asyncio.sleep

        async def fake_sleep(_delay, *args, **kwargs):
            return await real_sleep(0, *args, **kwargs)

        with mock.patch.object(asyncio, 'sleep', fake_sleep):
            await client.reconnect_backoff()

        self.assertEqual(
            client.GlobalData.reconnect_delay,
            client.MAX_RECONNECT_DELAY,
            'reconnect_backoff grew the delay past the cap',
        )

    async def test_main_loop_backs_off_exponentially(self) -> None:
        """
        main_loop must back off with a GROWING delay between failed do_setup()
        retries, not a constant one. The old fixed asyncio.sleep(1) yields
        [1, 1, 1] and fails the exponential assertion below.
        """
        setup_calls: dict[str, int] = {'n': 0}
        sleep_delays: list[float] = []

        async def fake_do_setup() -> bool:
            setup_calls['n'] += 1
            ## Escape the infinite loop after three backoff sleeps.
            if setup_calls['n'] >= 4:
                raise _StopLoop
            return False

        real_sleep = asyncio.sleep

        async def fake_sleep(delay, *args, **kwargs):
            sleep_delays.append(delay)
            return await real_sleep(0, *args, **kwargs)

        with mock.patch.object(client, 'do_setup', fake_do_setup), \
                mock.patch.object(asyncio, 'sleep', fake_sleep):
            with self.assertRaises(_StopLoop):
                await client.main_loop()

        self.assertEqual(
            sleep_delays[:3],
            [1.0, 2.0, 4.0],
            'main_loop did not back off exponentially on repeated connect '
            f'failures (saw {sleep_delays[:3]}); a persistently-down gateway '
            'would be polled at a fixed rate and flood dom0',
        )


if __name__ == '__main__':
    unittest.main()
