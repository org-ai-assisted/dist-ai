#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression test for the sdwdate_gui_client.main_loop reconnect backoff.

Bug: when the server socket exists but the connect/setup handshake fails
(stale socket, server not yet accepting), do_setup() returns False and
main_loop() used to `continue` with no delay -- a tight busy-loop at 100%
CPU, because the only asyncio.sleep(1) sat on the already-connected
disconnect path, never on the connect-failure path.

Guards that a failing do_setup() backs off with asyncio.sleep(1) before
retrying.
"""

# pylint: disable=wrong-import-position,invalid-name

import asyncio
import unittest
import unittest.mock as mock

try:
    from sdwdate_gui import sdwdate_gui_client as client
except ModuleNotFoundError as exc:  # pragma: no cover
    raise unittest.SkipTest(
        "sdwdate-gui is not importable; install the 'sdwdate-gui' package "
        'or set PYTHONPATH to its dist-packages directory'
    ) from exc


class _StopLoop(BaseException):
    """
    Sentinel used to break out of the otherwise-infinite main_loop.

    Inherits BaseException (like KeyboardInterrupt / SystemExit) so a broad
    'except Exception' anywhere in main_loop can never swallow it and leave
    the test spinning.
    """


class TestClientReconnectBackoff(unittest.IsolatedAsyncioTestCase):
    """main_loop() must not busy-spin when do_setup() keeps failing."""

    async def test_failed_setup_backs_off(self) -> None:
        setup_calls: dict[str, int] = {'n': 0}
        sleep_delays: list[float] = []

        async def fake_do_setup() -> bool:
            setup_calls['n'] += 1
            ## Second failure raises to escape the infinite loop; the first
            ## failure must have triggered a backoff sleep by then.
            if setup_calls['n'] >= 2:
                raise _StopLoop
            return False

        real_sleep = asyncio.sleep

        async def fake_sleep(delay: float, *args, **kwargs):
            sleep_delays.append(delay)
            ## Preserve real yielding without a wall-clock delay.
            return await real_sleep(0, *args, **kwargs)

        ## Gateway must not look disabled, or main_loop breaks out early.
        disabled_path = mock.MagicMock()
        disabled_path.is_file.return_value = False

        with mock.patch.object(client, 'do_setup', fake_do_setup), \
                mock.patch.object(asyncio, 'sleep', fake_sleep), \
                mock.patch.object(
                    client.GlobalData,
                    'qubes_gateway_server_disabled_path',
                    disabled_path,
                ):
            with self.assertRaises(_StopLoop):
                await client.main_loop()

        self.assertEqual(
            setup_calls['n'],
            2,
            'do_setup() should have been retried after the first failure',
        )
        self.assertIn(
            1,
            sleep_delays,
            'main_loop() busy-spun: no asyncio.sleep(1) backoff between '
            'failed do_setup() retries',
        )


if __name__ == '__main__':
    unittest.main()
