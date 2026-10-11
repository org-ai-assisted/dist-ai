#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Unit tests for the event-based sdwdate-gui.ConnectCheck responder logic in
sdwdate_gui.sdwdate_gui_connect_check.

wait_for_connect_endpoint(endpoint_path, watch_dir) blocks until the endpoint
appears, returning:

  * 'y' - the endpoint exists (fast path when already present, or the inotify
          event path once it is created).
  * 'q' - sdwdate-gui is disabled, OR this VM does not run the server
          (run_server_in_qubes not true) and so will never get an endpoint.

Production blocks INDEFINITELY on a server VM whose endpoint has not appeared
yet. To keep CI from hanging, the paths that could block run the wait in a
daemon thread joined with a short real timeout. parse_config_files is patched
so the tests do not depend on the machine's /etc/sdwdate-gui.d contents,
matching the existing config tests.
"""

# pylint: disable=invalid-name

import threading
import time
import unittest
import unittest.mock as mock
from contextlib import contextmanager, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator

try:
    from sdwdate_gui import sdwdate_gui_connect_check as cc
except ModuleNotFoundError as exc:  # pragma: no cover
    raise unittest.SkipTest(
        "sdwdate-gui is not importable; install the 'sdwdate-gui' package "
        'or set PYTHONPATH to its dist-packages directory'
    ) from exc


@contextmanager
def patched_config(
    disable: bool = False, run_server: bool = True
) -> Iterator[None]:
    """
    Patch parse_config_files so ConfigData reports the given 'disable' and
    'run_server_in_qubes' values, independent of the machine's config files.
    Defaults model a server VM with sdwdate-gui enabled (the wait proceeds).
    """

    def _fake_parse() -> None:
        cc.ConfigData.conf_dict = dict(cc.ConfigData.defaults_dict)
        cc.ConfigData.conf_dict['disable'] = disable
        cc.ConfigData.conf_dict['run_server_in_qubes'] = run_server

    with mock.patch.object(cc, 'parse_config_files', side_effect=_fake_parse):
        yield


class TestWaitForConnectEndpoint(unittest.TestCase):
    """wait_for_connect_endpoint resolves via fast path, event path, or 'q'."""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.watch_dir = Path(self._tmp.name)
        self.endpoint = self.watch_dir / 'sdwdate-gui.Connect'

    def test_fast_path_already_present(self) -> None:
        """Endpoint present before the call -> 'y' immediately (arm-then-check)."""
        self.endpoint.write_text('', encoding='utf-8')
        with patched_config():
            self.assertEqual(
                cc.wait_for_connect_endpoint(
                    str(self.endpoint), str(self.watch_dir)
                ),
                'y',
            )

    def test_event_path_created_after_arming(self) -> None:
        """Endpoint absent at call, created later -> 'y' via the inotify event."""
        result: dict[str, str] = {}

        def _wait() -> None:
            with patched_config():
                result['reply'] = cc.wait_for_connect_endpoint(
                    str(self.endpoint), str(self.watch_dir)
                )

        thread = threading.Thread(target=_wait, daemon=True)
        thread.start()
        ## Give the wait time to arm the watch and take the (absent) fast-path
        ## check, so creation here lands on the event path, not the fast path.
        time.sleep(0.3)
        self.assertFalse(
            self.endpoint.exists(), 'endpoint created too early for event path'
        )
        self.endpoint.write_text('', encoding='utf-8')
        thread.join(timeout=10)
        self.assertFalse(
            thread.is_alive(),
            'wait_for_connect_endpoint did not return after the endpoint '
            'appeared (the inotify event path is broken)',
        )
        self.assertEqual(result.get('reply'), 'y')

    def test_event_path_drains_unrelated_events(self) -> None:
        """
        Unrelated creations in the watched dir while waiting are drained each
        wakeup (process_events with a no-op handler); the wait still resolves to
        'y' only when the real endpoint appears, and the unrelated events never
        reach stdout. Exercises the event-queue drain (C2).
        """
        result: dict[str, str] = {}

        def _wait() -> None:
            with patched_config():
                result['reply'] = cc.wait_for_connect_endpoint(
                    str(self.endpoint), str(self.watch_dir)
                )

        thread = threading.Thread(target=_wait, daemon=True)
        thread.start()
        time.sleep(0.3)
        ## Fire several unrelated events the loop must drain, not mistake for
        ## the endpoint and not leave queued.
        for i in range(5):
            (self.watch_dir / f'unrelated-{i}').write_text('', encoding='utf-8')
            time.sleep(0.02)
        self.assertEqual(
            result.get('reply'), None, 'resolved on an unrelated event'
        )
        self.endpoint.write_text('', encoding='utf-8')
        thread.join(timeout=10)
        self.assertFalse(
            thread.is_alive(),
            'wait did not return after the real endpoint appeared',
        )
        self.assertEqual(result.get('reply'), 'y')

    def test_disabled_returns_q(self) -> None:
        """sdwdate-gui disabled -> 'q', no watch, no block."""
        with patched_config(disable=True):
            self.assertEqual(
                cc.wait_for_connect_endpoint(
                    str(self.endpoint), str(self.watch_dir)
                ),
                'q',
            )

    def test_non_server_vm_returns_q(self) -> None:
        """
        run_server_in_qubes not true -> 'q' terminally, never blocking: the
        maintainer never creates an endpoint on a non-server VM, so the
        responder must give up instead of waiting forever (C1). Run in a
        daemon thread so a regression (the old block-forever) FAILS via the
        join timeout rather than hanging the suite.
        """
        result: dict[str, str] = {}

        def _wait() -> None:
            with patched_config(disable=False, run_server=False):
                result['reply'] = cc.wait_for_connect_endpoint(
                    str(self.endpoint), str(self.watch_dir)
                )

        thread = threading.Thread(target=_wait, daemon=True)
        thread.start()
        thread.join(timeout=5)
        self.assertFalse(
            thread.is_alive(),
            'wait_for_connect_endpoint blocked on a non-server VM instead of '
            'returning q (it must not wait for an endpoint that never appears)',
        )
        self.assertEqual(result.get('reply'), 'q')


class TestMain(unittest.TestCase):
    """main() prints the single reply from wait_for_connect_endpoint."""

    def test_main_prints_reply(self) -> None:
        """main() prints whatever wait_for_connect_endpoint returns."""
        out = StringIO()
        with mock.patch.object(
            cc, 'wait_for_connect_endpoint', return_value='y'
        ) as waited:
            with redirect_stdout(out):
                cc.main()
        self.assertEqual(out.getvalue().strip(), 'y')
        ## main() must watch the directory containing the production endpoint.
        waited.assert_called_once_with(
            cc.ENDPOINT_PATH, str(Path(cc.ENDPOINT_PATH).parent)
        )


if __name__ == '__main__':
    unittest.main()
