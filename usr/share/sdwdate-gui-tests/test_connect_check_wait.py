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
  * 'q' - sdwdate-gui is disabled.

Production blocks INDEFINITELY. To keep CI from hanging, the event-path test
runs the wait in a daemon thread and creates the endpoint from the main thread,
joining with a short real timeout. parse_config_files is patched so the tests
do not depend on the machine's /etc/sdwdate-gui.d contents, matching the
existing config tests.
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
def patched_disable(disable: bool) -> Iterator[None]:
    """
    Patch parse_config_files so ConfigData reports the given 'disable' value,
    independent of the machine's config files.
    """

    def _fake_parse() -> None:
        cc.ConfigData.conf_dict = dict(cc.ConfigData.defaults_dict)
        cc.ConfigData.conf_dict['disable'] = disable

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
        with patched_disable(False):
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
            with patched_disable(False):
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

    def test_disabled_returns_q(self) -> None:
        """sdwdate-gui disabled -> 'q', no watch, no block."""
        with patched_disable(True):
            self.assertEqual(
                cc.wait_for_connect_endpoint(
                    str(self.endpoint), str(self.watch_dir)
                ),
                'q',
            )


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
