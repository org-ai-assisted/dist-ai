#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression test for the sdwdate-gui-qubes-proxy ConnectCheck poll.

Bug: the workstation proxy polled sdwdate-gui.ConnectCheck at a FIXED 1 Hz
with no backoff and no upper bound. Every poll is a qrexec call that dom0's
qrexec-policy-daemon logs, so whenever the gateway endpoint is slow or absent
the dom0 journal is flooded at one line per client VM per second, forever.

Fix: capped exponential backoff (1, 2, 4, ... up to a cap), implemented with
the helper-scripts light_sleep function.

This test runs the real script with stubbed dependencies and asserts the sleep
durations grow geometrically and saturate at the cap -- failing on the old
fixed-interval code (which never calls light_sleep at all).
"""

# pylint: disable=invalid-name

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


def _locate_script(name: str) -> Path:
    try:
        import sdwdate_gui  # pylint: disable=import-outside-toplevel
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise unittest.SkipTest(
            "sdwdate-gui is not importable; install the 'sdwdate-gui' package "
            'or set PYTHONPATH to its dist-packages directory'
        ) from exc
    start = Path(sdwdate_gui.__file__).resolve()
    for ancestor in start.parents:
        candidate = ancestor / 'libexec' / 'sdwdate-gui' / name
        if candidate.is_file():
            return candidate
    raise unittest.SkipTest(f"could not locate the '{name}' script")


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text, encoding='utf-8')
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class TestQubesProxyBackoff(unittest.TestCase):
    """sdwdate-gui-qubes-proxy must back off, not poll at a fixed 1 Hz."""

    ## Number of 'n' (not-ready) ConnectCheck replies before a 'y'. Chosen so
    ## the backoff reaches and holds at the cap for a few iterations.
    connectcheck_n = 8
    expected_delays = ['1', '2', '4', '8', '16', '32', '64', '64', '64']

    def test_backoff_is_capped_exponential(self) -> None:
        script = _locate_script('sdwdate-gui-qubes-proxy')
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            bin_dir = tmp / 'bin'
            stub_dir = tmp / 'stubs'
            bin_dir.mkdir()
            stub_dir.mkdir()
            light_sleep_log = tmp / 'light_sleep.log'
            qrexec_count = tmp / 'qrexec.count'

            ## light_sleep stub: record each requested duration, never sleep.
            _write_exec(
                stub_dir / 'light_sleep.bsh',
                'light_sleep() { printf \'%s\\n\' "$1" '
                '>> "${LIGHT_SLEEP_LOG}"; }\n',
            )
            ## systemd-notify stub: make "${systemd_notify[@]}" --ready a no-op.
            _write_exec(
                stub_dir / 'systemd-notify.bsh',
                'systemd_notify=(true)\n',
            )
            ## config-read stub: the proxy only reads the 'gateway' key.
            _write_exec(
                stub_dir / 'sdwdate-gui-config-read',
                "#!/bin/bash\nprintf '%s\\n' 'sys-test-gw'\n",
            )
            ## qrexec-client-vm stub: reply 'n' connectcheck_n times then 'y';
            ## Connect just succeeds.
            _write_exec(
                bin_dir / 'qrexec-client-vm',
                '#!/bin/bash\n'
                'service="$2"\n'
                'if [ "${service}" = "sdwdate-gui.ConnectCheck" ]; then\n'
                '  count="$(cat "${QREXEC_COUNT_FILE}" 2>/dev/null || echo 0)"\n'
                '  count="$((count + 1))"\n'
                '  printf \'%s\\n\' "${count}" > "${QREXEC_COUNT_FILE}"\n'
                '  if [ "${count}" -le "${CONNECTCHECK_N}" ]; then\n'
                '    printf \'%s\\n\' n\n'
                '  else\n'
                '    printf \'%s\\n\' y\n'
                '  fi\n'
                'fi\n'
                'exit 0\n',
            )
            ## sleep stub: keep a regression on the OLD fixed-`sleep 1` code
            ## fast (it would otherwise really sleep and still fail the assert).
            _write_exec(bin_dir / 'sleep', '#!/bin/bash\nexit 0\n')

            ## Materialize a runnable copy with the absolute dependency paths
            ## redirected to the stubs. Production bytes are unchanged; only the
            ## well-known literal paths are rewritten for the harness.
            text = script.read_text(encoding='utf-8')
            text = text.replace(
                '/usr/libexec/helper-scripts/light_sleep.bsh',
                str(stub_dir / 'light_sleep.bsh'),
            )
            text = text.replace(
                '/usr/libexec/helper-scripts/systemd-notify.bsh',
                str(stub_dir / 'systemd-notify.bsh'),
            )
            text = text.replace(
                '/usr/libexec/sdwdate-gui/sdwdate-gui-config-read',
                str(stub_dir / 'sdwdate-gui-config-read'),
            )
            run_script = tmp / 'sdwdate-gui-qubes-proxy'
            _write_exec(run_script, text)

            env = dict(os.environ)
            env['PATH'] = f"{bin_dir}:{env.get('PATH', '')}"
            env['LIGHT_SLEEP_LOG'] = str(light_sleep_log)
            env['QREXEC_COUNT_FILE'] = str(qrexec_count)
            env['CONNECTCHECK_N'] = str(self.connectcheck_n)

            result = subprocess.run(
                ['/bin/bash', str(run_script)],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(
                result.returncode,
                0,
                f'proxy exited non-zero: {result.returncode}\n'
                f'stdout={result.stdout!r}\nstderr={result.stderr!r}',
            )

            self.assertTrue(
                light_sleep_log.is_file(),
                'proxy never called light_sleep -- it is still using a fixed '
                'sleep poll (the dom0 log-spam regression)',
            )
            delays = light_sleep_log.read_text(encoding='utf-8').split()
            self.assertEqual(
                delays,
                self.expected_delays,
                'proxy backoff is not capped-exponential; got delays '
                f'{delays}',
            )


if __name__ == '__main__':
    unittest.main()
