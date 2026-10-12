#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Unit tests for sdwdate-gui-enabled-check, the ExecCondition that collapses the
'disable' kill-switch to sdwdate-gui.service presence.

Contract: exit 1 (systemd skips the unit cleanly) ONLY when config says
disable=true; exit 0 otherwise -- INCLUDING on a config-read failure, so a
broken config cannot silently hide the GUI. The script is source-able, so these
tests source it and drive sdwdate_gui_disabled with a stub config reader.
"""

# pylint: disable=invalid-name

import unittest

from bash_harness_common import locate_script, run_sourced


class TestEnabledCheck(unittest.TestCase):
    """sdwdate-gui-enabled-check gates the unit on the disable config value."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-enabled-check')

    def _run_main(self, config_stub_body: str):
        body = f"""
        fake_config_read() {{ {config_stub_body} }}
        source "${{SDWDATE_GUI_SCRIPT}}"
        main
        """
        return run_sourced(
            self.script, body, {'sdwdate_gui_config_read_cmd': 'fake_config_read'}
        )

    def test_disabled_true_skips_unit(self) -> None:
        """disable=true exits 1 so systemd skips the unit."""
        result = self._run_main("printf '%s\\n' 'true';")
        self.assertEqual(
            result.returncode,
            1,
            'enabled-check did not exit 1 when disabled; the unit would still '
            'start',
        )

    def test_enabled_runs_unit(self) -> None:
        """disable=false exits 0 so the unit runs."""
        result = self._run_main("printf '%s\\n' 'false';")
        self.assertEqual(
            result.returncode,
            0,
            f'enabled-check did not exit 0 when enabled: {result.stderr}',
        )

    def test_config_read_failure_does_not_disable(self) -> None:
        """
        A config-read failure must NOT disable (exit 0): a broken config must
        not silently hide the GUI. A regression that treated failure as
        disabled would exit 1 and fail this test.
        """
        result = self._run_main('return 1;')
        self.assertEqual(
            result.returncode,
            0,
            'enabled-check disabled the GUI on a config-read failure; it must '
            'fail safe (treat as enabled)',
        )

    def test_asks_config_for_the_disable_key(self) -> None:
        """sdwdate_gui_disabled reads specifically the 'disable' config key."""
        body = """
        fake_config_read() { printf '%s\\n' "$1" > "${ARG_LOG}"; printf 'false\\n'; }
        source "${SDWDATE_GUI_SCRIPT}"
        sdwdate_gui_disabled || true
        """
        import tempfile  # pylint: disable=import-outside-toplevel
        from pathlib import Path  # pylint: disable=import-outside-toplevel

        with tempfile.TemporaryDirectory() as tmp_str:
            arg_log = Path(tmp_str) / 'arg.log'
            result = run_sourced(
                self.script,
                body,
                {
                    'ARG_LOG': str(arg_log),
                    'sdwdate_gui_config_read_cmd': 'fake_config_read',
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                arg_log.read_text(encoding='utf-8').strip(),
                'disable',
                'sdwdate_gui_disabled did not query the disable config key',
            )


if __name__ == '__main__':
    unittest.main()
