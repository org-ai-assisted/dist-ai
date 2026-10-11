#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Property-fuzz the sdwdate-gui bash-glue string handling.

The Qubes glue scripts branch on exact-string comparisons of UNTRUSTED values
-- a qrexec ConnectCheck reply, the run_server_in_qubes / disable config
values, and the server-permitted role string. ai-review flagged that only the
literal happy-path strings were ever exercised. These Hypothesis properties
drive the REAL source-able functions over arbitrary strings (empty, whitespace,
newlines, near-misses like 'true ', 'TRUE', 'y\\n...', unicode) and assert the
exact-match branch invariants hold and nothing crashes.

Subprocess-backed, so max_examples is capped and deadline disabled (per-example
bash spawn time varies); this is a --core property suite, not the heavier
in-process fuzzer.
"""

# pylint: disable=invalid-name

import tempfile
import unittest
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from bash_harness_common import locate_script, run_sourced

## No NUL (bash truncates a variable at NUL -- a shell limitation, not a bug);
## everything else a qrexec/qubesdb/config value could realistically carry,
## plus the exact literals the branches test so the boundary is always hit.
_glue_text = st.one_of(
    st.sampled_from(['y', 'q', 'true', '', ' ', 'true ', 'TRUE', 'y\n', 'n']),
    st.text(
        alphabet=st.characters(min_codepoint=0x01, max_codepoint=0x2FF),
        max_size=48,
    ),
)

_SLOW = settings(max_examples=25, deadline=None)


class TestFinalizeConnectReplyFuzz(unittest.TestCase):
    """finalize_connect: flag only on 'q', Connect only on 'y', else retry."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-proxy')

    @_SLOW
    @given(reply=_glue_text)
    def test_reply_branch_invariants(self, reply: str) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            connect_log = tmp / 'connect.log'
            run_dir = tmp / 'run'
            body = """
            qrexec-client-vm() { printf '%s\\n' called >> "${CONNECT_LOG}"; }
            source "${SDWDATE_GUI_SCRIPT}"
            finalize_connect 'sys-test-gw' "${REPLY}"
            """
            res = run_sourced(
                self.script,
                body,
                {
                    'REPLY': reply,
                    'CONNECT_LOG': str(connect_log),
                    'sdwdate_gui_run_dir': str(run_dir),
                },
            )
            flag = (run_dir / 'qubes-gateway-server-disabled').is_file()
            connected = connect_log.is_file()
            ## No bash crash (syntax/unset): 0 on y/q, non-zero only on the
            ## transient arm -- never 2 (bash misparse) or 127 (command fault).
            self.assertIn(res.returncode, (0, 1), res.stderr)
            if reply == 'y':
                self.assertEqual(res.returncode, 0)
                self.assertTrue(connected)
                self.assertFalse(flag)
            elif reply == 'q':
                self.assertEqual(res.returncode, 0)
                self.assertFalse(connected)
                self.assertTrue(flag)
            else:
                ## Transient: no flag, no Connect, non-zero so it retries.
                self.assertEqual(res.returncode, 1)
                self.assertFalse(flag, f'flag wrongly set on reply {reply!r}')
                self.assertFalse(connected)


class TestProxyRoleFuzz(unittest.TestCase):
    """apply_proxy_role: drop the proxy flag IFF the value is not exactly 'true'."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-proxy-helper')

    @_SLOW
    @given(permitted=_glue_text)
    def test_role_flag_only_when_not_true(self, permitted: str) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            flag = Path(tmp_str) / 'should-proxy'
            body = """
            source "${SDWDATE_GUI_SCRIPT}"
            apply_proxy_role "${PERMITTED}"
            """
            res = run_sourced(
                self.script,
                body,
                {'PERMITTED': permitted, 'sdwdate_gui_proxy_flag': str(flag)},
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(
                flag.is_file(),
                permitted != 'true',
                f'proxy-flag presence wrong for permitted={permitted!r}',
            )


class TestServerGatingFuzz(unittest.TestCase):
    """server_gating: 0 iff run_server==true and disable!=true; else 10/11."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-connect')

    @_SLOW
    @given(run_server=_glue_text, disable=_glue_text)
    def test_gating_return_codes(self, run_server: str, disable: str) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            ## A config-read stub that returns the fuzzed value per key.
            stub = Path(tmp_str) / 'config-read-stub'
            stub.write_text(
                '#!/bin/bash\n'
                'case "$1" in\n'
                '  run_server_in_qubes) printf \'%s\' "${RUN_SERVER}" ;;\n'
                '  disable) printf \'%s\' "${DISABLE}" ;;\n'
                'esac\n',
                encoding='utf-8',
            )
            stub.chmod(0o755)
            body = """
            source "${SDWDATE_GUI_SCRIPT}"
            server_gating
            printf 'rc=%s\\n' "$?"
            """
            res = run_sourced(
                self.script,
                body,
                {
                    'sdwdate_gui_config_read_cmd': str(stub),
                    'RUN_SERVER': run_server,
                    'DISABLE': disable,
                },
            )
            rc_line = [
                ln for ln in res.stdout.splitlines() if ln.startswith('rc=')
            ]
            self.assertTrue(rc_line, f'no rc line; stderr={res.stderr}')
            gating_rc = int(rc_line[-1].split('=', 1)[1])
            if run_server != 'true':
                self.assertEqual(gating_rc, 10)
            elif disable == 'true':
                self.assertEqual(gating_rc, 11)
            else:
                self.assertEqual(gating_rc, 0)


if __name__ == '__main__':
    unittest.main()
