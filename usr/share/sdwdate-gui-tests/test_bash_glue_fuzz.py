#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Property-fuzz the sdwdate-gui bash-glue string handling.

The Qubes glue scripts handle UNTRUSTED or config-sourced strings -- the
server-permitted role value, the 'disable' config value, and the gateway VM
name passed straight to qrexec. ai-review flagged that only the literal
happy-path strings were ever exercised. These Hypothesis properties drive the
REAL source-able functions over arbitrary strings (empty, whitespace, newlines,
near-misses like 'true ', 'TRUE', unicode) and assert the exact-match branch
invariants hold, the gateway argument round-trips verbatim, and nothing crashes.

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
## everything else a qubesdb/config value could realistically carry, plus the
## exact literals the branches test so the boundary is always hit.
_glue_text = st.one_of(
    st.sampled_from(
        ['true', '', ' ', 'true ', 'TRUE', 'false', 'sys-whonix', '-x',
         '\r', '\n', 'a\rb', 'a\nb']
    ),
    st.text(
        alphabet=st.characters(min_codepoint=0x01, max_codepoint=0x2FF),
        max_size=48,
    ),
)

_SLOW = settings(max_examples=25, deadline=None)


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


class TestEnabledCheckFuzz(unittest.TestCase):
    """sdwdate-gui-enabled-check: exit 1 IFF the disable value is exactly 'true'."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-enabled-check')

    @_SLOW
    @given(disable=_glue_text)
    def test_disable_exact_match(self, disable: str) -> None:
        body = """
        fake_config_read() { printf '%s' "${DISABLE}"; }
        source "${SDWDATE_GUI_SCRIPT}"
        main
        """
        res = run_sourced(
            self.script,
            body,
            {'DISABLE': disable, 'sdwdate_gui_config_read_cmd': 'fake_config_read'},
        )
        ## No bash crash (syntax/unset): exit 0 (enabled) or 1 (disabled) only,
        ## never 2 (misparse) or 127 (command fault).
        self.assertIn(res.returncode, (0, 1), res.stderr)
        self.assertEqual(
            res.returncode,
            1 if disable == 'true' else 0,
            f'enabled-check gated wrongly for disable={disable!r}',
        )


class TestConnectGatewayFuzz(unittest.TestCase):
    """connect_to_gateway passes ANY gateway value verbatim, no splitting."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-proxy')

    @_SLOW
    @given(gateway=_glue_text)
    def test_gateway_arg_round_trips(self, gateway: str) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            gw_log = tmp / 'gw'
            svc_log = tmp / 'svc'
            body = """
            qrexec-client-vm() {
              printf '%s' "$1" > "${GW_LOG}"
              printf '%s' "$2" > "${SVC_LOG}"
            }
            source "${SDWDATE_GUI_SCRIPT}"
            connect_to_gateway "${GATEWAY}"
            """
            res = run_sourced(
                self.script,
                body,
                {
                    'GATEWAY': gateway,
                    'GW_LOG': str(gw_log),
                    'SVC_LOG': str(svc_log),
                },
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            ## The gateway reaches qrexec as a single verbatim argument (no word
            ## splitting / glob), and the service name is always appended.
            ## Compare BYTES: read_text() would universal-newline-translate a
            ## gateway containing CR/LF and spuriously mismatch.
            self.assertEqual(
                gw_log.read_bytes(),
                gateway.encode('utf-8'),
                f'gateway argument not passed verbatim for {gateway!r}',
            )
            self.assertEqual(
                svc_log.read_bytes(),
                b'sdwdate-gui.Connect',
                'connect_to_gateway did not request the Connect service',
            )


class TestConnectSetupGateFuzz(unittest.TestCase):
    """connect-setup: create the Connect endpoint IFF run_server_in_qubes=='true'."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-connect-setup')

    @_SLOW
    @given(run_server=_glue_text)
    def test_endpoint_only_when_server(self, run_server: str) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            endpoint = Path(tmp_str) / 'sdwdate-gui.Connect'
            body = """
            id() {
              case "$3" in
                user)     printf '1000\\n' ;;
                sysmaint) printf '1001\\n' ;;
                *)        command id "$@" ;;
              esac
            }
            fake_config_read() { printf '%s\\n' "${RUN_SERVER}"; }
            source "${SDWDATE_GUI_SCRIPT}"
            main
            """
            res = run_sourced(
                self.script,
                body,
                {
                    'RUN_SERVER': run_server,
                    'sdwdate_gui_config_read_cmd': 'fake_config_read',
                    'sdwdate_gui_boot_session': 'user_session',
                    'sdwdate_gui_connect_endpoint': str(endpoint),
                },
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(
                endpoint.is_symlink(),
                run_server == 'true',
                f'endpoint presence wrong for run_server={run_server!r}',
            )


if __name__ == '__main__':
    unittest.main()
