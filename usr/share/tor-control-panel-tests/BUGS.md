# tor-control-panel (Qt6 rewrite) - bugs the suite works around

Bugs in the `tor-control-panel` Qt6 rewrite that this suite cannot assert "fixed" against
yet (the app is not patched here). The full set of rewrite bugs found while reconciling PR
#4's CodeRabbit comments is tracked as GitHub issues on `org-ai-assisted/tor-control-panel`;
this file records only what the suite itself xfails or scopes around.

## make_sane raises AssertionError on a malformed bridge line
Tracked: org-ai-assisted/tor-control-panel#5

- `tor_control_panel_lib.py:397` -- `assert len(bridge_bit_list) > 1`.
- `tcpl_make_tor_conf_info_sane`'s contract is to RETURN a string for input it cannot fix,
  never raise. An empty / whitespace-only / single-token bridge line with bridges enabled
  raises `AssertionError`, breaking that contract for any caller.
- `test_make_sane.test_empty_bridge_line_returns_str_not_assertionerror` is
  `@unittest.expectedFailure`; it flips to XPASS (suite red) once line 397 returns a string
  -- the signal to drop the marker.
- `fuzz_torrc`'s make_sane phase fuzzes WELL-FORMED bridge lines only
  (`_rand_valid_bridge_lines`), so it does not trip this assert. It is not a flip-signal for
  the fix; widening its bridge domain is a separate follow-up once line 397 is hardened.
- NOTE: this is a DIFFERENT assert from the empty-custom-bridge GUI abort
  (`tor_control_panel.py:1281`, `assert bridge_type in bridges_default_dict`); that path
  aborts before reaching make_sane, so fixing line 397 does not fix the GUI path.

## tcp-write-torrc installs client torrc unvalidated (config injection)
Tracked: org-ai-assisted/tor-control-panel#17

- Two defects, one issue. (a) SHELL: `tcp-write-torrc:49-54` wraps the `unicode-show` and
  `tcp-validate-torrc` checks in `if ! cmd; then printf; fi` with no `exit`; under
  `set -o errexit` a failure in an `if` CONDITION does not abort, so line 56 `mv` installs
  the temp file regardless -- validation is cosmetic. (b) VALIDATOR: even once enforced,
  `tcp_validate_torrc` only parse-checks, and `tcpl_parse_torrc` records only the
  `ClientTransportPlugin` transport NAME, not the exec path, so `ClientTransportPlugin obfs4
  exec /tmp/evil` validates clean.
- `test_validate_torrc_cli.test_transport_plugin_exec_is_rejected` is
  `@unittest.expectedFailure`; it flips to XPASS (suite red) once the validator rejects
  directives/values the panel does not emit -- the signal to drop the marker. It is the
  validator-strictness (b) flip-signal.
- The shell `exit 1` half (a) is shell-only: observing "mv runs despite a failed check"
  needs the real root helper (root-owned FIFO + `/usr/local/etc/torrc.d`), not unit-testable
  here without root, so it is tracked in #17, not gated by this suite.
- Also covers the minor f-string bug: `tcp_validate_torrc.py:33` is a plain string, so the
  not-a-file error prints literal `{str(torrc_path)}`.
  `test_validate_torrc_cli.test_not_a_file_message_interpolates_path` is
  `@unittest.expectedFailure`; XPASS once the `f` prefix is added.

## communicate(timeout=1) on the privileged write is too tight
Tracked: org-ai-assisted/tor-control-panel#7

- `tor_control_panel_lib.py:722` gives the helper 1s, but the privileged write now also runs
  `unicode-show` and spawns a fresh python `tcp-validate-torrc` (imports the lib + stem); on a
  slow/loaded host that can exceed 1s and spuriously report "Torrc file write timed out!".
- The suite does NOT gate this: `tcp_testlib._FifoWriteStub.communicate(timeout=...)` accepts
  any timeout and never spawns the real helper, so the value is not observable here. Recorded
  so the silence is intentional, not an oversight.
