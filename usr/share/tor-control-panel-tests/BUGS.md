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
