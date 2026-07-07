# tor-control-panel tests

Regression + feature tests for **tor-control-panel** (which now also contains
the merged **anon-connection-wizard**) and its `torrc_gen` / `tor_status`
logic. Derived from the bug reports and the manual test plan in the Whonix forum
thread "Tor controller GUI (tor-control-panel)" (see `BUGS.md` for the full
inventory and `test_manual_plan.py` for arraybolt3's interactive walkthrough).

## What is tested

tor-control-panel is a PyQt5 GUI that turns a user's Tor configuration (bridge
type, custom bridges, proxy, enable/disable network) into torrc drop-in files
and parses them back. In normal operation it writes system paths under
`/usr/local/etc/torrc.d` and `/run/anon-connection-wizard` and shells out to
privileged `leaprun` helpers. The suite exercises the real code through
`tcp_testlib`, which:

- runs Qt under the `offscreen` platform plugin (no X server);
- redirects the torrc / comm-file paths to a private temp dir and replaces the
  privileged `write_to_temp_then_move()` + `leaprun` calls with in-process
  stubs, so the observable effect (the torrc ends up with the generated content)
  is reproduced without root, privleap or a Tor daemon;
- neutralises the blocking `self.exec_()` modal loops so the wizard / panel can
  be built headless and their handlers invoked directly.

## Checks

- **[torrc] generation + parse round-trip** (`test_torrc_gen.py`): every Bridges
  type (None / obfs4 / snowflake / meek / Custom bridges) and Proxy type
  (None / SOCKS4 / SOCKS5, with and without auth) generates the expected torrc,
  and `parse_torrc()` recovers it.
- **[A1] custom-bridge data loss** (`test_torrc_gen.py`): after writing custom
  bridges, `parse_torrc()` must report `Custom bridges` -- otherwise a later
  reconfigure silently replaces them with default obfs4 bridges.
- **[A2] wizard Cancel crash** (`test_anon_connection_wizard.py`): a freshly
  built AnonConnectionWizard has `bootstrap_thread` initialised and
  `cancel_button_clicked()` does not raise.
- **[A3] duplicate network toggle** (`test_tor_control_panel.py`): the
  Bridges-type selector never shows two `Disable network` (or `Enable network`)
  entries across refresh transitions.
- **[manual] GUI walkthrough** (`test_manual_plan.py`): arraybolt3's interactive
  test plan, encoded as skipped tests (require a display + live Tor).

`A4`-`A7` (bridge-line strip, cookie dialog, log-view regex, dropped proxy) are
fixed in source and exercised by the manual plan; see `BUGS.md`.

No root, no network, no Tor daemon (for the non-skipped tests).

## Running

```
tor-control-panel-tests                 # installed package
tor-control-panel-tests -v

# test a checkout instead of the installed package
TCP_REPO=/path/to/tor-control-panel tor-control-panel-tests
```

The package under test is resolved by `tcp_testlib`: `TCP_REPO` (a
tor-control-panel checkout) if set, else the installed
`/usr/lib/python3/dist-packages/tor_control_panel`.
