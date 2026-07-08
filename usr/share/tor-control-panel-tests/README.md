# tor-control-panel tests

Comprehensive headless test suite for **tor-control-panel** (which also contains
the merged **anon-connection-wizard**): torrc generation/parsing, the GUIs, the
privilege chain, the plain-Debian write path, and fuzzing of the untrusted-input
parsers.

## How it runs

The suite exercises the real code through `tcp_testlib`, which:

- runs Qt under the `offscreen` platform plugin (no X server);
- redirects the torrc / comm-file paths to a private temp dir and replaces the
  privileged `write_to_temp_then_move()` + privilege-runner calls with in-process
  stubs, so the generated config is observed without root, privleap, or a Tor
  daemon;
- neutralises the blocking modal loops so the wizard / panel are built headless
  and their handlers invoked directly.

The package under test is resolved by `tcp_testlib`: `TCP_REPO` (a
tor-control-panel checkout) if set, else the installed
`/usr/lib/python3/dist-packages/tor_control_panel`. Suites that need extra tools
skip cleanly when absent (`python3-stem`, the `tor` binary, network).

## Coverage

- **torrc gen/parse** (`test_torrc_gen`): every bridge type (None / obfs4 /
  snowflake / meek / custom) and proxy type (None / SOCKS4 / SOCKS5, with/without
  auth) generates the expected torrc and round-trips through `parse_torrc`.
- **Enable/disable + idempotency** (`test_tor_status`, `test_idempotency`):
  `DisableNetwork` toggled in place; repeating or interleaving config actions
  never duplicates, bloats, or corrupts the torrc.
- **GUIs** (`test_gui_driven`, `test_gui_gaps`, `test_ui_walkthrough`,
  `test_tor_control_panel`, `test_anon_connection_wizard`): headless feature and
  branch/handler coverage of both front-ends; NEWNYM without restart; sanitized
  log/torrc/bootstrap display.
- **Privilege chain** (`test_privilege`): leaprun -> pkexec -> passwordless sudo
  -> error; action-to-command mapping.
- **Plain Debian** (`test_distro_agnostic`, `test_tor_config_sane`,
  `test_debian_writepath`, `test_torrc_applied`): distro-aware drop-in dir
  (`/etc/tor/torrc.d` vs `/usr/local/etc/torrc.d`); `tor-config-sane` adds the
  `%include` (and migrates a stale one) but no redundant `ControlSocket`; the
  full privileged write path proven with `tor --verify-config`.
- **Bootstrap parser** (`test_tor_bootstrap`): the untrusted `status/bootstrap-
  phase` parser and thread lifetime.
- **Live-Tor integration** (`test_live_tor`): drives the app's own
  `TorBootstrap` against a throwaway `tor` for obfs4 / snowflake / meek bridges
  (needs the tor binary + network; skips otherwise).
- **Interactive plan** (`test_manual_plan`): the GUI walkthrough encoded as
  skipped tests (require a display + live Tor).

## Running

```
tor-control-panel-tests                    # core suite (fast, no root/network)
tor-control-panel-tests -v
TCP_REPO=/path/to/tor-control-panel tor-control-panel-tests   # test a checkout

tor-control-panel-tests-fuzz               # randomized fuzz of the parsers
tor-control-panel-tests-fuzz --iterations 50000 --seed 1
```

Coverage-guided fuzzing (ClusterFuzzLite + Atheris) and the static scanners
(Bandit, CodeQL, Coverity) live in the `tor-control-panel` repo itself.
