# tor-control-panel test suite

Regression + fuzz tests for the Qt6 `tor-control-panel` rewrite (the
consolidated package: `tor_control_panel_lib` pure logic, `tor_control_panel`
PyQt6 GUI, `tor_status_watcher`).

## Running

```
tor-control-panel-tests            # unittest discovery of test_*.py
tor-control-panel-tests-fuzz       # randomized fuzz of the pure parsers
```

Both resolve the package under test from `TCP_REPO=<checkout>` (the
`dist-ai-tests-all` wiring sets it), else the installed package. Everything runs
offscreen (`QT_QPA_PLATFORM=offscreen`); no root, no network, no real Tor.

## Harness

`tcp_testlib.py` provides the offscreen `QApplication`, source resolution, and:

- `sandbox()` -- redirects `tor_control_panel_lib`'s torrc / comm-FIFO / bridges
  path constants into a temp dir and replaces the privileged-task layer with
  in-process stubs. The `tcp-write-torrc` stub reproduces the real privileged
  helper's effect (the pushed config lands in the fake torrc via the FIFO).
- `no_modal()` -- makes `QDialog.exec` / the `QMessageBox` helpers non-blocking
  so the GUI can be driven headless.

## Coverage

- `test_parse_torrc` -- `tcpl_parse_torrc` valid / invalid / missing-file.
- `test_write_torrc` -- `tcpl_write_torrc` + parse<->write round-trips.
- `test_make_sane` -- `tcpl_make_tor_conf_info_sane` validation contract.
- `test_bridge_prefix` -- bridge-line `Bridge ` prefix add/remove.
- `test_default_port` -- `tcpl_default_port_for_protocol`.
- `test_privileged_consistency` -- the privileged-task map vs the privleap conf
  / libexec helpers.
- `test_watcher_bootstrap` -- `TcplTorMonitor.emit_bootstrap_event_maybe`
  (untrusted control-port bootstrap parsing).
- `test_gui_smoke` -- headless construction + startup wiring of the GUI dialog.
- `fuzz_torrc.py` -- never-raise / typed-return properties of the pure parsers.

## Known-failing (documents a rewrite bug, not a test defect)

A failing test here may be an intentionally-red regression documenting a bug in
the rewrite, cross-referenced to an open issue on the tor-control-panel repo.
Such tests are left red on purpose; do not "fix" them by weakening the test.
