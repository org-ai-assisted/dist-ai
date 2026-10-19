# tor-control-panel (Qt6 rewrite) - known bugs

Bugs found in the `tor-control-panel` Qt6 rewrite (ArrayBolt3 port, adopted onto
`org-ai-assisted/tor-control-panel` branch `ai`, PR #4) while reconciling CodeRabbit
review comments. All were verified against the real rewrite code; none are fixed in
`tor-control-panel` yet (maintainer decision: report, do not patch the app here). The
dist-ai suite stays honest-green around them: `test_make_sane` xfails the one it covers,
and `fuzz_torrc`'s `make_sane` phase fuzzes well-formed bridge input only (see #5).

Line numbers are against `tor-control-panel` tip `f9f0b12`.

## 1. Proxy auth value with a space fails to re-parse (blank config)
- `usr/lib/python3/dist-packages/tor_control_panel/tor_control_panel_lib.py:576-608`
- `tcpl_parse_torrc` splits on every space (`torrc_line.split(" ")`) and requires
  exactly 2 tokens for `Socks5ProxyUsername` / `Socks5ProxyPassword` /
  `HTTPSProxyAuthenticator`. A value containing a space yields >2 tokens ->
  "Invalid number of arguments for ..." -> the panel loads blank config. The UI
  (`QLineEdit`, no validator; only a 1..255 length check) accepts spaces, and
  `tcpl_write_torrc` writes the value unquoted, so the bad line round-trips.
- Repro: set a SOCKS5 password `a b`, Accept, restart the panel -> settings lost.
- Fix sketch: `split(" ", maxsplit=1)` for these value-bearing directives.

## 2. FIFO write client orphans the root writer; no communicate() timeout
- `tor_control_panel_lib.py:691-722`
- The client polls ~1s (10x0.1s) for the comm FIFO. On a slower `leaprun` it raises
  `FileNotFoundError`/`PermissionError` without terminating `write_exec_obj`; the root
  `tcp-write-torrc` keeps running, blocked forever in `cat`, and can be re-hit via a
  stale FIFO on the next Accept. `write_exec_obj.communicate()` has no `timeout`, so the
  GUI thread can hang on a wedged privileged task.
- Fix sketch: `terminate()`/`kill()` the process on give-up, stop polling once it has
  exited, and bound `communicate(timeout=...)`.

## 3. Debug print leaks proxy credentials to stdout/journal
- `tor_control_panel.py:753-754` -- `print(self.tor_conf_info)` in `__init__`.
- `TcplTorConfInfo` is a plain dataclass; its default repr includes `proxy_username`
  and `proxy_password` in cleartext. From a desktop launch, stdout goes to the session
  log / journal. Contradicts the PR's own credential-redaction goal.
- Fix sketch: delete the debug `print`.

## 4. Custom-bridge Accept can abort the process / show an empty error
- `tor_control_panel.py:1138-1142, 1256-1293`; `tor_control_panel_lib.py` add-prefix
  (~758-774) and `tcpl_write_torrc` assert (~641-643).
- (a) Empty custom-bridge box -> `bridge_lines_maybe == []`, combo still "Custom
  bridges", falls through to `assert bridge_type in bridges_default_dict` -> unhandled
  `AssertionError` in a Qt slot -> PyQt6 aborts the process. (Same root as #5.)
- (b) A pasted line already prefixed `Bridge ` -> `tcpl_bridge_lines_add_prefix` raises
  `ValueError` (called at 1139, outside the try) -> unhandled -> abort.
- (c) A vanilla bridge (`IP:PORT FP`) or `webtunnel` passes the UI check but
  `assert bridge_type in tcpl_bridge_transport_dict` in `tcpl_write_torrc` fails; this
  one is caught, but a bare assert yields an empty message -> useless error dialog.
- Fix sketch: strip+skip blanks; tolerate an existing `Bridge ` prefix; return
  `BAD_BRIDGE_LINE` for an empty custom list and for an unsupported transport; keep the
  whole accept path inside the exception guard.

## 5. make_sane asserts on a malformed bridge line instead of returning a str
- `tor_control_panel_lib.py:395-402` -- `assert len(bridge_bit_list) > 1`.
- `tcpl_make_tor_conf_info_sane`'s documented contract is to RETURN a string for input
  it cannot fix, never raise. An empty/whitespace-only/single-token bridge line with
  bridges enabled raises `AssertionError`. This is the caller-reachable core of #4(a).
- Guarded here: `test_make_sane.test_empty_bridge_line_returns_str_not_assertionerror`
  is `@unittest.expectedFailure`; `fuzz_torrc` fuzzes make_sane over well-formed bridge
  lines only. Both flip red (XPASS / fuzz crash) once the bridge path is hardened --
  the signal to drop the xfail and widen the fuzz domain.
- Fix sketch: return an error string for a line with fewer than two tokens.

## 6. load_logs leaks the wait override cursor on error returns
- `tor_control_panel.py:1448-1522`
- `QApplication.setOverrideCursor(wait)` at the top; the Tor-log error path (`return`
  ~1490) and the journal error path (`return` ~1508) both return before the sole
  `restoreOverrideCursor()` (~1522). Each read failure leaves (and stacks) a wait cursor.
- Fix sketch: wrap the body in `try/finally: restoreOverrideCursor()`.

## 7. Stem Controller leaked (socket + reader/event threads) on failure / Tor stop
- `tor_control_panel/tor_status_watcher.py:90-91, 116-162`
- The connect-retry `except` sets `self.tor_controller = None` without `.close()`; if
  `from_socket_file()` succeeded but `authenticate()`/`get_info()`/`add_event_listener()`
  then raised, the connected controller (socket + stem reader/event threads) leaks.
  Lines 90-91 likewise drop a live controller when Tor stops. No `.close()` exists in
  the file; `try_connect_to_tor()` runs on every `/run/tor` change -> repeated leaks.
- Fix sketch: best-effort `self.tor_controller.close()` before clearing, both spots.

## 8. tmpfiles makes the FIFO directory world-writable
- `usr/lib/tmpfiles.d/tor-control-panel.conf:4-5`
- `d /run/tor-control-panel 0777 root root -` (world-writable, no sticky bit) plus
  `Z /run/tor-control-panel/* 0666 root root -` lets any local user unlink/replace
  entries, enabling the symlink/FIFO-swap attacks in #9.
- Fix sketch: `d /run/tor-control-panel 0755 root root -`; drop the `Z` line. A
  root-owned 0755 dir stops non-root creating/unlinking the FIFO (closes #9's window).

## 9. Root tcp-write-torrc has a TOCTOU on the FIFO (symlink disclosure / injection)
- `usr/libexec/tor-control-panel/tcp-write-torrc:36-56`
- Runs as root, recreates the FIFO in the world-writable dir (#8), then `cat`s it with
  no `[ -p ]` / owner / `O_NOFOLLOW` check. Between `chown` (L39) and `cat` (L43) a local
  user can swap the FIFO for a symlink to a root-only file (e.g. `/etc/shadow`, then
  written out `chmod 644` -> disclosure) or an attacker-owned FIFO (torrc injection).
- Fix sketch: fix #8, and before reading verify the path is still a FIFO owned by
  `fifo_client_uid`, reading without following a symlink.

## 10. Orphaned ACW / restart-tor-gui launchers (ImportError)
- `usr/bin/anon-connection-wizard`, `usr/bin/restart-tor-gui` and their desktop entries
  `usr/share/applications/anon_connection_wizard.desktop`, `restart-tor-gui.desktop`.
- Both scripts `import tor_control_panel.anon_connection_wizard` /
  `.restart_tor_gui` -- modules the rewrite deleted -> `ImportError` at launch. The ACW
  WIP port left them behind; restart is now an in-panel button and there is no
  wizard/argv mode. (The working panel `usr/bin/tor-control-panel` is fine.)
- Fix sketch (maintainer's call): repoint the launchers at the panel, or remove the
  orphaned scripts + desktop entries.

## 11. tor-control-panel.desktop points at a non-existent icon path
- `usr/share/applications/tor-control-panel.desktop:10`
- `Icon=/usr/share/tor-control-panel/onion.png`, but icons install under
  `.../tor-control-panel/icons/` (the dialog uses `base_icon_path = .../icons`), so the
  installed file is `.../icons/onion.png`. The desktop icon is missing.
- Fix sketch: `Icon=/usr/share/tor-control-panel/icons/onion.png`.

## CI note (not a code bug, but blocks the suite in CI)
- `tor-control-panel/.github/dm-consumer.yml` installs `python3-pyqt5`, but the rewrite
  and this suite import PyQt6. CI needs `python3-pyqt6`. Left for the maintainer (this
  work makes no `tor-control-panel` changes).
