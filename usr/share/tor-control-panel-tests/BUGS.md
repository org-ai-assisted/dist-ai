# tor-control-panel / anon-connection-wizard -- bug & issue inventory

Source material:
- Whonix forum thread "Tor controller GUI (tor-control-panel)", 164 posts,
  2018-07-08 .. 2026-07-07:
  https://forums.whonix.org/t/tor-controller-gui-tor-control-panel/5444
- arraybolt3's (Aaron Rainbolt) review fork, `github.com/ArrayBolt3/merged-tcp-review`
  (inline `## TODO:` review notes over the merged TCP+ACW code).
- arraybolt3's final test pass + bug list: thread post #161. The manual GUI
  walkthrough from that post is encoded as skipped tests in
  `test_manual_plan.py`; the automatable checks are the real tests here.

Authoritative reporters: **troubadour** (original TCP author), **Patrick =
adrelanos** (lead Kicksecure/Whonix dev), **arraybolt3**. Other reporters (iry,
nurmagoz, HulaHoop, nyxnor, ...) are weighted cautiously and flagged where used.

Package layout note: anon-connection-wizard (ACW) is now MERGED into the
tor-control-panel package. Both live under
`usr/lib/python3/dist-packages/tor_control_panel/`. Line numbers below are for
the current official Kicksecure source (`Kicksecure/tor-control-panel`),
verified in-tree -- NOT the review fork (whose line numbers differ).

Legend: [BUG] wrong behaviour/crash/data-loss ; [ROBUST] missing guard/encoding
; [CONTENT] wrong text ; each tagged with a reporter and whether a regression
test exists in this suite.

---

## A. Confirmed genuine bugs -- targeted for surgical fixes

### A1 [BUG] Custom bridges silently replaced by default obfs4 bridges  (data loss)
- Reporter: arraybolt3 (post #161 bug 2); also a 2021 Qubes report (Bridges type: none).
- File: `torrc_gen.py`. `gen_torrc()` writes the marker `# Custom bridges are used`
  (line ~75) but `parse_torrc()` tests for the MISSPELLED `# Custom briges are used`
  (line 123, missing the 'd'). So `use_custom_bridges` is ALWAYS False on re-parse.
- Effect: after custom bridges are configured, `parse_torrc()` reports the bridge
  type as the transport of the first `Bridge` line (e.g. `obfs4`) instead of
  `Custom bridges`. On any later reconfigure (e.g. adding a proxy), the Configure
  flow (`tor_control_panel.py` ~583) treats it as DEFAULT bridges
  (`use_custom_bridges=False`), and `set_torrc()` regenerates the DEFAULT obfs4
  bridge lines -- discarding the user's custom bridges.
- Note: the custom-bridge *retrieval* path (`tor_control_panel.py` ~595) uses a
  lenient `'# Custom'` substring match, so ONLY `parse_torrc` is broken.
- Fix: correct the typo `briges` -> `bridges`.
- Test: `test_torrc_gen.py` (parse detects custom bridges; gen->parse round-trip).

### A2 [BUG] anon-connection-wizard crashes (core dump) when closed with Cancel
- Reporter: arraybolt3 (post #161 bug 4).
- File: `anon_connection_wizard.py`. `__init__` sets `self.bootstrap_done` (line
  ~668) but never initialises `self.bootstrap_thread`; that attribute is only
  assigned inside the connect path (~829). `cancel_button_clicked()` (line 912)
  reads `if self.bootstrap_thread:` -> `AttributeError` -> `IOT/core dump` if
  Cancel is pressed before connecting. (`back_button_clicked()` already guards
  this with try/except; cancel does not.)
- Fix: initialise `self.bootstrap_thread = None` in `__init__`.
- Test: `test_anon_connection_wizard.py`.

### A3 [BUG] Two "Disable network" entries in the Bridges-type selector
- Reporter: arraybolt3 (post #161 bug 1); troubadour (post #164) confirms.
- File: `tor_control_panel.py`. `refresh()` toggles the trailing combo entry with a
  hard-coded index: `removeItem(8)` + `addItem('Disable network'/'Enable network')`
  (lines ~774/781/788). The index-8 assumption is fragile; across a
  Restart->Configure sequence the removeItem does not hit the previously-added
  toggle entry, so a second one is appended.
- Fix: remove any existing 'Disable network'/'Enable network' entry by text
  (findText) before adding the correct one. Minimal diff, no restructure.
- Test: `test_tor_control_panel.py`.

### A4 [BUG] Custom bridge lines mangled by char-set strip
- Reporter: arraybolt3 (review note, ACW/TCP).
- File: `tor_control_panel.py:601`: `line = line.strip('Bridge' '\n')`. This strips
  the CHARACTER SET {B,r,i,d,g,e,\n} from both ends, not the `Bridge` prefix, so
  bridge lines beginning/ending with any of those chars are corrupted when the
  saved custom bridges are re-displayed.
- Fix: proper prefix removal, e.g. `line = line[len('Bridge'):].strip()`.
- Test: covered by the custom-bridge retrieval integration test where feasible;
  otherwise manual (test plan).

### A5 [BUG] cookie-authentication-failed dialog never shown; sys.exit never runs
- Reporter: arraybolt3 (review note).
- File: `anon_connection_wizard.py:762-768`. The `cookie_authentication_failed`
  branch builds `QMessageBox(...)` but never calls `.exec_()`, then compares the
  QMessageBox INSTANCE to `QMessageBox.Ok` (an enum) -- always False. So no dialog
  appears and `sys.exit(1)` never runs. (The sibling `no_controller` branch at
  ~757 correctly uses the `QMessageBox.warning(...)` static method.)
- Fix: mirror the `no_controller` branch -- use `QMessageBox.warning(self, title,
  text)` and keep the `== QMessageBox.Ok` check.
- Test: manual (GUI dialog); logic-parity asserted by inspection.

### A6 [BUG] Log-view redaction uses a data substring as a regex
- Reporter: arraybolt3 (review note).
- File: `tor_control_panel.py:709`: `line = re.sub(line[12:19], '...', line)`. The
  7-char slice of the (untrusted) Tor log line is used as a REGEX pattern: regex
  metacharacters raise `re.error`, and a short line makes `line[12:19]` empty,
  which `re.sub('')` uses to insert `...` between every character.
- Fix: positional replacement of the slice: `line = line[:12] + '...' + line[19:]`
  (preserves the intent -- blank out that column range -- with no regex).
- Test: manual/inspection (inline in refresh_logs).

### A7 [BUG/ROBUST] Proxy silently dropped when proxy password is the 'None' sentinel
- Reporter: arraybolt3 (review note).
- File: `anon_connection_wizard.py:886-887`. In `write_torrc()` the password branch
  has no `else`, unlike the username branch. When `Common.proxy_password == 'None'`
  only 6 args are built; `gen_torrc()` requires `len(args) >= 7` to emit proxy
  lines (`torrc_gen.py:90`), so the proxy is silently omitted from the torrc.
- Fix: add the symmetric `else: args.append('')`.
- Test: `test_torrc_gen.py` asserts gen_torrc emits a proxy line for a full
  7-arg proxy request (feature coverage); ACW arg-building covered by inspection.

## B. Robustness / hardening items -- ALL FIXED

- [FIXED] Custom meek (`meek_lite`) and mixed/vanilla-first custom bridges lost
  their `ClientTransportPlugin` line; `gen_torrc` now emits the right plugin per
  transport present (obfs4/snowflake/meek_lite), de-duplicated. Flagged by
  Codex + CodeRabbit + a fresh-eyes review.
- [FIXED] Unguarded `bootstrap_thread.terminate()` sites in `tor_control_panel.py`
  now route through a guarded `stop_bootstrap_thread()` helper (same class as A2).
- [FIXED] `torrc_gen.gen_torrc` no longer raises when a custom bridge's first
  token is not a known transport (vanilla IP:port bridge).
- [FIXED] `tor_bootstrap.py` regex parse guards a non-matching bootstrap-phase
  line (no `.group()` on `None`).
- [FIXED] `edit_etc_resolv_conf.py` catches `Exception`, not `BaseException`.
- [FIXED] QLabel-vs-string comparisons in `refresh_user_configuration`
  (`self.bridge_type.text()` / `self.proxy_type.text()`).
- [FIXED, arraybolt3 post #161 TODO] `TorBootstrap` QThreads are kept in a
  module-level set while running (removed on `finished`), so a still-running
  thread cannot be garbage-collected (QObject use-after-free).
- [FIXED, arraybolt3 post #161 TODO] Untrusted input from Tor / the systemd
  journal / the tor log / torrc is routed through helper-scripts
  `sanitize_string` before display (strips control chars, escapes, markup), so
  a hostile log line cannot inject into the QTextBrowser log view.
- [FIXED] `tor_status.tor_enabled_check` matches the `DisableNetwork` directive
  on a non-comment line (first token) instead of any substring.

## C. Notable NON-bugs / already fixed upstream (do NOT re-fix)

- `info.no_controller()` in current source RETURNS a proper string (info.py:150);
  the review note ("returns None / pops a window") applied to the review fork only.
- Yahoo bridge-request email provider: already removed from current source.
- `tor_status.py` / `torrc_gen.py` file reads: most now specify
  `encoding="utf-8"` upstream; several of the review's encoding/dangling-handle
  notes are already addressed. (A few `open()` calls in `tor_status.py` still lack
  an explicit encoding -- cosmetic.)
- Historical (all fixed): New Identity crash when Tor stopped; missing
  `import json` crash on bridge selection; MIME double-hash bug; multiple
  `/var/run/tor`/masked-Tor `FileNotFoundError` crashes; `is`-vs-`==`
  SyntaxWarning (`tor_bootstrap.py`); "Disable network" not setting
  `DisableNetwork 1`; QGridLayout+QSizePolicy misuse; "New Identity" reworked into
  "Request new Tor circuit".

## D. Genuinely open -- need a running GUI / live Tor, or belong upstream

These cannot be fixed reliably from static analysis (no way to reproduce or
verify the fix headlessly), or are a separate upstream workstream:

- ACW layout drift: unchecking "I need bridges..." after a Custom-bridges
  round-trip leaves the checkbox mid-window (post #161 bug 3). Purely visual; a
  QGridLayout stretch issue that needs the real GUI to see and confirm a fix --
  guessing blind risks making the layout worse.
- "Enable network" without closing TCP hangs / vanishes the window (troubadour,
  post #164). Needs a live Tor daemon to reproduce; troubadour is actively
  rewriting `tor_status.py` around this.
- Plain-Debian / non-Whonix support (no `/etc/torrc.d/*.conf`, TBB's bundled Tor
  making TCP's tor commands no-ops) -- troubadour's ongoing goal.
- "Unknown Bootstrap TAG" shown when connecting via a proxy (post #161, minor).
  The fallback is deliberate and safe (a static, sanitized message); the exact
  proxy-path tag to add to `tag_phase` is unknown without reproduction.

## E. Non-bug clarified

- `finish_button_clicked()` (`anon_connection_wizard.py`) is only connected to
  the Finish button's `clicked` signal, whose slot return value Qt ignores, so
  the `return True` (and its "still returns True on cancel" TODO) is a no-op, not
  a bug. Left as-is; removing it would only churn the `.connect`.
