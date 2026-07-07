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

## B. Robustness items (lower priority; fix if surgical)

- [ROBUST] `tor_control_panel.py` ~470/477/802/816/824 call
  `self.bootstrap_thread.terminate()` while only line ~460 guards with
  `hasattr`; same uninitialised-attribute class as A2.
- [ROBUST] `torrc_gen.py` `gen_torrc` custom-bridge path: `bridges_type.index(bridge)`
  raises ValueError if the first token of a custom bridge line is not a known
  transport name.
- [ROBUST] `tor_bootstrap.py` regex `.group(1)` on an unguarded `re.match`.
- [ROBUST] `edit_etc_resolv_conf.py` `except BaseException` too broad.
- [TODO, arraybolt3 post #161] Sanitize untrusted input read from Tor / the
  systemd journal (helper-scripts `sanitize_string`); prevent `TorBootstrap`
  QThreads being garbage-collected while running (QObject use-after-free).

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

## D. Open issues tracked upstream (not addressed here)

- ACW layout drift: unchecking "I need bridges..." after a Custom-bridges
  round-trip leaves the checkbox mid-window (post #161 bug 3). Visual; deferred.
- "Enable network" without closing TCP hangs / vanishes the window (troubadour,
  post #164, under investigation upstream; `tor_status.py` being rewritten).
- Plain-Debian / non-Whonix support (no `/etc/torrc.d/*.conf`, TBB's bundled Tor
  making TCP's tor commands no-ops) -- troubadour's ongoing goal.
- "Unknown Bootstrap TAG" shown when connecting via a proxy (post #161, minor).
- `finish_button_clicked()` always returns True even on cancel
  (`anon_connection_wizard.py:922`, pre-existing TODO; QWizard semantics -- left
  as-is to avoid a non-surgical change).
