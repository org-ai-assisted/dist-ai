# dist-ai

AI-committed regression-testing tooling for the Kicksecure / Whonix
ecosystem, for content too high-volume for human review. Only the
tooling is committed here; its large, regenerable artifacts -- baseline
corpora, fuzz inputs, generated fixtures -- are runtime data kept in the
operator's private cache (`~/private-cache`), never in the repo or package.

## Components

| Component | Status | Location |
|---|---|---|
| `mediawiki-dom-snapshot` | shipping | `usr/share/mediawiki-dom-snapshot/` |
| `sdwdate-gui-tests`      | shipping | `usr/share/sdwdate-gui-tests/` |
| `onion-grater-tests`     | shipping | `usr/share/onion-grater-tests/` |
| `privleap-tests`         | shipping | `usr/share/privleap-tests/` |
| `genmkfile-tests`        | shipping | `usr/share/genmkfile-tests/` |
| `open-link-confirmation-tests` | shipping | `usr/share/open-link-confirmation-tests/` |
| `sanitize-string-tests`  | shipping | `usr/share/sanitize-string-tests/` |
| `stcat-family-tests`     | shipping | `usr/share/stcat-family-tests/` |
| `unicode-show-tests`     | shipping | `usr/share/unicode-show-tests/` |
| `grep-find-unicode-wrapper-tests` | shipping | `usr/share/grep-find-unicode-wrapper-tests/` |
| `check-ref-commits-for-unicode-tests` | shipping | `usr/share/check-ref-commits-for-unicode-tests/` |
| `discourse-dom-snapshot` | planned  | `usr/share/discourse-dom-snapshot/` |
| `sdwdate-ci-fuzz`        | planned  | `usr/share/sdwdate-ci-fuzz/` |

Each component is independent. Each ships its own Debian binary
package via `debian/<component>.install`. The repo follows the FHS
layout used by the rest of the Kicksecure packaging tree.

## mediawiki-dom-snapshot

Drives headless Chromium via Playwright against a running MediaWiki,
captures a **complete regression-test corpus per page** (post-JS DOM,
viewport screenshot, full network manifest with body sha256s, every
asset body indexed by hash), and ships a three-axis diff (HTML text,
asset content, screenshot pixels + perceptual hash) so a refactor
can be proven not to have changed anything observably.

Use case: detect HTML/CSS/JS/image regressions introduced by
MediaWiki core or extension upgrades, or by site-CSS refactors.
Capture a baseline before the change, run again after, diff. The
pHash distance is the strongest single signal -- if it stays 0 the
rendering is visually identical despite any pixel-level
anti-aliasing jitter.

### Output layout

For each page in `pages.conf`:

```
<RAW_DIR>/<page>/
    dom.html           post-JS rendered HTML (volatile fields
                       scrubbed during normalise step)
    screenshot.png     viewport screenshot (animations disabled)
    manifest.json      URL -> { sha256, size, content_type, status }
    assets/<sha256>.<ext>
                       raw asset body, indexed by content hash so the
                       same CSS/JS/image served from multiple URLs
                       de-duplicates onto one file
```

### Usage

```
# capture + normalise against the live wiki
mediawiki-dom-snapshot

# diff a captured set against the baseline
mediawiki-dom-snapshot diff-baseline <tag>

# diff two captured sets directly
mediawiki-dom-snapshot diff <a> <b>

# promote a captured set to be the new baseline
mediawiki-dom-snapshot baseline-promote <tag>
```

Environment overrides:

| Var | Default | Meaning |
|---|---|---|
| `BASE_URL`     | `https://www.kicksecure.com` | target wiki origin |
| `PAGES_FILE`   | `/etc/mediawiki-dom-snapshot/pages.conf` | one title per line |
| `VIEWPORT`     | `1280x800` | browser viewport |
| `TIMEOUT_MS`   | `30000` | per-page timeout |
| `RAW_DIR`      | `~/private-cache/mediawiki-dom-snapshot/raw` | raw output |
| `FIX_DIR`      | `~/private-cache/mediawiki-dom-snapshot/fixtures` | normalised |
| `BASELINE_DIR` | `~/private-cache/mediawiki-dom-snapshot/baseline` | baseline corpus |

## sdwdate-gui-tests

Headless `unittest` suite for `sdwdate-gui-server`, driving the real
`SdwdateTrayIcon` and `SdwdateGuiClient` classes with unconnected local
sockets under the Qt `offscreen` platform plugin. No X server, system
tray, or live qrexec connection is required.

Unit coverage:

- the client de-duplication invariant that keeps a single Qubes VM (for
  example a DisposableVM `dispNNNN`) from being listed more than once in
  the tray menu when it reconnects before the gateway server reaps the
  previous connection
  (https://forums.whonix.org/t/sdwd-symbol-malefunction/23330). Both the
  Qubes branch (name authenticated by qrexec, so the stale older
  connection is dropped) and the non-Qubes branch (self-reported name,
  so the newcomer is kicked) are exercised, plus a unit test that the
  qrexec header parse emits `clientNameChanged`.
- tray menu activation: a left-click (`Trigger`) and a right-click
  (`Context`) each open exactly one menu, double- and middle-click do
  not, and under Wayland the handler does not self-popup.
- wire-protocol regressions: a fragmented (incomplete) message must not
  hang the parser, a newline in a status message must not get the client
  kicked, and `drop_client` is idempotent.
- tray deferral: the tray icon is not constructed until a system tray host
  is available (so Qt binds StatusNotifier, not the XEmbed fallback that
  hides the icon in the sysmaint session), the IPC listener/socket comes up
  immediately regardless of tray-host availability, and a client that
  connects before the tray exists is buffered and replayed into it.

### Fuzzer

`sdwdate-gui-tests-fuzz` is a simulator that drives the real server over
a real local socket, for both the Qubes and non-Qubes code paths, with:

- a **directed corpus** exercising every branch of the wire protocol and
  the client state machine (registration, status, Tor state, duplicate
  names, fragmentation, oversized / zero-length / non-printable / unknown
  commands, the menu action handlers, ...),
- **random and mutated** byte streams and framing, and
- **random client-lifecycle** sequences across several concurrent clients.

After every step it checks for: a hang (a `SIGALRM` watchdog catches an
infinite loop in the single-threaded event loop), a crash (an unhandled
exception in any Qt slot, captured via `sys.excepthook`), duplicate
names, failed registration / de-registration, and stuck menus. A
well-formed status message (including one with a newline) must not get
the client kicked.

With `python3-coverage` installed it reports line coverage of
`sdwdate_gui_server.py` / `sdwdate_gui_shared.py`, listing the exact
unexercised lines (the remainder being process bootstrap -- the real
listener, `main`, the signal handler -- which the harness replaces). The
RNG seed is printed; rerun a finding with `--seed`.

```
sdwdate-gui-tests-fuzz                       # both modes, default iterations
sdwdate-gui-tests-fuzz --mode qubes --iterations 2000
sdwdate-gui-tests-fuzz --seed 12345          # reproduce a specific run
```

### Integration suite

`sdwdate-gui-tests-integration` drives the same tray menu end to end on a
real display, with real click delivery:

- **X11**: a headless `Xvfb` plus a real XEmbed systray host
  (`stalonetray`); a genuine `xdotool` left- and right-click on the
  embedded icon must each open exactly one menu.
- **Wayland**: a headless `weston` plus the Qt `wayland` platform plugin;
  the handler must NOT self-popup (`QCursor.pos()` is `(0, 0)` under
  Wayland, so a popup there would land in the screen corner), leaving the
  menu to the compositor.
- **SNI late-host**: a headless `Xvfb` plus a private session bus
  (`dbus-run-session`) and a minimal `org.kde.StatusNotifierWatcher` stub
  brought up *after* the applet starts. Reproduces the startup race where
  the tray host (lxqt-panel, waybar) comes up after sdwdate-gui -- as in
  the user-sysmaint-split sysmaint session. The applet must defer
  constructing its `QSystemTrayIcon` until the watcher exists, otherwise Qt
  binds the legacy XEmbed backend and an SNI-only panel never shows the
  icon; the test asserts the icon registered via StatusNotifier.

These need extra tooling (`xvfb`, `stalonetray`, `xdotool`, `x11-utils`,
`weston`, `qtwayland5`, `dbus`, `python3-dbus`, `python3-gi`, listed in the
package's `Suggests`). Any phase whose tooling is missing is skipped loudly
rather than failed.

### Usage

```
# offscreen unit suite (depends on the sdwdate-gui package being installed)
sdwdate-gui-tests

# end-to-end integration suite (needs the Suggests tooling)
sdwdate-gui-tests-integration

# run from a git checkout against an uninstalled sdwdate-gui tree
PYTHONPATH=/path/to/sdwdate-gui/usr/lib/python3/dist-packages \
  ./usr/bin/sdwdate-gui-tests
PYTHONPATH=/path/to/sdwdate-gui/usr/lib/python3/dist-packages \
  ./usr/bin/sdwdate-gui-tests-integration
```

## onion-grater-tests

Regression and reproduction tests for the onion-grater Tor control-port
filter. The in-process unit suite imports the real onion-grater filtering
code and replays each application's control-command sequence, asserting
legitimate commands are allowed and argument-injection variants are
blocked. It reproduces the fixed Bisq `SETCONF` deanonymization and the
follow-up `DEL_ONION` / `HSFETCH` / `onion_client_auth_add` /
`AUTHCHALLENGE` hardening, old-vs-new, through the same matcher. No root,
no network, no real Tor.

A full-stack end-to-end suite spins up a throwaway offline tor plus the
real onion-grater binary plus a control client over a veth network,
proving the deanonymization vector reaches Tor on the old profile and is
blocked (510) on the new one. It also drives the `onion_authentication`
profile against real Tor: the profile's own documented
`ONION_CLIENT_AUTH_ADD` is allowed by the filter and accepted by Tor (the
client-auth credential is actually registered), while malformed / injection
variants (wrong key-arg order, wrong key algorithm, missing key, a trailing
extra keyword) are blocked with 510 and never reach Tor. It needs `tor` and
sudo (only the privileged setup is sudo'd, and it is cleaned up). Also shipped
are a
real-application driver (`bitcoind_drive.py`) and adversarial probes
(`probe_bypass.py`, `probe_rewrite.py`, `verify_dos.py`).

The tests target the installed onion-grater by default; set
`ONION_GRATER_REPO` to run them against a derivative-maker checkout.

### Usage

```
# in-process unit / reproduction suite
onion-grater-tests

# full-stack end-to-end (needs tor + sudo)
onion-grater-tests-e2e
```

## genmkfile-tests

Regression tests for the `genmkfile` build-helper's target dispatch.
`genmkfile`'s main dispatch splits build-machine setup into a cheap
"dependencies only" path (`make_get_dependencies`) and the full "version
info" path (`make_get_variables`). Only `deb-build-dep` / `deb-run-dep` /
`deb-all-dep` may take the cheap path; any target that touches a variable
set by `make_get_variables` (the upstream/debian tarball paths, the
`.dsc` / `.changes` names, `make_package_list`) must take the full path.

Two commits once mis-classified `deb-cleanup`, `reprepro-remove` and
`reprepro-add` into the cheap group, aborting them with e.g.
`make_upstream_tarball_relative_path: unbound variable` (and the
equivalent `make_main_changes_file` / `make_package_list` failures for the
reprepro targets). The suite drives the real `genmkfile` against a
throwaway minimal Debian source package and asserts each of the three
targets is routed through `make_get_variables` and never trips an "unbound
variable" error. No root, no network, no real reprepro (a stub wrapper
stands in). Validated non-vacuous against the pre-fix tree.

A second test (`git_describe_control_test.sh`) covers the
`make_use_git_describe_for_version` path. That flag is meant for special
repos with no `debian/control` (Whonix-Installer, qubes-template-*), where
`make_get_variables` short-circuits before setting the tarball / `.dsc`
paths. `live-build` sets the same flag but **does** ship `debian/control`
and is built as a `.deb`, so the short-circuit left
`make_upstream_tarball_relative_path` unset and `deb-cleanup` aborted. The
fix gates the short-circuit on the actual absence of `debian/control`; the
test asserts that a flag+`control` fixture routes `deb-cleanup` through
`make_get_variables` without an unbound-variable error **and** that
`git-tag-show` still reports the git-describe tag (`commit_<sha>`), not the
changelog version. Also non-vacuous against the pre-fix tree.

The suite targets `genmkfile` from `PATH` by default; set `GENMKFILE_BIN`
to test a specific `genmkfile`, or it falls back to a derivative-maker
checkout under `~/derivative-maker`.

### Usage

```
# dispatch regression suite
genmkfile-tests

# test a specific genmkfile binary
GENMKFILE_BIN=/path/to/genmkfile genmkfile-tests
```

## open-link-confirmation-tests

Security and unit tests for the Kicksecure
[open-link-confirmation](https://github.com/Kicksecure/open-link-confirmation)
link/file confirmation dialog (the `$BROWSER` / `x-www-browser` handler). The
untrusted input is the URL/file argument; it is shown by piping it through
helper-scripts' `sanitize-string` and rendering the result as HTML in a PyQt5
`QTextBrowser`.

The `open-link-confirmation-tests` command checks the whole display pipeline,
no root / no network / no real browser (Qt runs offscreen):

- a sanitization contract over a hostile battery (Unicode, RTL override,
  zero-width, ANSI/SGR, OSC-8, control bytes, oversized inputs, markup),
- a Qt rich-text differential that parses the sanitized output with the real Qt
  engine and asserts no clickable anchor or image is introduced,
- a static audit that the script only ever displays the sanitized argument, and
- a bash unit test of `source_config()`'s env-over-config precedence.

The Qt group encodes a known, currently-unfixed markup-injection bypass (a `<`
followed by whitespace then a tag name survives `sanitize-string` but Qt
reconstructs the tag) as strict-xfail cases; see
`usr/share/open-link-confirmation-tests/README.md`.

### Usage

```
open-link-confirmation-tests

# test a checkout instead of the installed copies
OPEN_LINK_CONFIRMATION_BIN=/path/to/open-link-confirmation \
SANITIZE_STRING_BIN=/path/to/sanitize-string \
./usr/bin/open-link-confirmation-tests
```

## sanitize-string-tests

Deep test + fuzz for the helper-scripts sanitize family (`stdisplay` ->
`strip_markup` -> `sanitize-string`) as consumed by msgcollector's PyQt5
`QTextBrowser` dialogs. `sanitize-string` output must be safe to display both
on a terminal and as HTML/Qt rich text. The suite proves it, with no bypasses:

- `[T]` terminal safety (ASCII only, no control/ESC except newline/tab, length
  cap), `[H]` no `<` survives, `[Q]` a cross-parser differential against the
  real Qt engine (no anchor/image revived), `[F]` content fidelity (benign
  inputs incl. `&`-query URLs round-trip, not silently dropped), `[L]` the
  length cap is exact.
- It encodes a parser-differential markup-injection bypass and the dropped-`&`
  content bug as strict-xfail cases that flip once the fixed `sanitize-string`
  is installed. Ships `qtextbrowser_repro.py` (minimal headless repro) and
  `popup_repro.sh` (live PoC via `sanitize-string` + `generic_gui_message`).

### Usage

```
sanitize-string-tests
sanitize-string-tests-fuzz                  # heavy fuzz sweep
SANITIZE_STRING_BIN=/path/to/sanitize-string sanitize-string-tests
```

## stcat-family-tests

Comprehensive test + fuzz for the **stcat family** -- the helper-scripts
`stdisplay`-package CLI tools that make untrusted text safe to print to a
terminal: `stcat`, `stcatn`, `stecho`, `stprint`, `stsponge`, `sttee`. Each
routes input through `stdisplay()` and forces ASCII output. The suite proves,
across all six tools, that nothing dangerous reaches the terminal:

- `[U]` no-colour: output is pure printable ASCII + newline/tab (no Unicode,
  control, ESC, DEL) over a hostile corpus and a byte-level fuzzer.
- `[C]` colour: Unicode is still stripped and only well-formed SGR colour
  escapes survive; OSC-8 and CSI cursor/clear are neutralised.
- `[S]` semantics: each tool still performs its function (including file
  paths, whose written content is verified sanitised).
- `[F]` fuzz: random byte streams (Unicode, control, escapes, malformed UTF-8,
  NUL) never break the no-colour invariant.

### Usage

```
stcat-family-tests
stcat-family-tests-fuzz                     # heavy fuzz sweep
STDISPLAY_REPO=/path/to/helper-scripts stcat-family-tests
```

## unicode-show-tests

Comprehensive test + fuzz for **unicode-show** -- the helper-scripts
`unicode_show`-package scanner that **detects** suspicious Unicode. It is the
mirror image of the `stcat` family: `stcat` sanitizes untrusted text for a
terminal, `unicode-show` reports the dangerous characters instead (exit `0`
clean, `1` suspicious found, `2` error). The suite proves the whole contract end
to end against the real CLI:

- `[D]` detection: over a hostile corpus (bidi Trojan-Source set, zero-width,
  BOM, homoglyph, combining, C1, line/paragraph separators, CJK, emoji, C0 /
  NUL / DEL) the tool exits `1` and names the exact codepoint (e.g. `U+202E`).
- `[S]` self-safety: unicode-show's own stdout never leaks the raw suspicious
  bytes it reports -- pure printable ASCII + newline/tab over the corpus and the
  fuzzer (it relies on `ascii()`; a regression to `repr()` is caught here).
- `[B]` benign: clean ASCII exits `0` with no output (so `[D]` is non-vacuous).
- `[N]` newline / whitespace: trailing whitespace flagged; missing final newline
  flagged by default and suppressed by `UNICODE_SHOW_ALLOW_MISSING_FINAL_NEWLINE=1`;
  empty input clean.
- `[E]` fail-closed: invalid UTF-8 (stdin or file) exits `2` without slipping a
  byte to stdout; a nonexistent path exits `2`.
- `[P]` paths: hostile file content is detected, and a hostile filename is
  sanitised in the output.
- `[F]` fuzz: random byte streams and random valid Unicode never crash, hang, or
  break the `[S]` invariant.

### Usage

```
unicode-show-tests
unicode-show-tests-fuzz                     # heavy fuzz sweep
UNICODE_SHOW_REPO=/path/to/helper-scripts unicode-show-tests
```

## grep-find-unicode-wrapper-tests

Comprehensive test + fuzz for **grep-find-unicode-wrapper** -- the helper-scripts
bash wrapper around `grep` that scans **files** for suspicious content and lists
the offending files (grep-like: exit `0` match, `1` no match, fails loud on a
grep error). Matches are printed via `stecho`, so a Unicode filename cannot
smuggle anything to the terminal. A file matches iff it holds any byte that is
not printable ASCII or tab/newline -- the union of non-ASCII, the bidi
Trojan-Source set, and the C0-control/DEL/NUL grep.

- `[D]`/`[C]` detection: a hostile corpus is flagged, with a dedicated check that
  a pure-ASCII control byte (which the non-ASCII greps miss) is still caught.
- `[B]` benign: clean ASCII is not flagged -- including trailing whitespace,
  which this tool (unlike `unicode-show`) does not treat as suspicious.
- `[M]` multi-file: only dirty files are listed, sorted `-u`.
- `[P]` self-safety: a hostile filename is sanitised in the output (pure ASCII).
- `[E]` errors: a nonexistent path fails loud, not a silent no-match.
- `[K]` known limitation: the tool's documented broken stdin handling (only the
  first grep consumes the pipe, so a control-only stdin input is a false
  negative) is pinned and flips to a failure if stdin is ever fixed.
- `[F]` fuzz: random byte files are checked against an independent byte-level
  oracle -- exit code must agree exactly and output must stay pure ASCII.

### Usage

```
grep-find-unicode-wrapper-tests
grep-find-unicode-wrapper-tests-fuzz        # heavy fuzz sweep
GREP_FIND_UNICODE_WRAPPER_REPO=/path/to/helper-scripts grep-find-unicode-wrapper-tests
```

## check-ref-commits-for-unicode-tests

Comprehensive test + fuzz for **check-ref-commits-for-unicode** -- the
helper-scripts git-ref guard that scans every commit a ref introduces
(`git log HEAD..<ref>`) for suspicious Unicode. For each new commit it pipes
`git show` (with `--unified=0 --no-ext-diff --no-textconv` and a `--format` that
includes the identity fields) through `unicode-show`, so it scans the **diff**,
the commit **message**, and the **author / committer name and email**. The suite
builds throwaway git repos and drives the real tool:

- `[D]` detection by location: a hostile codepoint in content, message, author
  name/email, or committer name/email each makes it exit `1` and name the commit.
- `[S]` self-safety: while reporting a hostile commit, its output stays pure
  ASCII (findings render as `[U+XXXX]`).
- `[B]` benign: a clean ref (incl. blank lines and a clean merge) exits `0`.
- `[M]` multi-commit: the dirty commit is flagged by sha, clean ones logged clean.
- `[E]` errors: no ref / nonexistent ref / no new commits / not a work tree each
  exit `1` with their own message (exit `1` is overloaded; distinguished by text).
- `[F]` fuzz: random clean-or-suspicious commits vs an independent oracle -- exit
  `1` iff something suspicious was injected, and output stays pure ASCII.

### Usage

```
check-ref-commits-for-unicode-tests
check-ref-commits-for-unicode-tests-fuzz    # heavy fuzz sweep
CHECK_REF_COMMITS_REPO=/path/to/helper-scripts check-ref-commits-for-unicode-tests
```
