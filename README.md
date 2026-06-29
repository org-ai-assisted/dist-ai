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
