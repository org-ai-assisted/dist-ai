# dist-ai

AI-committed regression-testing tooling for the Kicksecure / Whonix
ecosystem. Designed for content that is too high-volume for human
review: large baseline corpora, fuzz-test inputs, generated fixtures.

## Components

| Component | Status | Location |
|---|---|---|
| `mediawiki-dom-snapshot` | shipping | `usr/share/mediawiki-dom-snapshot/` |
| `sdwdate-gui-tests`      | shipping | `usr/share/sdwdate-gui-tests/` |
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

# diff a captured set against the shipped baseline
mediawiki-dom-snapshot diff-baseline <tag>

# diff two captured sets directly
mediawiki-dom-snapshot diff <a> <b>

# promote a captured set to be the new shipped baseline
mediawiki-dom-snapshot baseline-promote <tag>
```

Environment overrides:

| Var | Default | Meaning |
|---|---|---|
| `BASE_URL`     | `https://www.kicksecure.com` | target wiki origin |
| `PAGES_FILE`   | `/etc/mediawiki-dom-snapshot/pages.conf` | one title per line |
| `VIEWPORT`     | `1280x800` | browser viewport |
| `TIMEOUT_MS`   | `30000` | per-page timeout |
| `RAW_DIR`      | `/var/lib/mediawiki-dom-snapshot/raw` | raw output |
| `FIX_DIR`      | `/var/lib/mediawiki-dom-snapshot/fixtures` | normalised |

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

These need extra tooling (`xvfb`, `stalonetray`, `xdotool`, `x11-utils`,
`weston`, `qtwayland5`, listed in the package's `Suggests`). Any phase
whose tooling is missing is skipped loudly rather than failed.

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
