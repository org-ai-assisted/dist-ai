# dist-ai

AI test, reproduction, and fuzzing tooling for the Kicksecure and Whonix
ecosystem, committed with AI assistance. This is the AI's own sandbox
tooling: it runs only on disposable, untrusted CI, never ships to users,
and never enters Kicksecure or Whonix.

For how AI-assisted contributions are handled, and why this code is trusted
less than human-written code, see the org pages:
[org-ai-assisted.github.io](https://org-ai-assisted.github.io) (organisation:
[github.com/org-ai-assisted](https://github.com/org-ai-assisted)).

Only the tooling is committed here; its large, regenerable artifacts (baseline
corpora, fuzz inputs, generated fixtures) are runtime data kept in the
operator's private cache (`~/private-cache`), never in the repo or package.

## Components

| Component | Status | Location |
|---|---|---|
| `domsnap-engine` | shipping | `usr/share/domsnap-engine/` (driven by `dist_ai.webcheck.domsnap`) |
| `sdwdate-gui-tests`      | shipping | `usr/share/sdwdate-gui-tests/` |
| `sdwdate-tests`          | shipping | `usr/share/sdwdate-tests/` |
| `sdwdate-onion-tester-tests` | shipping | `usr/share/sdwdate-onion-tester-tests/` |
| `onion-time-pre-script-tests` | shipping | `usr/share/onion-time-pre-script-tests/` |
| `onion-grater-tests`     | shipping | `usr/share/onion-grater-tests/` |
| `kloak-tests`            | shipping | `usr/share/kloak-tests/` (CBMC proofs) |
| `privleap-tests`         | shipping | `usr/share/privleap-tests/` |
| `pyte-tests`             | shipping | `usr/share/pyte-tests/` |
| `dist-installer-cli-tests` | shipping | `usr/share/dist-installer-cli-tests/` |
| `genmkfile-tests`        | shipping | `usr/share/genmkfile-tests/` |
| `dm-help-steps-tests`    | shipping | `usr/share/dm-help-steps-tests/` |
| `open-link-confirmation-tests` | shipping | `usr/share/open-link-confirmation-tests/` |
| `sanitize-string-tests`  | shipping | `usr/share/sanitize-string-tests/` |
| `serial-console-enable-tests` | shipping | `usr/share/serial-console-enable-tests/` |
| `stcat-family-tests`     | shipping | `usr/share/stcat-family-tests/` |
| `stdisplay-tests`        | shipping | `usr/share/stdisplay-tests/` |
| `systemcheck-tests`      | shipping | `usr/share/systemcheck-tests/` |
| `systemcheck-tests-bwrap` | shipping | `usr/share/systemcheck-tests-bwrap/` |
| `tor-control-panel-tests` | shipping | `usr/share/tor-control-panel-tests/` |
| `tb-updater-tests`       | shipping | `usr/share/tb-updater-tests/` |
| `terminal-poc-corpus-tests` | shipping | `usr/bin/terminal-poc-corpus-tests` |
| `terminal-resilience-tests` | shipping | `usr/share/terminal-resilience-tests/` |
| `unicode-show-tests`     | shipping | `usr/share/unicode-show-tests/` |
| `grep-find-unicode-wrapper-tests` | shipping | `usr/share/grep-find-unicode-wrapper-tests/` |
| `setup-wizard-dist-tests` | shipping | `usr/share/setup-wizard-dist-tests/` |
| `iso-boot-tests` (fuzz)  | shipping | `usr/share/iso-boot-tests/` |
| `dm-smbios-reader-boot-tests`    | shipping | `usr/share/dm-smbios-reader-boot-tests/` |
| `vbox-ctl-local`         | shipping | `usr/share/dm-smbios-reader-boot-tests/vbox-ctl-local` |
| `image-test` (VBox fleet runner) | shipping | `usr/bin/image-test-*`, `usr/lib/systemd/system/image-test@.service` |
| `dm-whonix-pair`         | shipping | `usr/bin/dm-whonix-pair` (+ `usr/share/dm-whonix-pair-tests/`) |
| `dm-upgrade-regression`  | shipping | `usr/bin/dm-upgrade-regression` (+ `usr/share/dm-upgrade-regression-tests/`) |
| `dm-shared-apt-repo`     | shipping | `usr/bin/dm-shared-apt-repo` |
| `iso-download`           | shipping | `usr/bin/iso-download` (+ `usr/share/iso-download-tests/`) |
| `dm-reproducible-build-tests` | shipping | `usr/share/dm-reproducible-build-tests/` |
| `check-ref-commits-for-unicode-tests` | shipping | `usr/share/check-ref-commits-for-unicode-tests/` |
| `developer-meta-files-tests` | shipping | `usr/share/developer-meta-files-tests/` |
| `github-org-tools-tests` | shipping | `usr/share/github-org-tools-tests/` |
| `dm-reprepro-tracking-tests` | shipping | `usr/share/dm-reprepro-tracking-tests/` |
| `dm-virtualbox-wiki-links-tests` | shipping | `usr/share/dm-virtualbox-wiki-links-tests/` |
| `git-meld-tests`         | shipping | `usr/share/git-meld-tests/` |
| `lockfile-tests`         | shipping | `usr/share/lockfile-tests/` |
| `mediawiki-shell-tests`  | shipping | `usr/share/mediawiki-shell-tests/` |
| `msgcollector-tests`     | shipping | `usr/share/msgcollector-tests/` |
| `secure-terminal-tests`  | shipping | `usr/share/secure-terminal-tests/` |
| `web-analyzer-tests`     | shipping | `usr/share/web-analyzer-tests/` |
| `website-tests`          | shipping | `usr/share/website-tests/` |
| `private-ai-config-tests`   | shipping | `usr/share/private-ai-config-tests/` |
| `discourse-dom-snapshot` | planned  | `usr/share/discourse-dom-snapshot/` |
| `sdwdate-tests-fuzz`     | shipping | `usr/share/sdwdate-tests/` |

Each component is independent. All of them ship in the single `dist-ai` Debian
binary package, whose `debian/dist-ai.install` takes `usr/*` wholesale, so a
new suite needs no packaging change. The repo follows the FHS layout used by
the rest of the Kicksecure packaging tree.

## ci/ scripts

`ci/` holds shell logic invoked by CI, never inline in workflow yaml. Two kinds
live here:

- **Reusable-invoked** (`dist-ai-tests-ci-config.sh`,
  `dist-ai-tests-ci-hs-runtime.sh`) -- called by
  developer-meta-files' `reusable-dist-ai-tests.yml`.
Component-invoked CI tools live in `usr/bin/` with the rest of the executables,
not here -- `debian/dist-ai.install` ships `usr/*`, so they are packaged, whereas
`ci/` is not. `usr/bin/onion-tester-*` are called by sdwdate's own `local-*`
workflow, which checks this repo out (`path: .github/dist-ai`) and runs them by
path; they stay CWD-relative, so they operate on the component checkout while
living here.

One consequence worth knowing: a component's `paths:` filter cannot see files in
this repo, so a change here does not trigger that component's workflow. The
regression suite for those tools (`sdwdate-onion-tester-tests`) is mapped to the
component so it still gates that component's PRs.

## dist-ai-tests-all

There is no single "run everything" target beyond this. `dist-ai-tests-all`
(`usr/bin/dist-ai-tests-all`) runs the suites in one pass, aggregates the
per-suite result (PASS / FAIL / SKIP / TIMEOUT), and exits non-zero if any
failed. Category flags select what runs -- `--core` (default), `--fuzz`,
`--e2e`, `--integration`, or `--all`.

Pass `--repo-root <derivative-maker>` to point every suite at an in-tree
checkout (it wires each suite's `*_REPO` / `*_BIN` / `PYTHONPATH` / positional
argument automatically) instead of the installed package; a suite whose target
is absent exits 77 and is reported SKIP. The dom-snapshot engine (`domsnap`) is a
capture tool, not a pass/fail suite, so it is not registered here; its browser-free
unit regressions run under `website-tests`.

```
# core suites against an in-tree checkout
dist-ai-tests-all --core --repo-root ~/derivative-maker

# everything (fuzz is long; e2e needs tor + sudo; integration needs a GUI stack)
dist-ai-tests-all --all --repo-root ~/derivative-maker
```

## domsnap (dom-snapshot)

`dist_ai.webcheck.domsnap` is the single front door for DOM / visual-regression
snapshots. Its **wiki lane** drives headless Chromium via Playwright against a
running MediaWiki (engine in `usr/share/domsnap-engine/{snapshot,normalize,diff}.py`),
capturing a **complete regression-test corpus per page** (post-JS DOM, viewport
screenshot, full network manifest with body sha256s, every asset body indexed by
hash), and ships a three-axis diff (HTML text, asset content, screenshot pixels +
perceptual hash) so a refactor can be proven not to have changed anything observably.
(Its **static lane** -- `capture`/`diff-baseline`/`promote`, run via
`webcheck-domsnap-sandbox` -- does the same for the hand-written family Pages trees.)

Use case: detect HTML/CSS/JS/image regressions introduced by
MediaWiki core or extension upgrades, or by site-CSS refactors.
Capture a baseline before the change, run again after, diff. The
pHash distance is the strongest single signal -- if it stays 0 the
rendering is visually identical despite any pixel-level
anti-aliasing jitter.

### Output layout

For each page in `wiki-pages.conf` (under the run tag):

```
<RAW_DIR>/<tag>/<page>/
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

Run under the Playwright venv (see the `mediawiki-dom-diff` skill for venv wiring):

```
# capture + normalise against the live wiki into a run tag
python3 -m dist_ai.webcheck.domsnap wiki-run <tag>

# diff a captured set against the baseline
python3 -m dist_ai.webcheck.domsnap wiki-diff-baseline <tag>

# diff two captured sets directly
python3 -m dist_ai.webcheck.domsnap wiki-diff <a> <b>

# promote a captured set to be the new baseline
python3 -m dist_ai.webcheck.domsnap wiki-promote <tag>
```

Environment overrides:

| Var | Default | Meaning |
|---|---|---|
| `BASE_URL`     | `https://www.kicksecure.com` | target wiki origin |
| `PAGES_FILE`   | `/usr/share/domsnap-engine/wiki-pages.conf` | one title per line |
| `TIMEOUT_MS`   | `30000` | per-page timeout |
| `RAW_DIR`      | `~/private-cache/domsnap-wiki/raw` | raw output |
| `FIX_DIR`      | `~/private-cache/domsnap-wiki/fixtures` | normalised |
| `BASELINE_DIR` | `~/private-cache/domsnap-wiki/baseline` | baseline corpus |

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
`weston`, `qtwayland5`, `dbus`, `python3-dbus`, `python3-gi`), pulled in as
package dependencies. Any phase whose tooling is missing is skipped loudly
rather than failed.

### Usage

```
# offscreen unit suite (depends on the sdwdate-gui package being installed)
sdwdate-gui-tests

# end-to-end integration suite (needs the GUI tooling above)
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

## dm-help-steps-tests

Functional tests for the helper scripts under derivative-maker
`help-steps/`, currently the `/proc`-based process reaper
`mount-cleanup`. Victims covering every detection channel (cwd, open fd,
mmap-only, exe image, chrooted process, SIGTERM-ignoring) must die;
bystanders (unrelated processes, a sibling tree whose name is a
string-prefix collision of the target) must survive; the guards
(nonexistent path, `/`, skip-list basenames) are asserted. Requires root
(SKIPs otherwise) -- run inside a throwaway container or a sandbox VM,
e.g. `sandbox-run --dir <staged-dir> -- sudo bash ./mount_cleanup_test.sh`
with a copy of `mount-cleanup` staged next to the test. Subject
selection: `MOUNT_CLEANUP`, then a staged sibling copy, then
`~/derivative-maker/help-steps/mount-cleanup`.

## dist-installer-cli-tests

Regression tests for usability-misc's `dist-installer-cli` CI glue. The docker
build workflow's "back to default repository" step installs VirtualBox from the
default (non-Oracle) repository; on Debian-family that aborts with exit code 108
(Oracle repo not selected), which is expected and retried after dropping the
packages. Any OTHER failure is real and the step must propagate the installer's
OWN exit code.

A prior version ran `exit "$?"` inside the failure handler, where `$?` was the
status of the `if` that had just tested the code - so every distinct installer
failure collapsed into a meaningless 1 and the CI log no longer said WHICH
failure occurred. The step was extracted from the YAML into a real script
(`ci/vbox-back-to-default-repo.sh`) so it can be linted and tested against the
shipped text. The suite drives that real script with `sudo` stubbed to a
distinctive non-108 code and asserts the code propagates. No root, no network.
Point it at a usability-misc checkout with `USABILITY_MISC_REPO`; it exits 77
(SKIP) without one.

### Usage

```
# regression suite (resolves the checkout from USABILITY_MISC_REPO or ~/derivative-maker)
dist-installer-cli-tests

# against a specific usability-misc checkout
USABILITY_MISC_REPO=/path/to/usability-misc dist-installer-cli-tests
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

## stdisplay-tests

Comprehensive test + fuzz for **`stdisplay()`** itself -- the
`stdisplay`-package function the stcat family routes input through. Where
`stcat-family-tests` drives the CLIs at two colour settings, this suite tests
the **function directly across every colour depth** (3/4/8/24-bit), which is the
bug-prone part (`get_sgr_pattern()`'s graded allow-list). Every output is checked
against an **independent, palette-agnostic safety oracle**: strip every loose
`ESC [ ... m` (SGR can only set colour) and nothing dangerous may remain.

- `[P]` pins: the module's own docstring examples as exact-string regressions.
- `[B]` benign: printable ASCII + newline/tab pass through unchanged at every
  depth (proves it does not over-redact).
- `[G]` graded: one sequence per SGR bit-mode (3-bit fg/bg/reset, 4-bit bright,
  8-bit `;`/`:`, 24-bit) survives verbatim exactly when its depth is enabled and
  is redacted otherwise.
- `[R]` redaction: dangerous non-SGR escapes (clear, cursor, the input-injecting
  device-status report, OSC title / OSC-8, DCS/APC/PM, RIS, charset), C1 / C0
  controls, DEL, and non-ASCII die at every depth including truecolor.
- `[X]` exclude: `exclude_sgr` removes only the code it names.
- `[E]` env: `get_sgr_support()` NO_COLOR / COLORTERM logic and a `TERM` path
  that fails closed (`< 8`, no escapes) on an unknown or dumb terminal.
- `[I]` idempotence: `stdisplay(stdisplay(x)) == stdisplay(x)`.
- `[F]` fuzz: random Unicode, an escape-biased smuggling channel, and random
  exclude lists never raise, break the oracle, or lose idempotence.

### Usage

```
stdisplay-tests
stdisplay-tests-fuzz                        # heavy fuzz sweep
STDISPLAY_REPO=/path/to/helper-scripts stdisplay-tests
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
  fail loud with their own message and the build's error code (`2` on the
  improved tool -- distinct from a detection's `1` -- or `1` on a stale build;
  feature-detected).
- `[F]` fuzz: random clean-or-suspicious commits vs an independent oracle -- exit
  `1` iff something suspicious was injected, and output stays pure ASCII.

### Usage

```
check-ref-commits-for-unicode-tests
check-ref-commits-for-unicode-tests-fuzz    # heavy fuzz sweep
CHECK_REF_COMMITS_REPO=/path/to/helper-scripts check-ref-commits-for-unicode-tests
```

## VBox image-test fleet

Tools that run built Kicksecure/Whonix disk images under VirtualBox on the AMD OVH
bare-metal test server (headless, GPU-less). The `dm-smbios-reader-boot-tests` harness
above owns the serial/SMBIOS boot path; the tools here own the GUI-driven install, leak,
and upgrade lanes, their on-demand runner + results plane, and the host plumbing.

### image-test runner (`image-test-run`, `image-test@.service`, `image-test-gc`, `image-test-result-emit`)

On-demand templated oneshot: `image-test@<name>.service` reads `/etc/image-test/<name>.conf`
and runs `image-test-run`, which executes ONE `dm-smbios-reader-vbox` test as an unprivileged
per-instance user (the user is the isolation boundary -- VBox state is per-`$HOME`; `TEST_USER=root`
is refused) under `dm-vm-lock acquire --class work`, then publishes a screenshot + `result.json`
to the read-only results plane. A failing VM is the SIGNAL, it never aborts the publish; a publish
that cannot complete is NO-DATA, never a faked or downgraded verdict. `result.json` (schema
`dm-test-result/v1`) is written and validated solely by `image-test-result-emit`, so field order,
status enum, and step-summary agreement are defined once. `image-test-gc` resets an EPHEMERAL test
user's VBox state between runs (powers off + `unregistervm --delete` every VM it registered, removes
`~/VirtualBox VMs` and the per-user IPC dir); it refuses root and any `persist-*` user, only `eph-*`
is wipeable. Scheduling via a `.timer` is deferred; the unit is fired on demand today. Backed by the
sourced helpers under `usr/libexec/image-test/` (results publisher, screenshot content gate, COM1
drainer, MOK extractor).

### dm-whonix-pair

Boots an imported Whonix Gateway + Workstation pair headless on a VBox internal network and asserts
the Workstation egresses ONLY via the Gateway's Tor. The WS has a single internal-net NIC, so by
construction its only route out is via the Gateway (no direct WS egress); that the Gateway in turn
egresses ONLY over Tor -- not forwarding clearnet -- is the property the test VERIFIES, not something
the NIC topology guarantees, by running the `anon-leak-test` battery (enumerate / icmp / udp /
tor-confirm / gateway-craft; the reply-based ipv6-clearnet probe is deliberately omitted) inside the
WS via guestcontrol, fail-closed, with an AppArmor-confined `systemcheck` as the live positive control. Canary: the WS emits tagged direct-egress packets while the GW external
NIC is traced to a host pcap (`VBoxManage --nictrace`) -- the tagged destinations must NOT appear
leaving the GW, while a non-empty pcap + a passing tor-confirm prove the observation is not blind.
Exit 0 PASS / 5 FAIL / 2 setup.

### dm-upgrade-regression

The R6 upgrade-regression lane + the developer persona. Takes an EXISTING stable Kicksecure VM
install, switches its apt suite via `repository-dist`, applies staged updates, reboots, and
re-verifies the release-critical check battery -- the "stable users receiving stable updates are never
bricked" gate. (Check 8, `systemcheck`, is routed to the authoritative GUI-OCR gate rather than run on
the guestcontrol fast-path; the skip is recorded so a PASS never reads as "all checks green".)
`--repository stable-proposed-updates` is R6 (next-stable candidate, BLOCKING); `--repository developers`
is the early-warning developer persona. In-guest commands run via `VBoxManage guestcontrol`
(authoritative exit code) AND cross-checked against a screenshot: a catastrophic screen (kernel panic /
emergency / rescue / stuck-LUKS) fails any check, and a desktop-expected check additionally requires the
desktop to have painted. `--persist` is required (no default); `--revert` is reserved (not yet implemented).

### dm-shared-apt-repo

Delivers the derivative-maker local apt repo to the VBox fleet over a VBox SHARED FOLDER (no network
-- works even for a Whonix-Workstation on an internal-only net). Delivery only: derivative-maker owns
repo creation (`--skip-published-packages` populates `aptrepo_local/<derivative>`, codename `local`).
Subcommands `prepare <kicksecure|whonix>`, `attach <vm> [--transient]` (auto-mounted by the guest's
`mnt-shared-vbox.service` at `/mnt/shared`), `status [vm]`. The guest trusts this repo `[trusted=yes]`
over a read-only vboxsf mount; the trust anchor is the host build user who owns the local repo store.

### iso-download

Downloads a published Kicksecure/Whonix ISO and verifies it before use (`dist-installer-cli` fetches
`.ova`/KVM images but not the ISO). Integrity is fail-closed and both legs are required: OpenPGP verify
of `<image>.sha512sums.asc` over the sums file against `--cert`, then a hash match of the authenticated
entry for exactly `<image>` (basename-bound, so an older signed release cannot be served under a newer
name). Version is discovered (`--channel stable` -> wiki `Template:VersionNew` pin; `--channel developers`
-> highest published version dir) or pinned with `--version`; downloads route over Tor/SOCKS5 with
`--socks-proxy`, and `--onion` permits plaintext-http locations (onion services self-encrypt). The
version source is unsigned by design (TLS/onion-trusted), so it
guarantees a key-signed release of the resolved version but cannot alone stop a controlled version
source from selecting an older genuine release.

### vbox-ctl-local

Host-side VBox guest input/output via the vboxapi Main API (in-process XPCOM): real absolute mouse,
keyboard, and screenshot for a RUNNING VM with NO Guest Additions, where mouse and screenshot share
one pixel space (click where the screenshot shows something). It is the host-side counterpart to
`VBoxManage keyboardputscancode`, adding the mouse the CLI lacks (VM needs `--mouse usbtablet` + a USB
controller). It carries US set-1 scancode tables (unshifted, shifted, named chord keys), so it types
the full ASCII shell set and expresses combos by name; `vboxapi` is imported lazily so the pure
scancode helpers stay unit-testable without the bindings. It is the default `GUESTCTL` driver for
`dm-calamares-install`, `dm-whonix-pair`, and `dm-upgrade-regression`. Lives in
`usr/share/dm-smbios-reader-boot-tests/`.

### Host + plumbing helpers

- `vbox-host-shot` -- captures a Wayland-native PNG of a VBox GUI surface on a headless GPU-less host
  by running one VBox GUI client under a private `labwc` compositor and grabbing with `grim`,
  blank-gated (a failed/blank grab exits nonzero, never publishes a black image). `manager` grabs the
  VirtualBox Manager window; `vm-window` starts and grabs a running VM window.
- `dm-firmware-identity` -- classifier: maps three boot probes (`--efi`, `--coreboot`, `--secureboot`)
  to one canonical firmware identity and, with `--declared <id>`, reports `match=true|false|unknown` as
  data (not via exit code). The single place the VBox/qemu lanes resolve declared-vs-detected firmware.
- `dm-vbox-vcpus` -- prints the vCPU count a test VM should use: online host CPUs minus one (leaving a
  core for host + harness), floored at 1.
- `dm-vm-lock` -- VM-concurrency mutex for the shared server, wrapping a command: a readers-writer
  `flock` where `--class leak` is exclusive and `--class work` is shared but additionally claims one of
  N counting-semaphore slots to cap concurrent VMs. A `timeout` TTL backstops a wedged holder.
- `dm-local-apt-iterate` -- one-shot dev loop against a VBox VM: optional `derivative-update`, a
  derivative-maker build, `dm-shared-apt-repo prepare`, and optional `attach --vm NAME`; `--dry-run`
  prints every step and runs nothing.
- `image-redact-tokens` -- redacts non-deterministic tokens from screenshots for golden comparison:
  OCRs each image with tesseract and fills just each `--pattern`-matching word's box with a black
  rectangle, leaving the rest of the frame intact so a blank-gate still sees real content.
- `vbox-disk-extract` -- reads one file out of a VBox disk image on the HOST, read-only, without
  booting the VM (optional single-LUKS unlock, handles plain or LVM-in-LUKS). Reusable host-side
  inspection, e.g. lifting the installed system's MOK public cert for host-side enroll.

## coreboot firmware swap (opt-in, Dasharo-in-VirtualBox port)

The coreboot + `UefiPayloadPkg` ROM (`org-ai-assisted/dasharo`) is a GENERIC EFI firmware --
a drop-in for VBox's OVMF. A patched VirtualBox (the `DevEFI` CorebootRom + `DevACPI` SLP_EN
fixes from `org-ai-assisted/virtualbox`) loads it via the `EfiRom`/`CorebootRom` extradata; it
publishes a GOP on VBox's linear framebuffer and boots a full OS (Kicksecure live ISO -> GRUB ->
LXQt desktop -> Calamares install), verified.

So there is no bespoke lane: the test is the existing default-EFI full Calamares install story
with ONLY the firmware swapped. `dm-calamares-install --coreboot-rom <rom>` mirrors the proven
VM recipe (vboxvga, `piix3`/HPET/IOAPIC, the 36-bit-phys cpuid leaf, the `EfiRom`/`CorebootRom`
extradata) onto its install VM and drains COM1 for the whole run (reconnecting across the
install's power-cycles). `dm-release-test --coreboot-rom <rom>` forwards it through the normal
Kicksecure install lane -- same ISO, same walk-through, same result publishing. Both need
`--firmware efi` and the patched CorebootRom-aware VBoxManage, pointed at with `DASHARO_VBOX_BIN`
(its bin dir) or `VBOXMANAGE`. Empty `--coreboot-rom` -> the normal lanes are byte-unchanged.

```
DASHARO_VBOX_BIN=/path/to/VirtualBox/out/linux.amd64/release/bin \
dm-release-test kicksecure lxqt --firmware efi \
  --coreboot-rom /path/to/coreboot.rom
```

The reusable coreboot argv template (`build_coreboot_rom_argv`, `CB_CPUIDSET`,
`build_coreboot_vm_plan`, `build_uart_server_argv`) lives in the shared `dm-smbios-reader-vbox`
backend and is byte-exact unit tested by the `dm-smbios-reader-boot-tests` suite's
`test_dm_smbios_reader_vbox.py`; the install lane's
coreboot `modifyvm`/extradata argv is unit tested by `dm-calamares-install-tests`, and the
`dm-release-test` pass-through by `dm-release-test-tests`. See
`usr/share/dm-smbios-reader-boot-tests/dasharo-vbox-firmware-port.md` for the firmware-port
details (the patched VBox, the graphics patches, the i440fx + q35 bring-up).

## Related

- Organisation: https://github.com/org-ai-assisted
- Landing page: https://org-ai-assisted.github.io (source: https://github.com/org-ai-assisted/org-ai-assisted.github.io)
- Organisation profile: https://github.com/org-ai-assisted/.github
