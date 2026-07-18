# setup-wizard-dist tests

Regression tests for the Kicksecure / Whonix
[setup-wizard-dist](https://github.com/Kicksecure/setup-wizard-dist)
first-boot setup wizard.

## What it tests

`setup-wizard-dist` is a PyQt5 `QWizard`. The pages shown are decided at
runtime: the disclaimer pages are disabled by default, so the wizard usually
shows only the finish page -- a single page. A `QWizard` still lays out a Back
button, which on a single-page wizard has nowhere to go.

`swd_testlib.py` is the shared harness (sys.path, offscreen Qt, checkout
translations, stubbed `package-installed-check`, one `QApplication`). The test
modules drive the real `setup_wizard_dist.setup_wizard_dist`:

- **`test_back_button.py`** - a single-page wizard sets
  `NoBackButtonOnStartPage` and the Back button is not visible after `show()`
  (a plain `QWidget.hide()` does not survive `QWizard` rebuilding its button
  layout on `show()`, so the option is the correct mechanism); a multi-page
  (disclaimer-enabled) wizard does not set the option and the Back button is
  available past the start page.
- **`test_nextid_routing.py`** - `DisclaimerPage1.nextId()` routes accept ->
  disclaimer 2, reject -> finish page, and reject is the default;
  `DisclaimerPage2.nextId()` always routes to the finish page.
- **`test_finish_page_text.py`** - `get_finish_page_text()` assembles start +
  optional browser-choice + sysmaint-or-not + end; the browser-choice paragraph
  appears only on a `machine` (Kicksecure) host, never on a gateway/workstation
  (Whonix), and the sysmaint variant follows `user_sysmaint_split_installed`.
- **`test_ui_properties.py`** - window title per environment (Kicksecure vs
  Whonix), the Finish button relabelled "OK", `set_next_button_state()`'s
  inverted enable logic, `done()` recording a normal finish, the finish page
  widgets, and the Back/Next slots running without raising on their live pages.
- **`test_translations.py`** - every key referenced via `self._('...')` exists
  in the shipped translations YAML (code/translation drift guard), values are
  non-empty strings, and the YAML is ASCII.
- **`test_source_hygiene.py`** - the shipped module is pure ASCII (R-001).
- **`test_headless_render.py`** - drives the wizard on a REAL (virtual) X
  server: spawns `render_probe.py` under `xvfb-run` with the xcb platform
  plugin (a subprocess, so it does not collide with the offscreen
  `QApplication`) and asserts the Back button is not mapped on the single-page
  wizard yet is mapped past the start page on the multi-page one, also saving a
  screenshot of the rendered wizard. This complements the offscreen checks: it
  proves the real window backend maps the button box as expected, not just the
  `QWizard` option state. Skips (never fails) when `xvfb-run` or the xcb plugin
  is unavailable.

Most of the suite runs offscreen (`QT_QPA_PLATFORM=offscreen`); only
`test_headless_render.py` needs `xvfb-run` and the xcb runtime libraries, and
skips without them. No root, no network. The suite skips if PyQt5 or
guimessages (from helper-scripts) is not importable, or when a non-root run
cannot create `/var/cache/setup-dist`.

## Running

Installed:

```
setup-wizard-dist-tests
```

From a checkout (point it at the wizard and helper-scripts):

```
SETUP_WIZARD_DIST_REPO=/path/to/setup-wizard-dist \
PYTHONPATH=/path/to/helper-scripts/usr/lib/python3/dist-packages \
setup-wizard-dist-tests
```
