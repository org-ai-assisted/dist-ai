# setup-wizard-dist tests

Regression tests for the Kicksecure / Whonix
[setup-wizard-dist](https://github.com/Kicksecure/setup-wizard-dist)
first-boot setup wizard.

## What it tests

`setup-wizard-dist` is a PyQt5 `QWizard`. The pages shown are decided at
runtime: the disclaimer pages are disabled by default, so the wizard usually
shows only the finish page -- a single page. A `QWizard` still lays out a Back
button, which on a single-page wizard has nowhere to go.

- **[A] Back button visibility** - drives the real
  `setup_wizard_dist.setup_wizard_dist` wizard offscreen and asserts:
  - a single-page wizard sets `NoBackButtonOnStartPage` and the Back button is
    not visible after `show()`. A plain `QWidget.hide()` does not survive
    `QWizard` rebuilding its button layout on `show()`, so the option is the
    correct mechanism;
  - a multi-page (disclaimer-enabled) wizard does not set the option and the
    Back button becomes available past the start page.
- **[B] nextId routing** - `DisclaimerPage1.nextId()` routes accept ->
  disclaimer 2 and reject -> finish page.
- **[C] Source hygiene** - the shipped module is pure ASCII (R-001).

No root, no network, no X server. Qt runs offscreen
(`QT_QPA_PLATFORM=offscreen`). The suite skips if PyQt5 or guimessages (from
helper-scripts) is not importable, or when a non-root run cannot create
`/var/cache/setup-dist`.

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
