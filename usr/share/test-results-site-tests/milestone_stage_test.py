#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Unit test for test-results-site-generate's _milestone_stage: every screenshot caption must
state the boot PHASE it is from (live / pre-install vs the installed system's first boot vs
post-boot checks), derived from the milestone name, so the two firmware shots (live
'firmware-state' vs installed 'installed-firmware-logo') are never ambiguous. An unknown name
must yield '' (no guessed phase), never a wrong label."""

import importlib.machinery
import importlib.util
import os
import sys

_SELF = os.path.dirname(os.path.realpath(__file__))
_LIB = os.path.join(os.path.dirname(os.path.dirname(_SELF)), "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

GEN = os.path.join(os.path.dirname(os.path.dirname(_SELF)), "bin", "test-results-site-generate")


def _load():
    loader = importlib.machinery.SourceFileLoader("tr_site_gen_under_test", GEN)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


try:
    M = _load()
except ImportError as exc:
    print("milestone_stage_test: FATAL: required generator dependency not "
          "importable: %s" % exc, file=sys.stderr)
    sys.exit(1)

_failures = 0


def check(label, cond):
    global _failures
    if cond:
        print("ok: %s" % label)
    else:
        print("FAIL: %s" % label, file=sys.stderr)
        _failures += 1


CASES = [
    ## live / pre-install -- the live boot AND the Calamares installer running in it
    ("live-grub-menu", "live / pre-install"),
    ("live-desktop-ready", "live / pre-install"),
    ("live-guestcontrol-ready", "live / pre-install"),
    ("firmware-state", "live / pre-install"),
    ("welcome", "live / pre-install"),
    ("partitions-luks-filled", "live / pre-install"),
    ("install-done", "live / pre-install"),
    ## installed system / first boot
    ("installed-firmware-logo", "installed system / first boot"),
    ("installed-grub-menu", "installed system / first boot"),
    ("mok-reboot-desktop", "installed system / first boot"),
    ("first-boot", "installed system / first boot"),
    ## anchored: a live-* name that merely CONTAINS 'first-boot' must stay live, not be mislabeled
    ## installed by an unanchored substring match.
    ("live-first-boot-probe", "live / pre-install"),
    ## installed system / MOK enrollment (must NOT be swallowed by the first-boot branch)
    ("mok-cert-enrolled", "installed system / MOK enrollment"),
    ## installed system / sysmaint boot (sysmaint wins over the luks substring)
    ("sysmaint-luks-prompt", "installed system / sysmaint boot"),
    ## boot / LUKS unlock
    ("luks-prompt", "boot / LUKS unlock"),
    ("luks-passphrase-typed", "boot / LUKS unlock"),
    ("luks-unlocked", "boot / LUKS unlock"),
    ## post-boot checks
    ("check-6-gui-rendered", "post-boot checks"),
    ("checks-complete", "post-boot checks"),
    ("vt-70-login", "post-boot checks"),
]
for name, want in CASES:
    got = M._milestone_stage(name)
    check("stage(%r) == %r (got %r)" % (name, want, got), got == want)

## An unrecognized milestone must yield '' -- never a guessed/wrong phase.
for unknown in ("", "screenshot", "something-else", "random-step"):
    check("stage(%r) == '' (no guessed phase)" % unknown, M._milestone_stage(unknown) == "")

## The two firmware shots are UNAMBIGUOUS: live vs installed map to different phases.
check(
    "firmware shots disambiguated (live vs installed)",
    M._milestone_stage("firmware-state") != M._milestone_stage("installed-firmware-logo")
    and M._milestone_stage("firmware-state") != "",
)

if _failures:
    print("\n%d milestone_stage assertion(s) failed" % _failures, file=sys.stderr)
    sys.exit(1)
print("\nall milestone_stage assertions passed")
